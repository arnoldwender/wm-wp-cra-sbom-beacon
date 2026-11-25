<?php
declare(strict_types=1);

namespace WMCyber\CRA\SBOM;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Builds a CycloneDX 1.6 JSON inventory of the code WordPress loads: core, active plugins (site and network),
 * must-use plugins, the active theme and its parent.
 *
 * Only what the site states is written. Until 2026-09-15 the generator hashed the WordPress version string and
 * called it the core hash, labelled every plugin "Proprietary", and filled missing versions with "1.0.0"/"6.8".
 * Unknown values are now left out (CycloneDX 1.6: only type and name are required for a component).
 *
 * purl: there is no registered purl type for WordPress (purl-spec purl-types-index.json, 42 types, checked
 * 2026-09-15), so components use the registered "generic" type with a namespace.
 */
final class CycloneDxGenerator {
	/**
	 * @return array<string, mixed>
	 */
	public function generate_sbom(): array {
		$components = [ $this->core_component() ];

		foreach ( $this->active_plugin_components() as $component ) {
			$components[] = $component;
		}
		foreach ( $this->mu_plugin_components() as $component ) {
			$components[] = $component;
		}
		foreach ( $this->theme_components() as $component ) {
			$components[] = $component;
		}

		// The libraries the plugins and themes bundle. A plugin carrying a Composer vendor/
		// directory runs every library in it, and that is where published vulnerabilities live: an
		// inventory that stops at the plugin boundary answers the wrong question.
		foreach ( DependencyScanner::components( $this->bundle_roots() ) as $component ) {
			$components[] = $component;
		}

		// The runtime underneath. A site on an unsupported PHP or an end-of-life database is
		// vulnerable through software that no list of plugins mentions.
		foreach ( RuntimeInventory::components() as $component ) {
			$components[] = $component;
		}

		// The cryptographic bill of materials, off by default: on a stock PHP 8.3 with OpenSSL 3.5
		// it adds 186 components to a document that otherwise holds a few dozen.
		if ( CryptoInventory::enabled() ) {
			foreach ( CryptoInventory::components() as $component ) {
				$components[] = $component;
			}
		}

		return [
			'bomFormat'    => 'CycloneDX',
			'specVersion'  => '1.6',
			'serialNumber' => 'urn:uuid:' . wp_generate_uuid4(),
			'version'      => 1,
			'metadata'     => [
				'timestamp' => gmdate( 'Y-m-d\TH:i:s\Z' ),
				'tools'     => [
					'components' => [
						[
							'type'      => 'application',
							'publisher' => 'WM Suite',
							'name'      => 'WM CRA SBOM & Vulnerability Beacon',
							'version'   => WM_CRA_VERSION,
						],
					],
				],
				'component' => [
					'type' => 'application',
					'name' => (string) get_bloginfo( 'name' ),
				],
			],
			'components'   => $components,
		];
	}

	/** One serialisation for every path that hashes or stores an SBOM (CLI, admin, hub). */
	public static function serialize( array $sbom ): string {
		return (string) wp_json_encode( $sbom, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );
	}

	/**
	 * Generate and store a snapshot.
	 *
	 * @return array{saved: bool, snapshot_id: int, sha256: string, components_count: int, created_at: string, sbom: array<string, mixed>}
	 */
	public function save_snapshot( ?array $sbom = null ): array {
		global $wpdb;

		$sbom       = $sbom ?? $this->generate_sbom();
		$json       = self::serialize( $sbom );
		$sha256     = hash( 'sha256', $json );
		$count      = count( $sbom['components'] ?? [] );
		$created_at = current_time( 'mysql', true ); // UTC, like the SBOM timestamp.

		$inserted = $wpdb->insert(
			$wpdb->prefix . 'wm_cra_sbom_snapshots',
			[
				'cyclonedx_version' => '1.6',
				'components_count'  => $count,
				'sbom_sha256'       => $sha256,
				'sbom_json'         => $json,
				'created_at'        => $created_at,
			],
			[ '%s', '%d', '%s', '%s', '%s' ]
		);
		$saved = false !== $inserted && (int) $inserted > 0;

		return [
			'saved'            => $saved,
			'snapshot_id'      => $saved ? (int) $wpdb->insert_id : 0,
			'sha256'           => $sha256,
			'components_count' => $count,
			'created_at'       => $created_at,
			'sbom'             => $sbom,
		];
	}

	// -------------------------------------------------------------------------------------------------------------
	// Components
	// -------------------------------------------------------------------------------------------------------------

	private function core_component(): array {
		global $wp_version;
		$version = is_string( $wp_version ?? null ) && '' !== $wp_version ? $wp_version : (string) get_bloginfo( 'version' );

		return self::component( 'framework', 'wordpress-core', $version, 'pkg:generic/wordpress', [
			'description' => 'WordPress',
			'licenses'    => self::licenses( 'GPLv2 or later' ), // core's license.txt
		] );
	}

	/** @return list<array<string, mixed>> */
	private function active_plugin_components(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$all_plugins = function_exists( 'get_plugins' ) ? get_plugins() : [];

		$files = (array) get_option( 'active_plugins', [] );
		if ( is_multisite() ) {
			$files = array_merge( $files, array_keys( (array) get_site_option( 'active_sitewide_plugins', [] ) ) );
		}

		$components = [];
		foreach ( array_unique( array_map( 'strval', $files ) ) as $plugin_file ) {
			if ( ! isset( $all_plugins[ $plugin_file ] ) ) {
				continue;
			}
			$meta = $all_plugins[ $plugin_file ];
			$slug = sanitize_title( '.' !== dirname( $plugin_file ) ? dirname( $plugin_file ) : basename( $plugin_file, '.php' ) );

			$components[] = self::component( 'application', $slug, (string) ( $meta['Version'] ?? '' ), 'pkg:generic/wordpress-plugin/' . $slug, [
				'description' => (string) ( $meta['Name'] ?? '' ),
				'authors'     => (string) ( $meta['Author'] ?? '' ),
				'licenses'    => self::licenses( self::license_header( self::plugin_path( $plugin_file ) ) ),
			] );
		}
		return $components;
	}

	/** @return list<array<string, mixed>> */
	private function mu_plugin_components(): array {
		if ( ! function_exists( 'get_mu_plugins' ) ) {
			return [];
		}
		$components = [];
		foreach ( (array) get_mu_plugins() as $file => $meta ) {
			$slug         = sanitize_title( basename( (string) $file, '.php' ) );
			$components[] = self::component( 'application', $slug, (string) ( $meta['Version'] ?? '' ), 'pkg:generic/wordpress-mu-plugin/' . $slug, [
				'description' => (string) ( $meta['Name'] ?? '' ),
				'authors'     => (string) ( $meta['Author'] ?? '' ),
				'licenses'    => self::licenses( self::license_header( defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR . '/' . $file : '' ) ),
			] );
		}
		return $components;
	}

	/** @return list<array<string, mixed>> */
	private function theme_components(): array {
		$components = [];
		$theme      = wp_get_theme();
		$themes     = [ $theme ];
		$parent     = method_exists( $theme, 'parent' ) ? $theme->parent() : false;
		if ( $parent ) {
			$themes[] = $parent;
		}

		foreach ( $themes as $t ) {
			$slug    = (string) $t->get_stylesheet();
			$dir     = method_exists( $t, 'get_stylesheet_directory' ) ? (string) $t->get_stylesheet_directory() : '';
			$components[] = self::component( 'application', $slug, (string) $t->get( 'Version' ), 'pkg:generic/wordpress-theme/' . $slug, [
				'description' => (string) $t->get( 'Name' ),
				'authors'     => (string) $t->get( 'Author' ),
				'licenses'    => self::licenses( self::license_header( '' !== $dir ? $dir . '/style.css' : '' ) ),
			] );
		}
		return $components;
	}

	/**
	 * A component with only the fields that have a value. The purl carries the version only when it is known.
	 *
	 * @param array{description?: string, authors?: string, licenses?: array<int, mixed>} $extra
	 */
	private static function component( string $type, string $name, string $version, string $purl_base, array $extra ): array {
		$component = [ 'type' => $type, 'name' => $name ];
		$version   = trim( $version );
		if ( '' !== $version ) {
			$component['version'] = $version;
		}
		$component['purl'] = $purl_base . ( '' !== $version ? '@' . rawurlencode( $version ) : '' );

		if ( '' !== trim( $extra['description'] ?? '' ) ) {
			$component['description'] = trim( wp_strip_all_tags( $extra['description'] ) );
		}
		if ( '' !== trim( $extra['authors'] ?? '' ) ) {
			// CycloneDX 1.6 deprecates the "author" string in favour of "authors".
			$component['authors'] = [ [ 'name' => trim( wp_strip_all_tags( $extra['authors'] ) ) ] ];
		}
		if ( ! empty( $extra['licenses'] ) ) {
			$component['licenses'] = $extra['licenses'];
		}
		return $component;
	}

	/**
	 * The licence as the component states it, as a CycloneDX "name" (free text). "id" would have to be an SPDX
	 * identifier and cannot be combined with "name" (CycloneDX 1.6 schema); WordPress headers are free text.
	 *
	 * @return list<array{license: array{name: string}}>
	 */
	public static function licenses( string $license ): array {
		$license = trim( wp_strip_all_tags( $license ) );
		return '' === $license ? [] : [ [ 'license' => [ 'name' => $license ] ] ];
	}

	/** The "License:" header of a plugin file or style.css; WordPress does not include it in get_plugins(). */
	public static function license_header( string $file ): string {
		if ( '' === $file || ! is_readable( $file ) ) {
			return '';
		}
		$data = get_file_data( $file, [ 'License' => 'License' ] );
		return (string) ( $data['License'] ?? '' );
	}

	private static function plugin_path( string $plugin_file ): string {
		return defined( 'WP_PLUGIN_DIR' ) ? WP_PLUGIN_DIR . '/' . $plugin_file : '';
	}

	/**
	 * Directories to search for bundled lock files: the active plugins and the active themes.
	 *
	 * Keyed by the slug, so a library two plugins bundle is one component that names both owners.
	 *
	 * @return array<string, string>
	 */
	private function bundle_roots(): array {
		$roots = [];

		$files = (array) get_option( 'active_plugins', [] );
		if ( is_multisite() ) {
			$files = array_merge( $files, array_keys( (array) get_site_option( 'active_sitewide_plugins', [] ) ) );
		}

		foreach ( array_unique( array_map( 'strval', $files ) ) as $plugin_file ) {
			$directory = dirname( (string) $plugin_file );
			if ( '.' === $directory || ! defined( 'WP_PLUGIN_DIR' ) ) {
				continue; // A single-file plugin has nothing to bundle.
			}
			$roots[ sanitize_title( $directory ) ] = WP_PLUGIN_DIR . '/' . $directory;
		}

		$theme  = wp_get_theme();
		$themes = [ $theme ];
		$parent = method_exists( $theme, 'parent' ) ? $theme->parent() : false;
		if ( $parent ) {
			$themes[] = $parent;
		}
		foreach ( $themes as $t ) {
			$directory = method_exists( $t, 'get_stylesheet_directory' ) ? (string) $t->get_stylesheet_directory() : '';
			if ( '' !== $directory ) {
				$roots[ (string) $t->get_stylesheet() ] = $directory;
			}
		}

		return $roots;
	}
}
