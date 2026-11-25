<?php
declare(strict_types=1);

namespace WMCyber\CRA\SBOM;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Enumerates the Composer packages and npm dependencies that plugins and themes bundle.
 *
 * Until this class existed the SBOM listed only WordPress, the plugins, the must-use plugins and
 * the theme — the units a site administrator installs. The code that actually runs is larger: a
 * plugin carrying a Composer `vendor/` directory runs every library in it, and those libraries are
 * where published vulnerabilities live. An inventory that stops at the plugin boundary answers the
 * wrong question.
 *
 * Only lock files are read, never `composer.json` or `package.json`: a manifest states a range
 * ("^7.0"), a lock file states the version that is installed. This class writes versions, so it
 * reads the file that knows one.
 */
final class DependencyScanner {

	/** Lock files that state installed versions. */
	public const COMPOSER_LOCK = 'composer.lock';
	public const NPM_LOCK      = 'package-lock.json';

	/**
	 * Directories that are never searched for a lock file.
	 *
	 * A `composer.lock` inside `vendor/` belongs to a dependency of a dependency and describes a
	 * tree that is not installed here; `node_modules` holds thousands of them. Both would multiply
	 * the inventory with packages the site does not run.
	 */
	public const SKIP_DIRECTORIES = [ 'vendor', 'node_modules', '.git', '.github', 'tests', 'test', 'node-gyp' ];

	/** How deep below a plugin or theme root a lock file is still looked for. */
	public const MAX_DEPTH = 4;

	/** Most dependencies written into one inventory, so a monorepo cannot produce an unusable document. */
	public const MAX_COMPONENTS = 5000;

	/**
	 * Components for every lock file under the given roots.
	 *
	 * @param array<string, string> $roots Component name (the plugin or theme slug) => absolute directory.
	 * @return list<array<string, mixed>>
	 */
	public static function components( array $roots ): array {
		$components = [];
		$seen       = [];

		foreach ( $roots as $owner => $directory ) {
			foreach ( self::lock_files( (string) $directory ) as $lock ) {
				$found = str_ends_with( $lock, self::COMPOSER_LOCK )
					? self::composer_components( $lock, (string) $owner )
					: self::npm_components( $lock, (string) $owner );

				foreach ( $found as $component ) {
					// The same library bundled by two plugins is one component; the owners are
					// listed as properties so the inventory still says who brought it in.
					$key = (string) $component['purl'];
					if ( isset( $seen[ $key ] ) ) {
						$components[ $seen[ $key ] ]['properties'] = self::merge_owners(
							$components[ $seen[ $key ] ]['properties'] ?? [],
							(string) $owner
						);
						continue;
					}
					if ( count( $components ) >= self::MAX_COMPONENTS ) {
						return array_values( $components );
					}
					$seen[ $key ] = count( $components );
					$components[] = $component;
				}
			}
		}

		return array_values( $components );
	}

	/**
	 * Every lock file under one root, pruning the directories that hold other projects' locks.
	 *
	 * @return list<string>
	 */
	public static function lock_files( string $root ): array {
		$root = rtrim( str_replace( '\\', '/', $root ), '/' );
		if ( '' === $root || ! is_dir( $root ) ) {
			return [];
		}

		$found  = [];
		$queue  = [ [ $root, 0 ] ];

		while ( [] !== $queue ) {
			[ $directory, $depth ] = array_shift( $queue );

			foreach ( [ self::COMPOSER_LOCK, self::NPM_LOCK ] as $name ) {
				$candidate = $directory . '/' . $name;
				if ( is_file( $candidate ) && is_readable( $candidate ) ) {
					$found[] = $candidate;
				}
			}

			if ( $depth >= self::MAX_DEPTH ) {
				continue;
			}

			foreach ( (array) @scandir( $directory ) as $entry ) {
				$entry = (string) $entry;
				if ( '.' === $entry || '..' === $entry || in_array( $entry, self::SKIP_DIRECTORIES, true ) ) {
					continue;
				}
				$path = $directory . '/' . $entry;
				if ( is_dir( $path ) && ! is_link( $path ) ) {
					$queue[] = [ $path, $depth + 1 ];
				}
			}
		}

		sort( $found );

		return $found;
	}

	/**
	 * Composer packages from a lock file.
	 *
	 * Only `packages`, never `packages-dev`: development dependencies are not installed by
	 * `composer install --no-dev`, which is how a plugin is built for distribution, so listing them
	 * would claim code the site does not run.
	 *
	 * @return list<array<string, mixed>>
	 */
	public static function composer_components( string $lock_file, string $owner ): array {
		$data = self::read_json( $lock_file );
		if ( ! is_array( $data ) || ! isset( $data['packages'] ) || ! is_array( $data['packages'] ) ) {
			return [];
		}

		$components = [];
		foreach ( $data['packages'] as $package ) {
			if ( ! is_array( $package ) ) {
				continue;
			}
			$name    = self::clean( (string) ( $package['name'] ?? '' ) );
			$version = self::clean( (string) ( $package['version'] ?? '' ) );
			if ( '' === $name || '' === $version ) {
				continue;
			}

			$components[] = self::component(
				$name,
				$version,
				'pkg:composer/' . $name . '@' . rawurlencode( $version ),
				self::licence_of( $package ),
				$owner,
				(string) ( $package['description'] ?? '' )
			);
		}

		return $components;
	}

	/**
	 * npm dependencies from a lock file, in either the v1 or the v2/v3 layout.
	 *
	 * Entries flagged `dev` are skipped for the same reason as Composer's `packages-dev`.
	 *
	 * @return list<array<string, mixed>>
	 */
	public static function npm_components( string $lock_file, string $owner ): array {
		$data = self::read_json( $lock_file );
		if ( ! is_array( $data ) ) {
			return [];
		}

		$components = [];

		// v2 and v3: a "packages" map keyed by path, the root under the empty string.
		foreach ( (array) ( $data['packages'] ?? [] ) as $path => $package ) {
			if ( ! is_array( $package ) || '' === (string) $path || ! empty( $package['dev'] ) ) {
				continue;
			}
			$name = self::clean( (string) ( $package['name'] ?? '' ) );
			if ( '' === $name ) {
				// "node_modules/@scope/pkg" and "node_modules/pkg/node_modules/dep".
				$position = strrpos( (string) $path, 'node_modules/' );
				$name     = false === $position ? '' : self::clean( substr( (string) $path, $position + 13 ) );
			}
			$version = self::clean( (string) ( $package['version'] ?? '' ) );
			if ( '' === $name || '' === $version ) {
				continue;
			}
			$components[] = self::component( $name, $version, self::npm_purl( $name, $version ), self::licence_of( $package ), $owner, '' );
		}

		// v1: a nested "dependencies" tree.
		if ( [] === $components ) {
			foreach ( self::npm_v1( (array) ( $data['dependencies'] ?? [] ) ) as [$name, $version, $licence] ) {
				$components[] = self::component( $name, $version, self::npm_purl( $name, $version ), $licence, $owner, '' );
			}
		}

		return $components;
	}

	/**
	 * The v1 tree, flattened.
	 *
	 * @param array<string, mixed> $dependencies Dependency map.
	 * @return list<array{0:string,1:string,2:string}>
	 */
	private static function npm_v1( array $dependencies ): array {
		$flat = [];
		foreach ( $dependencies as $name => $package ) {
			if ( ! is_array( $package ) || ! empty( $package['dev'] ) ) {
				continue;
			}
			$clean_name = self::clean( (string) $name );
			$version    = self::clean( (string) ( $package['version'] ?? '' ) );
			if ( '' !== $clean_name && '' !== $version ) {
				$flat[] = [ $clean_name, $version, self::licence_of( $package ) ];
			}
			foreach ( self::npm_v1( (array) ( $package['dependencies'] ?? [] ) ) as $nested ) {
				$flat[] = $nested;
			}
		}
		return $flat;
	}

	/** purl for npm keeps a scope as a namespace: pkg:npm/%40scope/name@version. */
	private static function npm_purl( string $name, string $version ): string {
		if ( str_starts_with( $name, '@' ) && str_contains( $name, '/' ) ) {
			[ $scope, $package ] = explode( '/', substr( $name, 1 ), 2 );
			return 'pkg:npm/%40' . rawurlencode( $scope ) . '/' . rawurlencode( $package ) . '@' . rawurlencode( $version );
		}
		return 'pkg:npm/' . rawurlencode( $name ) . '@' . rawurlencode( $version );
	}

	/**
	 * A CycloneDX library component. Missing values are left out, never guessed.
	 *
	 * @return array<string, mixed>
	 */
	private static function component( string $name, string $version, string $purl, string $licence, string $owner, string $description ): array {
		$component = [
			'type'    => 'library',
			'name'    => $name,
			'version' => $version,
			'purl'    => $purl,
		];

		if ( '' !== trim( $description ) ) {
			$component['description'] = trim( \wp_strip_all_tags( $description ) );
		}
		if ( '' !== $licence ) {
			$component['licenses'] = CycloneDxGenerator::licenses( $licence );
		}
		$component['properties'] = self::merge_owners( [], $owner );

		return $component;
	}

	/**
	 * The owners of a shared dependency, as CycloneDX properties.
	 *
	 * @param list<array{name:string,value:string}> $properties Existing properties.
	 * @return list<array{name:string,value:string}>
	 */
	private static function merge_owners( array $properties, string $owner ): array {
		$owner = trim( $owner );
		if ( '' === $owner ) {
			return $properties;
		}
		foreach ( $properties as $property ) {
			if ( 'wm-cra:bundled-by' === ( $property['name'] ?? '' ) && $owner === ( $property['value'] ?? '' ) ) {
				return $properties;
			}
		}
		$properties[] = [ 'name' => 'wm-cra:bundled-by', 'value' => $owner ];
		return $properties;
	}

	/** The licence as the lock file states it; a list becomes "A OR B", which is how SPDX joins them. */
	private static function licence_of( array $package ): string {
		$licence = $package['license'] ?? ( $package['licenses'] ?? '' );
		if ( is_array( $licence ) ) {
			$licence = implode( ' OR ', array_filter( array_map( 'strval', $licence ) ) );
		}
		return self::clean( (string) $licence );
	}

	/** @return array<string, mixed>|null */
	private static function read_json( string $file ): ?array {
		$size = @filesize( $file );
		// A lock file larger than this is not one; reading it would only cost memory.
		if ( false === $size || $size > 8 * 1024 * 1024 ) {
			return null;
		}
		$raw = @file_get_contents( $file );
		if ( ! is_string( $raw ) ) {
			return null;
		}
		$data = json_decode( $raw, true );
		return is_array( $data ) ? $data : null;
	}

	private static function clean( string $value ): string {
		return trim( str_replace( [ "\r", "\n", "\t" ], ' ', $value ) );
	}
}
