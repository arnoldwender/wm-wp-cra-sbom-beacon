<?php
declare(strict_types=1);

namespace WMCyber\CRA\SBOM;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The runtime the site executes on: the PHP interpreter, its loaded extensions and the database
 * server.
 *
 * An inventory of the application without its runtime cannot answer the question the CRA asks of a
 * component list — a site on an unsupported PHP or an end-of-life database is vulnerable through
 * software nobody listed. Every value here is read from the running process or asked of the server;
 * none is derived from a setting that could be stale.
 */
final class RuntimeInventory {

	/**
	 * Extensions worth listing by name. `get_loaded_extensions()` returns around forty on a normal
	 * host, most of them part of PHP itself and without an independent version. These are the ones
	 * that wrap a separate library with its own release cycle and its own advisories.
	 */
	public const TRACKED_EXTENSIONS = [
		'openssl', 'curl', 'gd', 'imagick', 'libxml', 'zip', 'zlib', 'intl', 'sodium', 'mbstring',
		'pcre', 'sqlite3', 'pdo_mysql', 'mysqli', 'redis', 'memcached', 'apcu', 'imap', 'ldap', 'ffi',
	];

	/**
	 * Components for the runtime.
	 *
	 * @param array<string, mixed> $measured Overrides, so the suite can describe a host it is not running on.
	 * @return list<array<string, mixed>>
	 */
	public static function components( array $measured = [] ): array {
		$php_version = (string) ( $measured['php_version'] ?? PHP_VERSION );
		$extensions  = $measured['extensions'] ?? self::extension_versions();
		$database    = (string) ( $measured['database'] ?? self::database_version() );
		$server      = (string) ( $measured['server'] ?? self::web_server() );

		$components = [];

		if ( '' !== $php_version ) {
			$components[] = [
				'type'        => 'platform',
				'name'        => 'php',
				'version'     => $php_version,
				'purl'        => 'pkg:generic/php@' . rawurlencode( $php_version ),
				'description' => 'PHP runtime',
			];
		}

		foreach ( (array) $extensions as $name => $version ) {
			$name    = (string) $name;
			$version = trim( (string) $version );
			$component = [
				'type' => 'library',
				'name' => 'php-ext-' . $name,
				'purl' => 'pkg:generic/php-ext/' . rawurlencode( $name ) . ( '' !== $version ? '@' . rawurlencode( $version ) : '' ),
			];
			// An extension compiled into PHP reports no version of its own; the field is omitted
			// rather than filled with the PHP version, which would name a release it does not have.
			if ( '' !== $version ) {
				$component['version'] = $version;
			}
			$components[] = $component;
		}

		if ( '' !== $database ) {
			$components[] = [
				'type'        => 'platform',
				'name'        => self::database_name( $database ),
				'version'     => self::version_number( $database ),
				'purl'        => 'pkg:generic/' . self::database_name( $database ) . '@' . rawurlencode( self::version_number( $database ) ),
				'description' => $database,
			];
		}

		if ( '' !== $server ) {
			$components[] = [
				'type'        => 'platform',
				'name'        => 'web-server',
				'purl'        => 'pkg:generic/web-server',
				'description' => $server,
			];
		}

		return $components;
	}

	/**
	 * Loaded extensions with the version of the library they wrap, where there is one.
	 *
	 * @return array<string, string>
	 */
	public static function extension_versions(): array {
		$versions = [];
		foreach ( self::TRACKED_EXTENSIONS as $name ) {
			if ( ! extension_loaded( $name ) ) {
				continue;
			}
			$library = self::library_version( $name );
			$versions[ $name ] = '' !== $library
				? $library
				: self::usable_version( (string) ( phpversion( $name ) ?: '' ), PHP_VERSION );
		}
		ksort( $versions );

		return $versions;
	}

	/**
	 * A reported extension version, or '' when it is only PHP's own.
	 *
	 * Measured 2026-09-16: `phpversion( 'openssl' )` returns **8.5.10** on a stock build — the PHP
	 * version, not OpenSSL's. An SBOM carrying `php-ext-openssl@8.5.10` sends a vulnerability
	 * scanner looking for an OpenSSL release that does not exist, which is worse than leaving the
	 * field out. Most bundled extensions report PHP's version this way.
	 */
	public static function usable_version( string $reported, string $php_version ): string {
		$reported = trim( $reported );

		return ( '' === $reported || $reported === trim( $php_version ) ) ? '' : $reported;
	}

	/**
	 * The version of the underlying library, for the extensions that expose one.
	 *
	 * These are the two that matter for advisories and the two PHP lets us ask.
	 */
	public static function library_version( string $name ): string {
		if ( 'openssl' === $name && defined( 'OPENSSL_VERSION_TEXT' ) ) {
			return 1 === preg_match( '/(\d+\.\d+(?:\.\d+)?[a-z]?)/', (string) OPENSSL_VERSION_TEXT, $match ) ? $match[1] : '';
		}

		if ( 'curl' === $name && function_exists( 'curl_version' ) ) {
			$curl = curl_version();
			return is_array( $curl ) ? trim( (string) ( $curl['version'] ?? '' ) ) : '';
		}

		return '';
	}

	/** The server's own answer, not the value a setting remembers. */
	public static function database_version(): string {
		global $wpdb;

		if ( ! isset( $wpdb ) || ! is_object( $wpdb ) || ! method_exists( $wpdb, 'db_server_info' ) ) {
			return '';
		}

		$info = $wpdb->db_server_info();

		return is_string( $info ) ? trim( $info ) : '';
	}

	/**
	 * What the server calls itself, when it says.
	 *
	 * No `wp_unslash()`: WordPress slashes `$_GET`, `$_POST`, `$_COOKIE` and `$_REQUEST`, never
	 * `$_SERVER`. This is a banner the server sends, cleaned of markup and control characters
	 * before it goes into a document, not user input being sanitised.
	 */
	public static function web_server(): string {
		$software = isset( $_SERVER['SERVER_SOFTWARE'] ) ? (string) $_SERVER['SERVER_SOFTWARE'] : '';

		return trim( (string) preg_replace( '/[\x00-\x1F\x7F]/', '', wp_strip_all_tags( $software ) ) );
	}

	/** MariaDB announces itself inside the MySQL version string; the two have different advisories. */
	public static function database_name( string $server_info ): string {
		return false !== stripos( $server_info, 'mariadb' ) ? 'mariadb' : 'mysql';
	}

	/** The leading version number of a server string such as "8.0.35-0ubuntu0.22.04.1". */
	public static function version_number( string $server_info ): string {
		return 1 === preg_match( '/(\d+\.\d+(?:\.\d+)?)/', $server_info, $match ) ? $match[1] : '';
	}
}
