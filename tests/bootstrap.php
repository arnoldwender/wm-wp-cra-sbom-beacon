<?php
declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', sys_get_temp_dir() . '/wordpress/' );
}
if ( ! defined( 'WM_CRA_PATH' ) ) {
	define( 'WM_CRA_PATH', dirname( __DIR__ ) . '/' );
}
if ( ! defined( 'WM_CRA_VERSION' ) ) {
	define( 'WM_CRA_VERSION', '1.2.2' );
}
if ( ! defined( 'WM_CRA_TESTING' ) ) {
	define( 'WM_CRA_TESTING', true );
}

// Every class the generator reaches for, required by hand because there is no autoloader here.
// CycloneDxGenerator calls DependencyScanner, CryptoInventory and RuntimeInventory statically, so
// running the suite through the phpunit that setup-php installs — which does NOT load
// vendor/autoload.php, unlike vendor/bin/phpunit — died on "Class DependencyScanner not found".
// That is exactly how CI ran it, so the job was red while `vendor/bin/phpunit` stayed green locally.
require_once dirname( __DIR__ ) . '/includes/SBOM/DependencyScanner.php';
require_once dirname( __DIR__ ) . '/includes/SBOM/CryptoInventory.php';
require_once dirname( __DIR__ ) . '/includes/SBOM/RuntimeInventory.php';
require_once dirname( __DIR__ ) . '/includes/SBOM/CycloneDxGenerator.php';
require_once dirname( __DIR__ ) . '/includes/Beacon/SecurityTxtHandler.php';

if ( ! function_exists( 'wp_generate_uuid4' ) ) {
	function wp_generate_uuid4() {
		return 'c0a80101-1234-4567-89ab-cdef01234567';
	}
}
if ( ! function_exists( 'get_bloginfo' ) ) {
	function get_bloginfo( $show = 'name' ) {
		return 'Test WordPress DevOps Platform';
	}
}
if ( ! function_exists( 'get_option' ) ) {
	function get_option( $opt, $default = false ) {
		global $mock_options;
		return $mock_options[ $opt ] ?? $default;
	}
}
if ( ! function_exists( 'update_option' ) ) {
	function update_option( $opt, $val ) {
		global $mock_options;
		$mock_options[ $opt ] = $val;
		return true;
	}
}
if ( ! function_exists( 'home_url' ) ) {
	function home_url( $path = '' ) {
		return 'http://localhost:8080' . $path;
	}
}
if ( ! function_exists( 'rest_url' ) ) {
	function rest_url( $path = '' ) {
		return 'http://localhost:8080/wp-json/' . $path;
	}
}
if ( ! function_exists( 'esc_url_raw' ) ) {
	function esc_url_raw( $url ) {
		return $url;
	}
}
if ( ! function_exists( 'wp_get_theme' ) ) {
	function wp_get_theme() {
		return new class {
			public function get_stylesheet() { return 'generatepress'; }
			public function get( $key ) { return '3.5.0'; }
		};
	}
}
if ( ! function_exists( 'sanitize_title' ) ) {
	function sanitize_title( $title ) {
		return strtolower( preg_replace( '/[^a-zA-Z0-9_-]/', '', $title ) );
	}
}

// get_plugins() lives in wp-admin/includes/plugin.php, which the generator requires when the
// function is absent. ABSPATH points at a non-existent temp dir here, so stubbing the function
// is what keeps that require from firing.
if ( ! function_exists( 'get_plugins' ) ) {
	function get_plugins() {
		return array(
			'wm-cra-sbom-beacon/wm-cra-sbom-beacon.php' => array(
				'Name'      => 'WM CRA SBOM Beacon',
				'Version'   => WM_CRA_VERSION,
				'Author'    => 'WM Suite',
				'PluginURI' => 'https://arnoldwender.com',
			),
		);
	}
}

if ( ! function_exists( 'sanitize_text_field' ) ) {
	function sanitize_text_field( $str ) {
		return trim( strip_tags( (string) $str ) );
	}
}

if ( ! function_exists( 'is_multisite' ) ) {
	function is_multisite() {
		return false;
	}
}
if ( ! function_exists( 'wp_strip_all_tags' ) ) {
	function wp_strip_all_tags( $s ) {
		return trim( strip_tags( (string) $s ) );
	}
}
if ( ! function_exists( 'get_file_data' ) ) {
	function get_file_data( $file, $headers ) {
		return array( 'License' => '' );
	}
}

if ( ! function_exists( 'wp_parse_url' ) ) {
	function wp_parse_url( $url, $component = -1 ) {
		return parse_url( $url, $component );
	}
}

// The inventory now walks the plugin and theme directories and reads the CBOM setting, so these
// three have to exist here as well; without them the PHPUnit run stops at "undefined function"
// while the standalone suite stays green, which hides the gap rather than reporting it.
if ( ! function_exists( 'apply_filters' ) ) {
	function apply_filters( $tag, $value, ...$rest ) {
		return $value;
	}
}
if ( ! function_exists( 'get_site_option' ) ) {
	function get_site_option( $option, $default = false ) {
		return $default;
	}
}
if ( ! defined( 'WP_PLUGIN_DIR' ) ) {
	define( 'WP_PLUGIN_DIR', sys_get_temp_dir() . '/wm-cra-phpunit-plugins' );
}

