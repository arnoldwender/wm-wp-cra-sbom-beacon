<?php
/**
 * Plugin Name:       WM CRA SBOM & Vulnerability Beacon
 * Plugin URI:        https://arnoldwender.com/wordpress-plugins/wm-cra-sbom-beacon/
 * Description:       CycloneDX 1.6 inventory of the code WordPress loads, /.well-known/security.txt (RFC 9116) from admin settings, and advisories stored as CSAF 2.0 base documents. It does not assess whether the Cyber Resilience Act applies.
 * Version:           1.2.2
 * Requires at least: 6.4
 * Tested up to:      7.1
 * Requires PHP:      8.2
 * Author:            Arnold Wender
 * Author URI:        https://arnoldwender.com
 * License:           GPLv2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wm-cra-sbom-beacon
 * Domain Path:       /languages
 */

declare(strict_types=1);

namespace WMCyber\CRA;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! defined( 'WM_CRA_VERSION' ) ) {
	define( 'WM_CRA_VERSION', '1.2.2' );
}
if ( ! defined( 'WM_CRA_FILE' ) ) {
	define( 'WM_CRA_FILE', __FILE__ );
}
if ( ! defined( 'WM_CRA_PATH' ) ) {
	define( 'WM_CRA_PATH', plugin_dir_path( __FILE__ ) );
}
if ( ! defined( 'WM_CRA_URL' ) ) {
	define( 'WM_CRA_URL', plugin_dir_url( __FILE__ ) );
}

// Autoloader
spl_autoload_register( function ( string $class ): void {
	$prefix = 'WMCyber\\CRA\\';
	$base_dir = WM_CRA_PATH . 'includes/';

	$len = strlen( $prefix );
	if ( strncmp( $prefix, $class, $len ) !== 0 ) {
		return;
	}

	$relative_class = substr( $class, $len );
	$file = $base_dir . str_replace( '\\', '/', $relative_class ) . '.php';

	if ( file_exists( $file ) ) {
		require_once $file;
	}
} );

// Lifecycle Hooks
register_activation_hook( __FILE__, [ Database\Schema::class, 'activate' ] );
register_deactivation_hook( __FILE__, [ Database\Schema::class, 'deactivate' ] );
register_deactivation_hook( __FILE__, static function (): void {
	wp_clear_scheduled_hook( Vuln\VulnerabilityAudit::CRON_HOOK );
} );

// Multisite: provision tables and defaults when a new subsite is initialized while network-activated.
add_action( 'wp_initialize_site', static function ( object $new_site ): void {
	if ( ! is_multisite() ) {
		return;
	}
	if ( ! function_exists( 'is_plugin_active_for_network' ) && is_file( ABSPATH . 'wp-admin/includes/plugin.php' ) ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
	}
	if ( ! function_exists( 'is_plugin_active_for_network' ) || ! is_plugin_active_for_network( plugin_basename( __FILE__ ) ) ) {
		return;
	}
	$blog_id = (int) ( $new_site->blog_id ?? 0 );
	if ( $blog_id <= 0 ) {
		return;
	}
	switch_to_blog( $blog_id );
	try {
		Database\Schema::activate();
	} finally {
		restore_current_blog();
	}
}, 20 );

// The unattended daily pass over the inventory.
add_action( Vuln\VulnerabilityAudit::CRON_HOOK, [ Vuln\VulnerabilityAudit::class, 'run_scheduled' ] );

// Register as Spoke in WM Suite Hub
add_filter( 'wm_register_suite_module', function ( array $modules ): array {
	if ( ! class_exists( 'WMCyber\CRA\Adapters\Cra_Spoke_Adapter' ) && file_exists( WM_CRA_PATH . 'includes/Adapters/Cra_Spoke_Adapter.php' ) ) {
		require_once WM_CRA_PATH . 'includes/Adapters/Cra_Spoke_Adapter.php';
	}
	if ( class_exists( 'WMCyber\CRA\Adapters\Cra_Spoke_Adapter' ) ) {
		$modules[] = new Adapters\Cra_Spoke_Adapter();
	}
	return $modules;
} );

add_action( 'plugins_loaded', function (): void {
	Core\Plugin::instance()->boot();
} );

