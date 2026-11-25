<?php
declare(strict_types=1);

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

/**
 * WM Suite CRA SBOM Beacon — uninstall (`D-UNINSTALL`).
 *
 * Preserves all options and the 3 CRA Beacon database tables by default across reinstalls.
 * Deletes options, drops tables and cleans up the guard-only uploads/wm-cra/sbom directory
 * only when the administrator explicitly enabled `wm_cra_beacon_delete_data_on_uninstall`.
 *
 * @package WMCyber\CRA
 */
( static function (): void {
	global $wpdb;

	wp_clear_scheduled_hook( 'wm_cra_vuln_scan' );

	$options = [
		'wm_cra_security_txt_contact',
		'wm_cra_security_txt_expires',
		'wm_cra_security_txt_languages',
		'wm_cra_security_txt_policy',
		'wm_cra_security_txt_encryption',
		'wm_cra_security_txt_confirmed',
		'wm_cra_settings',
		'wm_cra_sbom_include_crypto',
		'wm_cra_public_endpoints',
		'wm_cra_api_token_hash',
		'wm_cra_cache_bust',
		'wm_cra_beacon_delete_data_on_uninstall',
		'wm_cra_delete_data_on_uninstall',
		'wm_cra_vuln_enabled',
		'wm_cra_nvd_api_key',
		'wm_cra_vuln_cursor',
		'wm_cra_vuln_state',
		'wm_cra_vex_statements',
		'wm_cra_vex_version',
		'wm_cra_db_version',
	];

	$cleanup_site = static function () use ( $wpdb, $options ): void {
		$delete_all = '1' === (string) get_option( 'wm_cra_beacon_delete_data_on_uninstall', '0' );
		if ( ! $delete_all ) {
			return;
		}

		foreach ( $options as $option ) {
			delete_option( $option );
		}

		foreach ( [ 'wm_cra_sbom_snapshots', 'wm_cra_advisories', 'wm_cra_vulnerabilities', 'wm_cra_audit_log' ] as $table ) {
			$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $wpdb->prefix . $table ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange -- administrator explicitly opted into full data removal on uninstall.
		}

		// The directory DirectoryProtector created: removed only while it holds nothing but its four guard files.
		$uploads = wp_upload_dir( null, false );
		$base    = trailingslashit( (string) ( $uploads['basedir'] ?? '' ) ) . 'wm-cra';
		$dir     = $base . '/sbom';
		if ( '' !== (string) ( $uploads['basedir'] ?? '' ) && is_dir( $dir ) ) {
			$entries = array_values( array_diff( (array) scandir( $dir ), [ '.', '..' ] ) );
			$guards  = [ '.htaccess', 'web.config', 'index.php', 'index.html' ];
			if ( [] === array_diff( $entries, $guards ) ) {
				foreach ( $entries as $entry ) {
					wp_delete_file( $dir . '/' . $entry );
				}
				@rmdir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_rmdir
				if ( is_dir( $base ) && [] === array_diff( (array) scandir( $base ), [ '.', '..' ] ) ) {
					@rmdir( $base ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_rmdir
				}
			}
		}
	};

	if ( is_multisite() ) {
		$any_opted_in = '1' === (string) get_site_option( 'wm_cra_beacon_delete_data_on_uninstall', '0' );
		foreach ( get_sites( [ 'fields' => 'ids', 'number' => 0 ] ) as $site_id ) {
			switch_to_blog( (int) $site_id );
			if ( '1' === (string) get_option( 'wm_cra_beacon_delete_data_on_uninstall', '0' ) ) {
				$any_opted_in = true;
			}
			$cleanup_site();
			restore_current_blog();
		}
		if ( $any_opted_in ) {
			foreach ( $options as $option ) {
				delete_site_option( $option );
			}
		}
	} else {
		$cleanup_site();
	}
} )();
