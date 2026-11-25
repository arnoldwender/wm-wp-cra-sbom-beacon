<?php
declare(strict_types=1);

namespace WMCyber\CRA\Database;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WMCyber\CRA\Beacon\SecurityTxtHandler;

final class Schema {
	/**
	 * Activation. With network activation every site gets its tables and defaults; before 2026-09-15 only the
	 * site that ran the activation did, and the other sites queried tables that did not exist.
	 */
	public static function activate( bool $network_wide = false ): void {
		if ( $network_wide && is_multisite() ) {
			foreach ( get_sites( [ 'fields' => 'ids', 'number' => 0 ] ) as $site_id ) {
				switch_to_blog( (int) $site_id );
				try {
					self::activate_site();
				} finally {
					restore_current_blog();
				}
			}
			return;
		}
		self::activate_site();
	}

	public static function activate_site( bool $flush_rewrite = true ): void {
		global $wpdb;

		$charset_collate  = $wpdb->get_charset_collate();
		$table_snapshots  = $wpdb->prefix . 'wm_cra_sbom_snapshots';
		$table_advisories = $wpdb->prefix . 'wm_cra_advisories';

		if ( ! function_exists( 'dbDelta' ) ) {
			require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		}

		// SBOM snapshots saved on request (admin button, `wp cra sbom-generate --snapshot`, hub action).
		dbDelta( "CREATE TABLE $table_snapshots (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			cyclonedx_version varchar(10) NOT NULL DEFAULT '1.6',
			components_count int(10) unsigned NOT NULL DEFAULT 0,
			sbom_sha256 varchar(64) NOT NULL,
			sbom_json longtext NOT NULL,
			created_at datetime NOT NULL,
			PRIMARY KEY (id),
			KEY idx_created_at (created_at)
		) $charset_collate;" );

		// Findings of the vulnerability audit, replaced per component on each check.
		dbDelta( "CREATE TABLE {$wpdb->prefix}wm_cra_vulnerabilities (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			component_purl varchar(255) NOT NULL,
			source varchar(20) NOT NULL,
			advisory_id varchar(64) NOT NULL,
			cve_id varchar(32) NOT NULL DEFAULT '',
			severity varchar(20) NOT NULL DEFAULT '',
			cvss_score decimal(3,1) NULL,
			summary text NULL,
			detected_at datetime NOT NULL,
			PRIMARY KEY (id),
			KEY idx_component (component_purl),
			KEY idx_cve (cve_id)
		) $charset_collate;" );

		// Advisories published with `wp cra csaf-publish`.
		dbDelta( "CREATE TABLE $table_advisories (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			tracking_id varchar(64) NOT NULL,
			title varchar(255) NOT NULL,
			severity varchar(20) NOT NULL DEFAULT 'medium',
			csaf_json longtext NOT NULL,
			published_at datetime NOT NULL,
			updated_at datetime NOT NULL,
			PRIMARY KEY (id),
			UNIQUE KEY uq_tracking_id (tracking_id)
		) $charset_collate;" );

		// Defaults so the file is served at all. The contact is a guess (security@<host>), so the file counts as
		// unconfirmed until an administrator saves the form. Expires stays under one year (RFC 9116 2.5.5).
		if ( ! get_option( SecurityTxtHandler::OPT_CONTACT ) ) {
			update_option( SecurityTxtHandler::OPT_CONTACT, SecurityTxtHandler::default_contact(), false );
			update_option( SecurityTxtHandler::OPT_EXPIRES, gmdate( 'Y-m-d\TH:i:s\Z', strtotime( '+11 months' ) ), false );
			update_option( SecurityTxtHandler::OPT_LANGUAGES, 'de, en', false );
		}

		// WordPress includes the plugin file during activation after init has run, so the rules that
		// SecurityTxtHandler::init() adds on init are not registered in this request. Until 2026-09-15 the flush
		// below stored the rewrite rules without them and /.well-known/security.txt answered 404 until the
		// permalinks were saved again (measured on a local WordPress install). On plugins_loaded (maybe_upgrade),
		// $wp_rewrite is still null; SecurityTxtHandler::init() registers on init and flushes once on wp_loaded.
		if ( $flush_rewrite ) {
			( new SecurityTxtHandler() )->add_rewrite_rules();
			flush_rewrite_rules();
		}

		// An unattended audit is only unattended if something runs it; the schedule follows the switch.
		\WMCyber\CRA\Vuln\VulnerabilityAudit::sync_schedule();
		update_option( 'wm_cra_db_version', 2, false );
	}

	/**
	 * Keep schema and scheduled vulnerability scans healthy on already-active installs.
	 */
	public static function maybe_upgrade(): void {
		\WMCyber\CRA\Vuln\VulnerabilityAudit::sync_schedule();
		if ( 2 <= (int) get_option( 'wm_cra_db_version', 0 ) ) {
			return;
		}
		self::activate_site( false );
	}

	public static function deactivate(): void {
		// The rules are still registered in this request, so a flush would store them again. Deleting the option
		// makes WordPress rebuild the rules on the next request, without this plugin.
		delete_option( 'rewrite_rules' );
	}
}
