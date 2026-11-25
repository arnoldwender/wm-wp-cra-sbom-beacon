<?php
/**
 * WM Suite CRA SBOM Beacon — Suite Hub Spoke Adapter
 *
 * Health, telemetry and actions for the WM Suite Hub, all derived from the state of the served security.txt and
 * the plugin tables. Until 2026-09-15 health, telemetry and self test only checked that a contact option existed,
 * which activation always writes, so an expired file reported HEALTHY; the settings link opened a page that did
 * not exist and the SBOM properties declared CRA Annex I and BSI TR-03183-2 conformance.
 *
 * @package WMCyber\CRA
 */

declare(strict_types=1);

namespace WMCyber\CRA\Adapters;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! interface_exists( 'ArnoldWender\SuiteHub\Contracts\WM_Plugin_Module_Interface' ) ) {
	return;
}

use ArnoldWender\SuiteHub\Contracts\WM_Plugin_Module_Interface;
use WMCyber\CRA\Core\Plugin;

final class Cra_Spoke_Adapter implements WM_Plugin_Module_Interface {

	// security.txt state => hub health.
	private const HEALTH_BY_STATE = [
		'ok'             => 'HEALTHY',
		'expiring'       => 'DEGRADED',
		'expired'        => 'ERROR',
		'invalid'        => 'ERROR',
		'no_route'       => 'ERROR',
		'not_configured' => 'NEEDS_CONFIG',
	];

	public function get_module_slug(): string {
		return 'wm-cra-sbom-beacon';
	}

	public function get_name(): string {
		return 'WM CRA SBOM Beacon';
	}

	public function get_version(): string {
		return defined( 'WM_CRA_VERSION' ) ? WM_CRA_VERSION : '1.2.2';
	}

	public function get_description(): string {
		return 'CycloneDX 1.6 inventory of the active code, security.txt (RFC 9116) and advisories as CSAF 2.0 base documents.';
	}

	public function get_health_status(): string {
		if ( ! $this->tables_exist() ) {
			return 'ERROR';
		}
		$status = Plugin::instance()->get_security_txt()->status();
		// The activation default contact is a guessed address: not healthy until an administrator saved the form.
		if ( 'ok' === $status['state'] && ! $status['confirmed'] ) {
			return 'NEEDS_CONFIG';
		}
		return self::HEALTH_BY_STATE[ $status['state'] ] ?? 'ERROR';
	}

	public function get_sbom_data(): array {
		return [
			'bom-ref'     => 'pkg:wordpress/wm-cra-sbom-beacon@' . $this->get_version(),
			'type'        => 'application',
			'name'        => $this->get_name(),
			'version'     => $this->get_version(),
			'description' => $this->get_description(),
			'scope'       => 'required',
			'hashes'      => [
				[
					'alg'     => 'SHA-256',
					'content' => hash_file( 'sha256', WM_CRA_FILE ),
				],
			],
			// CycloneDX 1.6: "id" must be an SPDX identifier and cannot be combined with "name".
			'licenses'    => [
				[
					'license' => [
						'id' => 'GPL-2.0-or-later',
					],
				],
			],
			'properties'  => [
				[
					'name'  => 'wm:features:sbom',
					'value' => 'CycloneDX 1.6 JSON inventory of the active code (REST, WP-CLI, admin)',
				],
				[
					'name'  => 'wm:features:security-txt',
					'value' => 'security.txt (RFC 9116) from the admin settings',
				],
				[
					'name'  => 'wm:features:advisories',
					'value' => 'advisories stored as CSAF 2.0 base documents (WP-CLI)',
				],
			],
		];
	}

	public function get_dependencies(): array {
		return [];
	}

	public function get_settings_url(): ?string {
		return admin_url( 'admin.php?page=wm-cra-beacon' );
	}

	public function get_telemetry_metrics(): array {
		global $wpdb;
		$plugin          = Plugin::instance();
		$table_snapshots = $wpdb->prefix . 'wm_cra_sbom_snapshots';

		$snapshots_count = 0;
		$latest_hash     = '';
		if ( $this->table_exists( $table_snapshots ) ) {
			$snapshots_count = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i', $table_snapshots ) );
			$row             = $wpdb->get_row( $wpdb->prepare( 'SELECT sbom_sha256 FROM %i ORDER BY id DESC LIMIT 1', $table_snapshots ) );
			if ( $row && ! empty( $row->sbom_sha256 ) ) {
				$latest_hash = substr( (string) $row->sbom_sha256, 0, 16 );
			}
		}

		$status = $plugin->get_security_txt()->status();

		return [
			'sbom_snapshots'           => $snapshots_count,
			'latest_sbom_hash'         => '' !== $latest_hash ? $latest_hash : 'none',
			'advisories'               => $plugin->get_csaf_publisher()->count_advisories(),
			'security_txt_state'       => $status['state'],
			'security_txt_expires'     => '' !== $status['expires'] ? $status['expires'] : 'none',
			'security_txt_confirmed'   => $status['confirmed'] ? 'YES' : 'NO',
			'security_txt_url'         => home_url( '/.well-known/security.txt' ),
		];
	}

	public function execute_action( string $action, array $params = [] ): array {
		switch ( $action ) {
			case 'self_test':
				$status = Plugin::instance()->get_security_txt()->status();
				$tables = $this->tables_exist();
				$ok     = $tables && 'ok' === $status['state'] && $status['confirmed'];
				return [
					'success' => $ok,
					'message' => $ok
						? sprintf( 'security.txt gültig bis %s, Tabellen vorhanden.', $status['expires'] )
						: sprintf(
							'Nicht bereit: security.txt-Status %s%s%s.',
							$status['state'],
							$status['confirmed'] ? '' : ', Kontakt nicht bestätigt',
							$tables ? '' : ', Tabellen fehlen'
						),
				];

			case 'generate_sbom':
				try {
					$snapshot = Plugin::instance()->get_sbom_generator()->save_snapshot();
				} catch ( \Throwable $e ) {
					return [
						'success' => false,
						'message' => 'Fehler bei der SBOM-Erzeugung: ' . $e->getMessage(),
					];
				}
				if ( ! $snapshot['saved'] ) {
					return [
						'success' => false,
						'message' => 'Die SBOM-Momentaufnahme konnte nicht gespeichert werden.',
					];
				}
				return [
					'success' => true,
					'message' => sprintf( 'SBOM-Momentaufnahme %d gespeichert (SHA-256: %s, %d Komponenten).', $snapshot['snapshot_id'], substr( $snapshot['sha256'], 0, 16 ), $snapshot['components_count'] ),
				];

			default:
				return [
					'success' => false,
					'message' => sprintf( 'Unbekannte Spoke-Aktion "%s".', esc_html( $action ) ),
				];
		}
	}

	private function tables_exist(): bool {
		global $wpdb;
		return $this->table_exists( $wpdb->prefix . 'wm_cra_sbom_snapshots' ) && $this->table_exists( $wpdb->prefix . 'wm_cra_advisories' );
	}

	private function table_exists( string $table ): bool {
		global $wpdb;
		return $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) ) === $table;
	}
}
