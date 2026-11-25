<?php
declare(strict_types=1);

namespace WMCyber\CRA\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WMCyber\CRA\API\RestController;
use WMCyber\CRA\SBOM\CryptoInventory;
use WMCyber\CRA\Vuln\NvdClient;
use WMCyber\CRA\Vuln\VulnerabilityAudit;
use WMCyber\CRA\SBOM\CycloneDxGenerator;
use WMCyber\CRA\Beacon\SecurityTxtHandler;
use WMCyber\CRA\CSAF\CsafPublisher;

/**
 * Admin screen and dashboard widget.
 *
 * Until 2026-09-15 the screen was Spanish and showed fixed values: "CIBERRESILIENCIA OK", "SECURITY.TXT ACTIVO",
 * "RFC 9116 verificado", a widget with "18 Komponenten" and "SBOM Signatur gültig" (no signing exists), and a
 * security.txt preview with a fixed Expires date. The settings form saved to an option the served file never read.
 * Every value shown now comes from SecurityTxtHandler::status(), the generator or the tables.
 */
final class AdminDashboard {
	private const PAGE = 'wm-cra-beacon';
	public const OPT_DELETE_ON_UNINSTALL = 'wm_cra_beacon_delete_data_on_uninstall';

	public function __construct(
		private readonly CycloneDxGenerator $sbom_generator,
		private readonly SecurityTxtHandler $security_txt,
		private readonly CsafPublisher $csaf_publisher
	) {}

	public function init(): void {
		add_action( 'admin_menu', [ $this, 'register_admin_menu' ] );
		add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_admin_assets' ] );
		add_action( 'admin_init', [ $this, 'register_settings' ] );
		add_action( 'admin_init', [ $this, 'handle_form_actions' ] );
		add_action( 'wp_dashboard_setup', [ $this, 'register_dashboard_widget' ] );
	}

	public function register_settings(): void {
		if ( function_exists( 'register_setting' ) ) {
			register_setting(
				'wm_cra_beacon_settings',
				'wm_cra_beacon_delete_data_on_uninstall',
				[
					'type'              => 'boolean',
					'sanitize_callback' => static fn( $value ): int => ! empty( $value ) ? 1 : 0,
					'default'           => 0,
				]
			);
		}
	}

	// -------------------------------------------------------------------------------------------------------------
	// Labels
	// -------------------------------------------------------------------------------------------------------------

	/** One sentence for the state of the served security.txt. */
	public static function state_label( array $status ): string {
		switch ( $status['state'] ) {
			case 'ok':
				/* translators: %s: Expires date of security.txt (UTC) */
				return sprintf( __( 'Gültig bis %s', 'wm-cra-sbom-beacon' ), self::date_part( $status['expires'] ) );
			case 'expiring':
				/* translators: 1: number of days, 2: Expires date of security.txt (UTC) */
				return sprintf( __( 'Läuft in %1$d Tagen ab (%2$s)', 'wm-cra-sbom-beacon' ), (int) $status['days_left'], self::date_part( $status['expires'] ) );
			case 'expired':
				/* translators: %s: Expires date of security.txt (UTC) */
				return sprintf( __( 'Abgelaufen am %s', 'wm-cra-sbom-beacon' ), self::date_part( $status['expires'] ) );
			case 'invalid':
				return __( 'Kontakt oder Ablaufdatum ungültig', 'wm-cra-sbom-beacon' );
			case 'no_route':
				return __( 'Nicht erreichbar: Permalinks stehen auf „Einfach“ oder die Regel ist nicht gespeichert', 'wm-cra-sbom-beacon' );
			default:
				return __( 'Kein Kontakt hinterlegt', 'wm-cra-sbom-beacon' );
		}
	}

	private static function date_part( string $rfc3339 ): string {
		return '' !== $rfc3339 ? substr( $rfc3339, 0, 10 ) : '';
	}

	private static function is_good( array $status ): bool {
		return 'ok' === $status['state'] && $status['confirmed'];
	}

	// -------------------------------------------------------------------------------------------------------------
	// Widget
	// -------------------------------------------------------------------------------------------------------------

	public function register_dashboard_widget(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		wp_add_dashboard_widget(
			'wm_cra_sbom_widget',
			__( 'CRA Beacon: security.txt und SBOM', 'wm-cra-sbom-beacon' ),
			[ $this, 'render_dashboard_widget' ]
		);
	}

	public function render_dashboard_widget(): void {
		$status   = $this->security_txt->status();
		$snapshot = $this->latest_snapshot();
		$good     = self::is_good( $status );
		?>
		<div class="wm-dash-widget-box" data-wm-theme="<?php echo esc_attr( function_exists( 'wm_get_suite_theme' ) ? wm_get_suite_theme() : 'cyber-events' ); ?>">
			<div class="wm-dash-banner <?php echo $good ? 'is-valid' : 'is-warning'; ?>">
				<span class="wm-dash-banner-icon dashicons <?php echo $good ? 'dashicons-yes-alt' : 'dashicons-warning'; ?>" aria-hidden="true"></span>
				<div>
					<div class="wm-dash-banner-title">
						<?php
						/* translators: %s: state of security.txt, e.g. "Gültig bis 2027-08-01" */
						echo esc_html( sprintf( __( 'security.txt: %s', 'wm-cra-sbom-beacon' ), self::state_label( $status ) ) );
						?>
					</div>
					<?php if ( 'ok' === $status['state'] && ! $status['confirmed'] ) : ?>
						<div class="wm-dash-banner-sub"><?php esc_html_e( 'Kontakt noch nicht bestätigt: Einstellungen einmal speichern.', 'wm-cra-sbom-beacon' ); ?></div>
					<?php endif; ?>
				</div>
			</div>

			<div class="wm-dash-kpi-grid">
				<div class="wm-dash-kpi-card">
					<div class="wm-dash-kpi-val"><?php echo null === $snapshot ? '–' : esc_html( (string) $snapshot['components_count'] ); ?></div>
					<div class="wm-dash-kpi-lbl"><?php esc_html_e( 'Komponenten (letzte Momentaufnahme)', 'wm-cra-sbom-beacon' ); ?></div>
				</div>
				<div class="wm-dash-kpi-card">
					<div class="wm-dash-kpi-val"><?php echo esc_html( (string) $this->csaf_publisher->count_advisories() ); ?></div>
					<div class="wm-dash-kpi-lbl"><?php esc_html_e( 'Sicherheitshinweise', 'wm-cra-sbom-beacon' ); ?></div>
				</div>
			</div>

			<div class="wm-dash-actions">
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . self::PAGE ) ); ?>" class="wm-dash-btn">
					<?php esc_html_e( 'CRA Beacon öffnen', 'wm-cra-sbom-beacon' ); ?>
				</a>
				<a href="<?php echo esc_url( rest_url( 'wm-cra/v1/sbom' ) ); ?>" class="wm-dash-btn">
					<?php esc_html_e( 'SBOM als JSON', 'wm-cra-sbom-beacon' ); ?>
				</a>
			</div>
		</div>
		<?php
	}

	// -------------------------------------------------------------------------------------------------------------
	// Menu and assets
	// -------------------------------------------------------------------------------------------------------------

	/**
	 * Family menu icon: a monochrome hub-and-spoke mark, filled shapes only so the WordPress
	 * svg-painter can recolour it with the admin colour scheme. Placeholder until the family
	 * icon is decided (hackaton plan D12).
	 */
	public static function family_menu_icon(): string {
		$svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><circle cx="10" cy="10" r="2.6" fill="black"/><circle cx="10" cy="3" r="1.8" fill="black"/><circle cx="16.1" cy="13.5" r="1.8" fill="black"/><circle cx="3.9" cy="13.5" r="1.8" fill="black"/><rect x="9.3" y="4.5" width="1.4" height="3.4" fill="black"/><rect x="9.3" y="12.1" width="1.4" height="3.4" fill="black" transform="rotate(-60 10 10)"/><rect x="9.3" y="12.1" width="1.4" height="3.4" fill="black" transform="rotate(60 10 10)"/></svg>';
		return 'data:image/svg+xml;base64,' . base64_encode( $svg );
	}

	public function register_admin_menu(): void {
		add_menu_page(
			__( 'CRA Beacon', 'wm-cra-sbom-beacon' ),
			__( 'CRA Beacon (SBOM)', 'wm-cra-sbom-beacon' ),
			'manage_options',
			self::PAGE,
			[ $this, 'render_dashboard_page' ],
			self::family_menu_icon(),
			30
		);
	}

	public function enqueue_admin_assets( string $hook ): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only routing check.
		$page = sanitize_text_field( wp_unslash( $_GET['page'] ?? '' ) );
		// index.php: the dashboard widget uses the family classes too (until 2026-09-15 it rendered unstyled there).
		if ( 'index.php' !== $hook && ! str_contains( $hook, 'wm-cra' ) && ! str_contains( $page, 'wm-cra' ) ) {
			return;
		}

		$root = dirname( __DIR__, 2 ) . '/assets/css/';
		wp_enqueue_style(
			'wm-admin-tokens',
			WM_CRA_URL . 'assets/css/wm-admin-tokens.css',
			[],
			(string) ( @filemtime( $root . 'wm-admin-tokens.css' ) ?: WM_CRA_VERSION )
		);
		wp_enqueue_style(
			'wm-admin-ui',
			WM_CRA_URL . 'assets/css/wm-admin-ui.css',
			[ 'wm-admin-tokens' ],
			(string) ( @filemtime( $root . 'wm-admin-ui.css' ) ?: WM_CRA_VERSION )
		);
	}

	// -------------------------------------------------------------------------------------------------------------
	// Form actions
	// -------------------------------------------------------------------------------------------------------------

	public function handle_form_actions(): void {
		if ( ! isset( $_POST['wm_cra_action'] ) || ! current_user_can( 'manage_options' ) ) {
			return;
		}

		check_admin_referer( 'wm_cra_admin_action', 'wm_cra_nonce' );

		$action = sanitize_key( wp_unslash( $_POST['wm_cra_action'] ) );

		if ( 'generate_snapshot' === $action ) {
			$snapshot = $this->sbom_generator->save_snapshot();
			$this->redirect( 'sbom', $snapshot['saved'] ? [ 'generated' => '1' ] : [ 'snapshot_error' => '1' ] );
		}

		if ( 'save_vuln_options' === $action ) {
			update_option( VulnerabilityAudit::OPT_ENABLED, isset( $_POST['vuln_enabled'] ) ? 1 : 0, false );
			// The key only raises the rate limit; an unusable one is stored as empty rather than
			// kept, so the client falls back to the slower budget instead of sending a bad header.
			$key = sanitize_text_field( wp_unslash( $_POST['nvd_api_key'] ?? '' ) );
			update_option( NvdClient::OPT_API_KEY, 1 === preg_match( '/^[A-Za-z0-9-]{8,64}$/', $key ) ? $key : '' );
			VulnerabilityAudit::sync_schedule();
			$this->redirect( 'vuln', [ 'saved' => '1' ] );
		}

		if ( 'run_vuln_scan' === $action ) {
			( new VulnerabilityAudit( $this->sbom_generator ) )->run( 'manual' );
			$this->redirect( 'vuln', [ 'saved' => '1' ] );
		}

		if ( 'save_sbom_options' === $action ) {
			// Its own action, not part of the security.txt form: a checkbox has nothing to validate,
			// and folding it in would let an invalid Expires date discard a setting that is fine.
			update_option( CryptoInventory::OPT_INCLUDE, isset( $_POST['include_crypto'] ) ? 1 : 0, false );
			update_option( RestController::OPT_PUBLIC_ENDPOINTS, isset( $_POST['public_endpoints'] ) ? 1 : 0, false );
			RestController::flush_caches();
			$this->redirect( 'sbom', [ 'saved' => '1' ] );
		}

		if ( 'rotate_api_token' === $action ) {
			$token = RestController::rotate_api_token();
			if ( function_exists( 'set_transient' ) ) {
				$uid = function_exists( 'get_current_user_id' ) ? (int) get_current_user_id() : 0;
				set_transient( 'wm_cra_flash_token_' . $uid, $token, 60 );
			}
			$this->redirect( 'sbom', [ 'token_rotated' => '1' ] );
		}

		if ( 'revoke_api_token' === $action ) {
			RestController::revoke_api_token();
			$this->redirect( 'sbom', [ 'token_revoked' => '1' ] );
		}

		if ( 'save_uninstall_options' === $action ) {
			update_option( 'wm_cra_beacon_delete_data_on_uninstall', isset( $_POST['delete_data_on_uninstall'] ) ? 1 : 0, false );
			$this->redirect( 'settings', [ 'uninstall_saved' => '1' ] );
		}

		if ( 'save_settings' === $action ) {
			$errors = $this->save_settings( wp_unslash( $_POST ) );
			$this->redirect( 'settings', [] === $errors ? [ 'saved' => '1' ] : [ 'errors' => implode( ',', $errors ) ] );
		}
	}

	/**
	 * Validate every field first; write the security.txt options only when all are valid. The legacy option
	 * wm_cra_settings (written until 2026-09-15, never read) is left alone and removed on uninstall.
	 *
	 * @param array<string, mixed> $post Unslashed $_POST.
	 * @return list<string> Error codes; empty when saved.
	 */
	public function save_settings( array $post ): array {
		$values = [
			SecurityTxtHandler::OPT_CONTACT    => SecurityTxtHandler::sanitize_contact( (string) ( $post['contact'] ?? '' ) ),
			SecurityTxtHandler::OPT_EXPIRES    => SecurityTxtHandler::sanitize_expires( (string) ( $post['expires'] ?? '' ) ),
			SecurityTxtHandler::OPT_LANGUAGES  => SecurityTxtHandler::sanitize_languages( (string) ( $post['languages'] ?? '' ) ),
			SecurityTxtHandler::OPT_POLICY     => SecurityTxtHandler::sanitize_https_url( (string) ( $post['policy'] ?? '' ) ),
			SecurityTxtHandler::OPT_ENCRYPTION => SecurityTxtHandler::sanitize_https_url( (string) ( $post['encryption'] ?? '' ) ),
		];
		$codes = [
			SecurityTxtHandler::OPT_CONTACT    => 'contact',
			SecurityTxtHandler::OPT_EXPIRES    => 'expires',
			SecurityTxtHandler::OPT_LANGUAGES  => 'languages',
			SecurityTxtHandler::OPT_POLICY     => 'policy',
			SecurityTxtHandler::OPT_ENCRYPTION => 'encryption',
		];

		$errors = [];
		foreach ( $values as $option => $value ) {
			if ( null === $value ) {
				$errors[] = $codes[ $option ];
			}
		}
		if ( [] !== $errors ) {
			return $errors;
		}

		foreach ( $values as $option => $value ) {
			update_option( $option, $value );
		}
		update_option( SecurityTxtHandler::OPT_CONFIRMED, gmdate( 'Y-m-d\TH:i:s\Z' ), false );
		return [];
	}

	/** @param array<string, string> $args */
	private function redirect( string $tab, array $args ): void {
		wp_safe_redirect( add_query_arg( array_merge( [ 'page' => self::PAGE, 'tab' => $tab ], $args ), admin_url( 'admin.php' ) ) );
		exit;
	}

	// -------------------------------------------------------------------------------------------------------------
	// Data
	// -------------------------------------------------------------------------------------------------------------

	private function snapshots_table(): string {
		global $wpdb;
		return $wpdb->prefix . 'wm_cra_sbom_snapshots';
	}

	private function snapshots_table_exists(): bool {
		global $wpdb;
		$table = $this->snapshots_table();
		return $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) ) === $table;
	}

	/** @return array{components_count: int, sbom_sha256: string, created_at: string}|null */
	private function latest_snapshot(): ?array {
		$rows = $this->recent_snapshots( 1 );
		return $rows[0] ?? null;
	}

	/** @return list<array{components_count: int, sbom_sha256: string, created_at: string}> */
	private function recent_snapshots( int $limit ): array {
		global $wpdb;
		if ( ! $this->snapshots_table_exists() ) {
			return [];
		}
		$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT components_count, sbom_sha256, created_at FROM %i ORDER BY id DESC LIMIT %d', $this->snapshots_table(), $limit ), ARRAY_A );
		$out  = [];
		foreach ( (array) $rows as $row ) {
			$out[] = [
				'components_count' => (int) $row['components_count'],
				'sbom_sha256'      => (string) $row['sbom_sha256'],
				'created_at'       => (string) $row['created_at'],
			];
		}
		return $out;
	}

	private function count_snapshots(): int {
		global $wpdb;
		return $this->snapshots_table_exists() ? (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i', $this->snapshots_table() ) ) : 0;
	}

	/** Licence names of a component, or an empty string. */
	private static function license_text( array $component ): string {
		$names = [];
		foreach ( (array) ( $component['licenses'] ?? [] ) as $entry ) {
			$name = $entry['license']['name'] ?? ( $entry['license']['id'] ?? '' );
			if ( '' !== (string) $name ) {
				$names[] = (string) $name;
			}
		}
		return implode( ', ', $names );
	}

	// -------------------------------------------------------------------------------------------------------------
	// Page
	// -------------------------------------------------------------------------------------------------------------

	public function render_dashboard_page(): void {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only tab routing and result notices.
		$current_tab = sanitize_key( wp_unslash( $_GET['tab'] ?? 'overview' ) );
		$errors      = isset( $_GET['errors'] ) ? array_filter( explode( ',', sanitize_text_field( wp_unslash( $_GET['errors'] ) ) ) ) : [];
		$notice      = isset( $_GET['saved'] ) ? 'saved' : ( isset( $_GET['generated'] ) ? 'generated' : ( isset( $_GET['snapshot_error'] ) ? 'snapshot_error' : ( isset( $_GET['token_rotated'] ) ? 'token_rotated' : ( isset( $_GET['token_revoked'] ) ? 'token_revoked' : ( isset( $_GET['uninstall_saved'] ) ? 'uninstall_saved' : '' ) ) ) ) );
		// phpcs:enable

		$tabs = [
			'overview' => [ 'label' => __( 'Übersicht', 'wm-cra-sbom-beacon' ), 'icon' => 'dashicons-dashboard' ],
			'sbom'     => [ 'label' => __( 'Software-Liste (SBOM)', 'wm-cra-sbom-beacon' ), 'icon' => 'dashicons-list-view' ],
			'vuln'     => [ 'label' => __( 'Schwachstellen', 'wm-cra-sbom-beacon' ), 'icon' => 'dashicons-shield' ],
			'settings' => [ 'label' => __( 'security.txt', 'wm-cra-sbom-beacon' ), 'icon' => 'dashicons-admin-settings' ],
			'glossary' => [ 'label' => __( 'Begriffe', 'wm-cra-sbom-beacon' ), 'icon' => 'dashicons-book' ],
		];
		if ( ! isset( $tabs[ $current_tab ] ) ) {
			$current_tab = 'overview';
		}

		$status = $this->security_txt->status();
		$good   = self::is_good( $status );
		?>
		<div class="wrap wm-admin wm-cra-admin-wrap">
			<header class="wm-admin-header">
				<div class="wm-header-brand">
					<div class="wm-header-icon">
						<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
					</div>
					<div>
						<h1><?php esc_html_e( 'CRA Beacon: security.txt, Software-Liste und Sicherheitshinweise', 'wm-cra-sbom-beacon' ); ?></h1>
						<p class="wm-subtitle"><?php esc_html_e( 'CycloneDX 1.6 · security.txt (RFC 9116) · CSAF 2.0 (Basisprofil)', 'wm-cra-sbom-beacon' ); ?></p>
					</div>
				</div>
				<div class="wm-header-badges">
					<span class="wm-badge-family" title="<?php esc_attr_e( 'Part of the WM Suite plugin family', 'wm-cra-sbom-beacon' ); ?>">
						<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="3"/><circle cx="12" cy="4" r="2"/><circle cx="19" cy="16" r="2"/><circle cx="5" cy="16" r="2"/><path d="M12 7v2M13.9 13.2l3.4 2M10.1 13.2l-3.4 2"/></svg>
						<?php esc_html_e( 'WM Suite', 'wm-cra-sbom-beacon' ); ?>
						<span class="wm-badge-family-state"><?php echo defined( 'WM_SUITE_HUB_VERSION' ) ? esc_html__( 'Hub', 'wm-cra-sbom-beacon' ) : esc_html__( 'Standalone', 'wm-cra-sbom-beacon' ); ?></span>
					</span>
					<span class="wm-badge <?php echo esc_attr( $good ? 'wm-badge-green' : ( in_array( $status['state'], [ 'ok', 'expiring' ], true ) ? 'wm-badge-amber' : 'wm-badge-red' ) ); ?>">
						<?php
						/* translators: %s: state of security.txt */
						echo esc_html( sprintf( __( 'security.txt: %s', 'wm-cra-sbom-beacon' ), self::state_label( $status ) ) );
						?>
					</span>
				</div>
			</header>

			<div class="wm-quick-guide">
				<div class="wm-quick-guide-title"><?php esc_html_e( 'Was dieses Plugin tut', 'wm-cra-sbom-beacon' ); ?></div>
				<p class="wm-quick-guide-desc">
					<?php esc_html_e( 'Es erzeugt eine Liste des Codes, den WordPress lädt, im Format CycloneDX 1.6, stellt die Datei /.well-known/security.txt aus den Angaben auf dieser Seite bereit und listet Sicherheitshinweise, die mit WP-CLI veröffentlicht wurden. Es prüft nicht, ob der Cyber Resilience Act für diese Website oder ihre Betreiber gilt, und es ersetzt keine Meldung nach Artikel 14 der Verordnung.', 'wm-cra-sbom-beacon' ); ?>
				</p>
				<div class="wm-quick-guide-actions">
					<form method="post">
						<?php wp_nonce_field( 'wm_cra_admin_action', 'wm_cra_nonce' ); ?>
						<input type="hidden" name="wm_cra_action" value="generate_snapshot" />
						<button type="submit" class="wm-preset-pill-btn"><?php esc_html_e( 'Momentaufnahme der SBOM speichern', 'wm-cra-sbom-beacon' ); ?></button>
					</form>
					<a href="<?php echo esc_url( home_url( '/.well-known/security.txt' ) ); ?>" class="wm-preset-pill-btn"><?php esc_html_e( 'security.txt öffnen', 'wm-cra-sbom-beacon' ); ?></a>
					<a href="<?php echo esc_url( rest_url( 'wm-cra/v1/sbom' ) ); ?>" class="wm-preset-pill-btn"><?php esc_html_e( 'SBOM als JSON', 'wm-cra-sbom-beacon' ); ?></a>
				</div>
			</div>

			<?php if ( 'saved' === $notice ) : ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'security.txt gespeichert. Die ausgelieferte Datei nutzt die neuen Angaben.', 'wm-cra-sbom-beacon' ); ?></p></div>
			<?php elseif ( 'generated' === $notice ) : ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Momentaufnahme gespeichert; sie steht in der Liste unter „Software-Liste (SBOM)“.', 'wm-cra-sbom-beacon' ); ?></p></div>
			<?php elseif ( 'snapshot_error' === $notice ) : ?>
				<div class="notice notice-error"><p><?php esc_html_e( 'Die Momentaufnahme konnte nicht gespeichert werden. Fehlt die Tabelle, das Plugin einmal deaktivieren und wieder aktivieren.', 'wm-cra-sbom-beacon' ); ?></p></div>
			<?php elseif ( 'token_rotated' === $notice ) : ?>
				<?php
				$uid         = function_exists( 'get_current_user_id' ) ? (int) get_current_user_id() : 0;
				$flash_token = function_exists( 'get_transient' ) ? (string) get_transient( 'wm_cra_flash_token_' . $uid ) : '';
				if ( '' !== $flash_token && function_exists( 'delete_transient' ) ) {
					delete_transient( 'wm_cra_flash_token_' . $uid );
				}
				?>
				<div class="notice notice-success is-dismissible">
					<p>
						<?php esc_html_e( 'Neues Bearer-Token erzeugt (wird nur einmal angezeigt):', 'wm-cra-sbom-beacon' ); ?>
						<?php if ( '' !== $flash_token ) : ?>
							<code><?php echo esc_html( $flash_token ); ?></code>
						<?php endif; ?>
					</p>
				</div>
			<?php elseif ( 'token_revoked' === $notice ) : ?>
				<div class="notice notice-info is-dismissible"><p><?php esc_html_e( 'Bearer-Token widerrufen.', 'wm-cra-sbom-beacon' ); ?></p></div>
			<?php elseif ( 'uninstall_saved' === $notice ) : ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Deinstallations-Einstellung gespeichert.', 'wm-cra-sbom-beacon' ); ?></p></div>
			<?php endif; ?>
			<?php if ( [] !== $errors ) : ?>
				<div class="notice notice-error"><p><?php esc_html_e( 'Nichts gespeichert. Bitte diese Felder prüfen:', 'wm-cra-sbom-beacon' ); ?> <?php echo esc_html( implode( ', ', array_map( [ self::class, 'field_label' ], $errors ) ) ); ?></p></div>
			<?php endif; ?>

			<nav class="wm-nav-tabs" aria-label="<?php esc_attr_e( 'Bereiche', 'wm-cra-sbom-beacon' ); ?>">
				<?php foreach ( $tabs as $slug => $tab ) : ?>
					<a href="<?php echo esc_url( add_query_arg( [ 'page' => self::PAGE, 'tab' => $slug ], admin_url( 'admin.php' ) ) ); ?>" class="wm-tab-link <?php echo $current_tab === $slug ? 'active' : ''; ?>"<?php echo $current_tab === $slug ? ' aria-current="page"' : ''; ?>>
						<span class="dashicons <?php echo esc_attr( $tab['icon'] ); ?>" aria-hidden="true"></span> <?php echo esc_html( $tab['label'] ); ?>
					</a>
				<?php endforeach; ?>
			</nav>

			<?php
			if ( 'overview' === $current_tab ) {
				$this->render_overview( $status );
			} elseif ( 'sbom' === $current_tab ) {
				$this->render_sbom();
			} elseif ( 'vuln' === $current_tab ) {
				$this->render_vulnerabilities();
			} elseif ( 'settings' === $current_tab ) {
				$this->render_settings( $status );
			} else {
				$this->render_glossary();
			}
			?>
		</div>
		<?php
	}

	public static function field_label( string $code ): string {
		$labels = [
			'contact'    => __( 'Kontakt', 'wm-cra-sbom-beacon' ),
			'expires'    => __( 'Ablaufdatum', 'wm-cra-sbom-beacon' ),
			'languages'  => __( 'Sprachen', 'wm-cra-sbom-beacon' ),
			'policy'     => __( 'Richtlinie', 'wm-cra-sbom-beacon' ),
			'encryption' => __( 'Schlüssel', 'wm-cra-sbom-beacon' ),
		];
		return $labels[ $code ] ?? $code;
	}

	private function render_overview( array $status ): void {
		$components = count( $this->sbom_generator->generate_sbom()['components'] );
		?>
		<div class="wm-grid-4">
			<div class="wm-stat-card">
				<span class="wm-stat-label"><?php esc_html_e( 'Komponenten jetzt', 'wm-cra-sbom-beacon' ); ?></span>
				<span class="wm-stat-value"><?php echo esc_html( (string) $components ); ?></span>
				<span class="wm-stat-delta"><?php esc_html_e( 'WordPress, aktive Plugins, Must-Use-Plugins, Themes', 'wm-cra-sbom-beacon' ); ?></span>
			</div>
			<div class="wm-stat-card">
				<span class="wm-stat-label"><?php esc_html_e( 'security.txt', 'wm-cra-sbom-beacon' ); ?></span>
				<span class="wm-stat-value"><?php echo esc_html( self::state_label( $status ) ); ?></span>
				<span class="wm-stat-delta"><?php echo $status['confirmed'] ? esc_html__( 'Kontakt bestätigt', 'wm-cra-sbom-beacon' ) : esc_html__( 'Kontakt nicht bestätigt', 'wm-cra-sbom-beacon' ); ?></span>
			</div>
			<div class="wm-stat-card">
				<span class="wm-stat-label"><?php esc_html_e( 'Momentaufnahmen', 'wm-cra-sbom-beacon' ); ?></span>
				<span class="wm-stat-value"><?php echo esc_html( (string) $this->count_snapshots() ); ?></span>
				<span class="wm-stat-delta"><?php esc_html_e( 'gespeicherte SBOMs', 'wm-cra-sbom-beacon' ); ?></span>
			</div>
			<div class="wm-stat-card">
				<span class="wm-stat-label"><?php esc_html_e( 'Sicherheitshinweise', 'wm-cra-sbom-beacon' ); ?></span>
				<span class="wm-stat-value"><?php echo esc_html( (string) $this->csaf_publisher->count_advisories() ); ?></span>
				<span class="wm-stat-delta"><?php esc_html_e( 'veröffentlicht mit wp cra csaf-publish', 'wm-cra-sbom-beacon' ); ?></span>
			</div>
		</div>

		<?php if ( ! self::is_good( $status ) ) : ?>
			<div class="wm-inline-notice is-warning">
				<?php
				if ( 'ok' === $status['state'] ) {
					/* translators: %s: contact written on activation, e.g. mailto:security@example.com */
					echo esc_html( sprintf( __( 'Der Kontakt wurde bei der Aktivierung geraten (%s) und ist noch nicht bestätigt. Prüfen Sie die Adresse unter „security.txt“ und speichern Sie einmal.', 'wm-cra-sbom-beacon' ), $this->security_txt->get_fields()['contact'] ) );
				} else {
					echo esc_html( self::state_label( $status ) );
				}
				?>
			</div>
		<?php endif; ?>

		<div class="wm-card">
			<h2><?php esc_html_e( 'Ausgelieferte security.txt', 'wm-cra-sbom-beacon' ); ?></h2>
			<p class="wm-field-desc">
				<?php
				/* translators: %s: URL of security.txt */
				echo esc_html( sprintf( __( 'Genau dieser Inhalt wird unter %s ausgeliefert:', 'wm-cra-sbom-beacon' ), home_url( '/.well-known/security.txt' ) ) );
				?>
			</p>
			<pre class="wm-code-block"><?php echo esc_html( $this->security_txt->generate_security_txt_content() ); ?></pre>
		</div>
		<?php
	}

	/**
	 * Render the vulnerability audit.
	 *
	 * The table is per component and leads with its **state**, not with a count: NVD's rate limit
	 * means one run reaches a handful of components, so most rows are legitimately unchecked most
	 * of the time. A screen that showed a green tick for them would be claiming something about the
	 * majority of the site that nobody established.
	 */
	private function render_vulnerabilities(): void {
		$state    = VulnerabilityAudit::state();
		$findings = VulnerabilityAudit::findings( 100 );
		$enabled  = (bool) get_option( VulnerabilityAudit::OPT_ENABLED, 1 );
		$has_key  = NvdClient::has_key();
		$next_run = wp_next_scheduled( VulnerabilityAudit::CRON_HOOK );

		$labels = [
			VulnerabilityAudit::STATE_CHECKED         => __( 'geprüft', 'wm-cra-sbom-beacon' ),
			VulnerabilityAudit::STATE_NEVER_CHECKED   => __( 'noch nie geprüft', 'wm-cra-sbom-beacon' ),
			VulnerabilityAudit::STATE_UNKNOWN_VERSION => __( 'Version unbekannt', 'wm-cra-sbom-beacon' ),
			VulnerabilityAudit::STATE_SOURCE_ERROR    => __( 'Quelle nicht erreichbar', 'wm-cra-sbom-beacon' ),
		];
		$by_purl = [];
		foreach ( $findings as $row ) {
			$by_purl[ (string) $row['component_purl'] ][] = $row;
		}
		?>
		<div class="wm-card">
			<h2><?php esc_html_e( 'Abgleich gegen Schwachstellen-Datenbanken', 'wm-cra-sbom-beacon' ); ?></h2>
			<p class="wm-field-desc"><?php esc_html_e( 'Composer- und npm-Pakete gehen an OSV, WordPress-Komponenten an die NVD. Jede Quelle wird nur nach dem gefragt, was sie führt: die NVD kennt keine Composer-Pakete unter diesen Namen, und OSV liefert für WordPress-Plugins auf jede Anfrage eine leere Antwort — die sich wie ein unauffälliger Befund liest. Die NVD begrenzt ohne Schlüssel auf fünf Anfragen je 30 Sekunden, deshalb prüft ein Lauf nur einen Teil der Liste und merkt sich, wo er stehen geblieben ist.', 'wm-cra-sbom-beacon' ); ?></p>
			<p class="wm-field-desc"><strong><?php esc_html_e( 'Eine nicht geprüfte Komponente ist keine unauffällige Komponente.', 'wm-cra-sbom-beacon' ); ?></strong></p>

			<?php if ( [] === $state ) : ?>
				<p class="wm-empty-state"><?php esc_html_e( 'Noch kein Abgleich gelaufen.', 'wm-cra-sbom-beacon' ); ?></p>
			<?php else : ?>
				<div class="wm-table-container">
					<table class="wm-table">
						<thead>
							<tr>
								<th scope="col"><?php esc_html_e( 'Komponente', 'wm-cra-sbom-beacon' ); ?></th>
								<th scope="col"><?php esc_html_e( 'Version', 'wm-cra-sbom-beacon' ); ?></th>
								<th scope="col"><?php esc_html_e( 'Stand', 'wm-cra-sbom-beacon' ); ?></th>
								<th scope="col"><?php esc_html_e( 'Quelle', 'wm-cra-sbom-beacon' ); ?></th>
								<th scope="col"><?php esc_html_e( 'Geprüft (UTC)', 'wm-cra-sbom-beacon' ); ?></th>
								<th scope="col"><?php esc_html_e( 'Treffer', 'wm-cra-sbom-beacon' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ( $state as $purl => $row ) : ?>
								<tr>
									<td><strong><?php echo esc_html( (string) ( $row['name'] ?? $purl ) ); ?></strong><br /><code><?php echo esc_html( (string) $purl ); ?></code></td>
									<td><?php echo esc_html( '' !== (string) ( $row['version'] ?? '' ) ? (string) $row['version'] : '—' ); ?></td>
									<td><?php echo esc_html( $labels[ (string) ( $row['state'] ?? '' ) ] ?? (string) ( $row['state'] ?? '' ) ); ?>
										<?php if ( ! empty( $row['error'] ) ) : ?>
											<br /><span class="wm-field-desc"><?php echo esc_html( (string) $row['error'] ); ?></span>
										<?php endif; ?>
										<?php if ( ! empty( $row['note'] ) ) : ?>
											<br /><span class="wm-field-desc"><?php echo esc_html( (string) $row['note'] ); ?></span>
										<?php endif; ?>
									</td>
									<td><?php echo esc_html( '' !== (string) ( $row['source'] ?? '' ) ? strtoupper( (string) $row['source'] ) : '—' ); ?></td>
									<td><?php echo esc_html( '' !== (string) ( $row['checked'] ?? '' ) ? substr( (string) $row['checked'], 0, 19 ) : '—' ); ?></td>
									<td>
										<?php echo esc_html( (string) (int) ( $row['findings'] ?? 0 ) ); ?>
										<?php foreach ( $by_purl[ (string) $purl ] ?? [] as $finding ) : ?>
											<br /><code><?php echo esc_html( '' !== (string) $finding['cve_id'] ? (string) $finding['cve_id'] : (string) $finding['advisory_id'] ); ?></code>
											<?php if ( null !== $finding['cvss_score'] ) : ?>
												<?php echo esc_html( ' CVSS ' . (string) $finding['cvss_score'] ); ?>
											<?php endif; ?>
										<?php endforeach; ?>
									</td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
				</div>
			<?php endif; ?>
		</div>

		<div class="wm-card">
			<h2><?php esc_html_e( 'Einstellungen des Abgleichs', 'wm-cra-sbom-beacon' ); ?></h2>
			<form method="post">
				<?php wp_nonce_field( 'wm_cra_admin_action', 'wm_cra_nonce' ); ?>
				<input type="hidden" name="wm_cra_action" value="save_vuln_options" />
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><?php esc_html_e( 'Täglicher Abgleich', 'wm-cra-sbom-beacon' ); ?></th>
						<td>
							<label for="wm_cra_vuln_enabled">
								<input type="checkbox" name="vuln_enabled" id="wm_cra_vuln_enabled" value="1" <?php checked( $enabled ); ?> />
								<?php esc_html_e( 'Die Software-Liste täglich gegen OSV und die NVD abgleichen', 'wm-cra-sbom-beacon' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="wm_cra_nvd_api_key"><?php esc_html_e( 'NVD-API-Schlüssel (optional)', 'wm-cra-sbom-beacon' ); ?></label></th>
						<td>
							<input type="text" name="nvd_api_key" id="wm_cra_nvd_api_key" value="" class="regular-text" autocomplete="off" placeholder="<?php echo esc_attr( $has_key ? __( 'hinterlegt — zum Ändern neu eingeben, zum Löschen leer speichern', 'wm-cra-sbom-beacon' ) : __( 'kein Schlüssel hinterlegt', 'wm-cra-sbom-beacon' ) ); ?>" />
							<p class="wm-field-desc">
								<?php
								/* translators: 1: components per run without a key, 2: components per run with a key */
								echo esc_html( sprintf( __( 'Ohne Schlüssel erlaubt die NVD fünf Anfragen je 30 Sekunden, also %1$d Komponenten pro Lauf; mit Schlüssel 50 je 30 Sekunden und %2$d Komponenten pro Lauf.', 'wm-cra-sbom-beacon' ), NvdClient::BUDGET_WITHOUT_KEY, NvdClient::BUDGET_WITH_KEY ) );
								?>
							</p>
						</td>
					</tr>
				</table>
				<button type="submit" class="button button-primary"><?php esc_html_e( 'Übernehmen', 'wm-cra-sbom-beacon' ); ?></button>
			</form>

			<form method="post">
				<?php wp_nonce_field( 'wm_cra_admin_action', 'wm_cra_nonce' ); ?>
				<input type="hidden" name="wm_cra_action" value="run_vuln_scan" />
				<p>
					<button type="submit" class="button"><?php esc_html_e( 'Jetzt einen Durchgang ausführen', 'wm-cra-sbom-beacon' ); ?></button>
					<span class="wm-field-desc">
						<?php if ( ! $enabled ) : ?>
							<?php esc_html_e( 'Der geplante Abgleich ist aus; es läuft nur, was Sie hier starten.', 'wm-cra-sbom-beacon' ); ?>
						<?php elseif ( $next_run ) : ?>
							<?php
							/* translators: %s: timestamp in UTC */
							echo esc_html( sprintf( __( 'Nächster geplanter Lauf: %s UTC.', 'wm-cra-sbom-beacon' ), gmdate( 'Y-m-d H:i:s', (int) $next_run ) ) );
							?>
						<?php else : ?>
							<?php esc_html_e( 'Der Abgleich ist eingeschaltet, aber es ist kein Lauf geplant. Einmal speichern legt den Termin an.', 'wm-cra-sbom-beacon' ); ?>
						<?php endif; ?>
					</span>
				</p>
			</form>
		</div>
		<?php
	}

	private function render_sbom(): void {
		$sbom      = $this->sbom_generator->generate_sbom();
		$snapshots = $this->recent_snapshots( 10 );
		$unknown   = __( 'nicht angegeben', 'wm-cra-sbom-beacon' );
		?>
		<div class="wm-card">
			<h2><?php esc_html_e( 'Aktiver Code', 'wm-cra-sbom-beacon' ); ?></h2>
			<p class="wm-field-desc"><?php esc_html_e( 'WordPress, aktive Plugins (Website und Netzwerk), Must-Use-Plugins, das aktive Theme und sein Eltern-Theme mit den Angaben aus ihren Dateiköpfen; dazu die Composer- und npm-Bibliotheken, die diese Plugins und Themes mitliefern, und die Laufzeit darunter (PHP, versionierte Erweiterungen, Datenbankserver). Inaktive Plugins sind nicht enthalten.', 'wm-cra-sbom-beacon' ); ?></p>

			<form method="post" class="wm-inline-form">
				<?php wp_nonce_field( 'wm_cra_admin_action', 'wm_cra_nonce' ); ?>
				<input type="hidden" name="wm_cra_action" value="save_sbom_options" />
				<label for="wm_cra_include_crypto">
					<input type="checkbox" name="include_crypto" id="wm_cra_include_crypto" value="1" <?php checked( CryptoInventory::enabled() ); ?> />
					<?php esc_html_e( 'Kryptografische Verfahren mitaufnehmen (CBOM)', 'wm-cra-sbom-beacon' ); ?>
				</label>
				<p class="wm-field-desc"><?php esc_html_e( 'Listet die Hash-Verfahren, Chiffren und TLS-Versionen auf, die dieser Server anbietet — auch die veralteten, denn genau dafür ist eine Krypto-Liste da. Auf einem üblichen PHP 8.3 mit OpenSSL 3.5 sind das rund 186 zusätzliche Einträge, deshalb ist die Aufnahme standardmäßig aus.', 'wm-cra-sbom-beacon' ); ?></p>
				<label for="wm_cra_public_endpoints">
					<input type="checkbox" name="public_endpoints" id="wm_cra_public_endpoints" value="1" <?php checked( RestController::is_public_enabled() ); ?> />
					<?php esc_html_e( 'REST-Endpunkte (/sbom, /spdx, /vex, /csaf) ohne Anmeldung öffentlich freigeben', 'wm-cra-sbom-beacon' ); ?>
				</label>
				<p class="wm-field-desc"><?php esc_html_e( 'Standardmäßig sind die Endpunkte geschützt (Administrator-Sitzung oder Authorization: Bearer <Token>). Bei öffentlicher Freigabe greifen 1 Stunde Transient-Cache und ein Ratenlimit von 60 Anfragen pro Minute.', 'wm-cra-sbom-beacon' ); ?></p>
				<button type="submit" class="button"><?php esc_html_e( 'Übernehmen', 'wm-cra-sbom-beacon' ); ?></button>
			</form>
			<div class="wm-inline-form">
				<form method="post">
					<?php wp_nonce_field( 'wm_cra_admin_action', 'wm_cra_nonce' ); ?>
					<input type="hidden" name="wm_cra_action" value="rotate_api_token" />
					<button type="submit" class="button"><?php echo RestController::has_api_token() ? esc_html__( 'Bearer-Token neu erzeugen', 'wm-cra-sbom-beacon' ) : esc_html__( 'Bearer-Token erzeugen', 'wm-cra-sbom-beacon' ); ?></button>
				</form>
				<?php if ( RestController::has_api_token() ) : ?>
					<form method="post">
						<?php wp_nonce_field( 'wm_cra_admin_action', 'wm_cra_nonce' ); ?>
						<input type="hidden" name="wm_cra_action" value="revoke_api_token" />
						<button type="submit" class="button"><?php esc_html_e( 'Bearer-Token widerrufen', 'wm-cra-sbom-beacon' ); ?></button>
					</form>
				<?php endif; ?>
			</div>
			<div class="wm-table-container">
				<table class="wm-table">
					<thead>
						<tr>
							<th scope="col"><?php esc_html_e( 'Komponente', 'wm-cra-sbom-beacon' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Typ', 'wm-cra-sbom-beacon' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Version', 'wm-cra-sbom-beacon' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Paket-URL (purl)', 'wm-cra-sbom-beacon' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Lizenz laut Dateikopf', 'wm-cra-sbom-beacon' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $sbom['components'] as $comp ) : ?>
							<?php $license = self::license_text( $comp ); ?>
							<tr>
								<td><strong><?php echo esc_html( (string) $comp['name'] ); ?></strong></td>
								<td><?php echo esc_html( (string) $comp['type'] ); ?></td>
								<td><?php echo esc_html( (string) ( $comp['version'] ?? $unknown ) ); ?></td>
								<td><code><?php echo esc_html( (string) $comp['purl'] ); ?></code></td>
								<td><?php echo esc_html( '' !== $license ? $license : $unknown ); ?></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>
		</div>

		<div class="wm-card">
			<h2><?php esc_html_e( 'Gespeicherte Momentaufnahmen (neueste 10)', 'wm-cra-sbom-beacon' ); ?></h2>
			<?php if ( [] === $snapshots ) : ?>
				<p class="wm-empty-state"><?php esc_html_e( 'Noch keine Momentaufnahme gespeichert.', 'wm-cra-sbom-beacon' ); ?></p>
			<?php else : ?>
				<div class="wm-table-container">
					<table class="wm-table">
						<thead>
							<tr>
								<th scope="col"><?php esc_html_e( 'Gespeichert (UTC)', 'wm-cra-sbom-beacon' ); ?></th>
								<th scope="col"><?php esc_html_e( 'Komponenten', 'wm-cra-sbom-beacon' ); ?></th>
								<th scope="col"><?php esc_html_e( 'SHA-256 des JSON', 'wm-cra-sbom-beacon' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ( $snapshots as $row ) : ?>
								<tr>
									<td><?php echo esc_html( $row['created_at'] ); ?></td>
									<td><?php echo esc_html( (string) $row['components_count'] ); ?></td>
									<td><code><?php echo esc_html( substr( $row['sbom_sha256'], 0, 16 ) ); ?>…</code></td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
				</div>
			<?php endif; ?>
		</div>
		<?php
	}

	private function render_settings( array $status ): void {
		$f            = $this->security_txt->get_fields();
		$contact      = (string) preg_replace( '/^mailto:/i', '', $f['contact'] );
		$expires_date = self::date_part( $f['expires'] );
		$max_date     = gmdate( 'Y-m-d', time() + YEAR_IN_SECONDS );
		?>
		<div class="wm-card">
			<h2><?php esc_html_e( 'Angaben für /.well-known/security.txt', 'wm-cra-sbom-beacon' ); ?></h2>
			<form method="post">
				<?php wp_nonce_field( 'wm_cra_admin_action', 'wm_cra_nonce' ); ?>
				<input type="hidden" name="wm_cra_action" value="save_settings" />

				<div class="wm-field-card">
					<label class="wm-field-title" for="wm-cra-contact"><?php esc_html_e( 'Kontakt (Pflichtfeld)', 'wm-cra-sbom-beacon' ); ?></label>
					<p class="wm-field-desc"><?php esc_html_e( 'E-Mail-Adresse (wird als mailto: ausgeliefert) oder eine https-Adresse eines Kontaktformulars.', 'wm-cra-sbom-beacon' ); ?></p>
					<input type="text" id="wm-cra-contact" name="contact" value="<?php echo esc_attr( $contact ); ?>" class="wm-input" required />
				</div>

				<div class="wm-field-card">
					<label class="wm-field-title" for="wm-cra-expires"><?php esc_html_e( 'Ablaufdatum (Pflichtfeld)', 'wm-cra-sbom-beacon' ); ?></label>
					<p class="wm-field-desc"><?php esc_html_e( 'Nach diesem Tag gilt die Datei als veraltet. RFC 9116 empfiehlt weniger als ein Jahr; weiter in der Zukunft liegende Daten werden abgelehnt.', 'wm-cra-sbom-beacon' ); ?></p>
					<input type="date" id="wm-cra-expires" name="expires" value="<?php echo esc_attr( $expires_date ); ?>" max="<?php echo esc_attr( $max_date ); ?>" class="wm-input" required />
				</div>

				<div class="wm-field-card">
					<label class="wm-field-title" for="wm-cra-languages"><?php esc_html_e( 'Bevorzugte Sprachen', 'wm-cra-sbom-beacon' ); ?></label>
					<p class="wm-field-desc"><?php esc_html_e( 'Sprachkürzel, durch Komma getrennt, z. B. de, en.', 'wm-cra-sbom-beacon' ); ?></p>
					<input type="text" id="wm-cra-languages" name="languages" value="<?php echo esc_attr( $f['languages'] ); ?>" class="wm-input" />
				</div>

				<div class="wm-field-card">
					<label class="wm-field-title" for="wm-cra-policy"><?php esc_html_e( 'Richtlinie für Meldungen', 'wm-cra-sbom-beacon' ); ?></label>
					<p class="wm-field-desc"><?php esc_html_e( 'https-Adresse einer Seite, die beschreibt, wie Meldungen behandelt werden. Leer lassen, wenn es keine gibt.', 'wm-cra-sbom-beacon' ); ?></p>
					<input type="url" id="wm-cra-policy" name="policy" value="<?php echo esc_attr( $f['policy'] ); ?>" class="wm-input" />
				</div>

				<div class="wm-field-card">
					<label class="wm-field-title" for="wm-cra-encryption"><?php esc_html_e( 'Öffentlicher Schlüssel', 'wm-cra-sbom-beacon' ); ?></label>
					<p class="wm-field-desc"><?php esc_html_e( 'https-Adresse eines OpenPGP-Schlüssels für verschlüsselte Meldungen. Leer lassen, wenn es keinen gibt.', 'wm-cra-sbom-beacon' ); ?></p>
					<input type="url" id="wm-cra-encryption" name="encryption" value="<?php echo esc_attr( $f['encryption'] ); ?>" class="wm-input" />
				</div>

				<p><button type="submit" class="button button-primary"><?php esc_html_e( 'security.txt speichern', 'wm-cra-sbom-beacon' ); ?></button></p>
			</form>
		</div>

		<div class="wm-card">
			<h2><?php esc_html_e( 'Datenaufbewahrung bei Deinstallation', 'wm-cra-sbom-beacon' ); ?></h2>
			<form method="post">
				<?php wp_nonce_field( 'wm_cra_admin_action', 'wm_cra_nonce' ); ?>
				<input type="hidden" name="wm_cra_action" value="save_uninstall_options" />
				<p>
					<label for="wm_cra_beacon_delete_data_on_uninstall">
						<input type="checkbox" name="delete_data_on_uninstall" id="wm_cra_beacon_delete_data_on_uninstall" value="1" <?php checked( (bool) get_option( 'wm_cra_beacon_delete_data_on_uninstall', 0 ) ); ?> />
						<?php esc_html_e( 'Bei der Deinstallation des Plugins alle Optionen sowie gespeicherte SBOM-Momentaufnahmen, CSAF-Sicherheitshinweise, Schwachstellen-Befunde und VEX-Stellungnahmen endgültig löschen', 'wm-cra-sbom-beacon' ); ?>
					</label>
				</p>
				<p class="wm-field-desc"><?php esc_html_e( 'Standardmäßig bleiben Optionen, Nachweis-Tabellen und VEX-Stellungnahmen bei einer Plugin-Deinstallation erhalten.', 'wm-cra-sbom-beacon' ); ?></p>
				<p><button type="submit" class="button"><?php esc_html_e( 'Einstellung speichern', 'wm-cra-sbom-beacon' ); ?></button></p>
			</form>
		</div>
		<?php
	}

	private function render_glossary(): void {
		$terms = [
			__( 'Cyber Resilience Act (CRA)', 'wm-cra-sbom-beacon' ) => __( 'Verordnung (EU) 2024/2847 über horizontale Cybersicherheitsanforderungen für Produkte mit digitalen Elementen. Sie gilt ab dem 11. Dezember 2027, die Meldepflichten nach Artikel 14 ab dem 11. September 2026 (Artikel 71). Dieses Plugin prüft nicht, ob sie für eine Website gilt.', 'wm-cra-sbom-beacon' ),
			__( 'SBOM (Software Bill of Materials)', 'wm-cra-sbom-beacon' ) => __( 'Eine formale Aufzeichnung der Komponenten einer Software und ihrer Beziehungen in der Lieferkette (Artikel 3 Nummer 39 CRA). Hersteller müssen sie laut Anhang I Teil II mindestens für die Abhängigkeiten der obersten Ebene erstellen; veröffentlichen müssen sie sie nicht.', 'wm-cra-sbom-beacon' ),
			__( 'CycloneDX', 'wm-cra-sbom-beacon' ) => __( 'Maschinenlesbares Format für Software-Stücklisten. Die Technische Richtlinie BSI TR-03183-2 beschreibt die Abbildung ihrer Datenfelder auf CycloneDX und SPDX; sie ist nach Angabe des BSI nicht verbindlich.', 'wm-cra-sbom-beacon' ),
			__( 'security.txt (RFC 9116)', 'wm-cra-sbom-beacon' ) => __( 'Textdatei unter /.well-known/security.txt mit Kontakt und Ablaufdatum, damit Sicherheitsmeldungen die richtige Stelle erreichen.', 'wm-cra-sbom-beacon' ),
			__( 'CSAF 2.0', 'wm-cra-sbom-beacon' ) => __( 'Common Security Advisory Framework (OASIS): maschinenlesbares Format für Sicherheitshinweise. Dieses Plugin speichert Hinweise als Dokumente des Basisprofils und veröffentlicht keine provider-metadata.json.', 'wm-cra-sbom-beacon' ),
		];
		?>
		<div class="wm-card">
			<h2><?php esc_html_e( 'Begriffe', 'wm-cra-sbom-beacon' ); ?></h2>
			<div class="wm-glossary-grid">
				<?php foreach ( $terms as $term => $definition ) : ?>
					<div class="wm-glossary-card">
						<div class="wm-glossary-term"><?php echo esc_html( $term ); ?></div>
						<p class="wm-glossary-def"><?php echo esc_html( $definition ); ?></p>
					</div>
				<?php endforeach; ?>
			</div>
		</div>
		<?php
	}
}
