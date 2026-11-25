<?php
declare(strict_types=1);

namespace WMCyber\CRA\Frontend;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WMCyber\CRA\Admin\AdminDashboard;
use WMCyber\CRA\CSAF\CsafPublisher;
use WMCyber\CRA\Beacon\SecurityTxtHandler;

/**
 * Shortcodes [wm_cra_psirt] / [wm_security_disclosure], Gutenberg block wm/cra-psirt,
 * WP 6.5+ Block Bindings source (wm-cra-beacon/status) and GenerateBlocks 2.x Dynamic Tag ({{wm_cra_beacon_status}}).
 *
 * Until 2026-09-15 the box called the site an "Offizielle Koordinierungsstelle für Schwachstellenmeldungen", carried
 * a "EU CRA & BSI TR-03183" badge, and with no advisories stated "Alle Systeme entsprechen dem aktuellen Patch-Stand"
 * without checking anything. The inline styles are still the original ones (README Known issues).
 */
final class PsirtPortal {
	public const EDITOR_SCRIPT_HANDLE  = 'wm-cra-beacon-blocks-editor';
	public const BLOCK_BINDING_SOURCE  = 'wm-cra-beacon/status';
	public const GB_DYNAMIC_TAG        = 'wm_cra_beacon_status';

	public function __construct(
		private readonly CsafPublisher $csaf_publisher,
		private readonly SecurityTxtHandler $security_txt
	) {}

	public function init(): void {
		add_shortcode( 'wm_cra_psirt', [ $this, 'render_portal' ] );
		add_shortcode( 'wm_security_disclosure', [ $this, 'render_portal' ] );
		add_action( 'init', [ $this, 'register_block' ] );
		add_action( 'init', [ $this, 'register_integrations' ] );
		add_filter( 'generateblocks_dynamic_tag_replacement', [ $this, 'filter_generateblocks_dynamic_tag' ], 10, 3 );
	}

	public function register_block(): void {
		$asset_file = WM_CRA_PATH . 'build/index.asset.php';
		$asset      = is_file( $asset_file )
			? require $asset_file
			: [
				'dependencies' => [ 'wp-block-editor', 'wp-blocks', 'wp-components', 'wp-element', 'wp-i18n', 'wp-server-side-render' ],
				'version'      => WM_CRA_VERSION,
			];

		if ( function_exists( 'wp_register_script' ) ) {
			wp_register_script(
				self::EDITOR_SCRIPT_HANDLE,
				WM_CRA_URL . 'build/index.js',
				$asset['dependencies'],
				(string) $asset['version'],
				true
			);
		}

		if ( function_exists( 'wp_set_script_translations' ) ) {
			wp_set_script_translations(
				self::EDITOR_SCRIPT_HANDLE,
				'wm-cra-sbom-beacon',
				WM_CRA_PATH . 'languages'
			);
		}

		if ( function_exists( 'register_block_type' ) ) {
			register_block_type(
				WM_CRA_PATH . 'blocks/cra-psirt',
				[
					'editor_script'   => self::EDITOR_SCRIPT_HANDLE,
					'render_callback' => [ $this, 'render_portal' ],
				]
			);
		}
	}

	/**
	 * Register WP 6.5+ Block Bindings source (`wm-cra-beacon/status`) and GenerateBlocks 2.x Dynamic Tag (`{{wm_cra_beacon_status}}`).
	 */
	public function register_integrations(): void {
		if ( function_exists( 'register_block_bindings_source' ) ) {
			register_block_bindings_source(
				'wm-cra-beacon/status',
				[
					'label'              => __( 'CRA Beacon Status', 'wm-cra-sbom-beacon' ),
					'get_value_callback' => [ $this, 'get_block_binding_value' ],
					'uses_context'       => [],
				]
			);
		}

		if ( class_exists( 'GenerateBlocks_Register_Dynamic_Tag' ) ) {
			new \GenerateBlocks_Register_Dynamic_Tag(
				[
					'title'       => __( 'CRA Beacon Status', 'wm-cra-sbom-beacon' ),
					'tag'         => self::GB_DYNAMIC_TAG,
					'type'        => 'site',
					'supports'    => [],
					'description' => __( 'Berechneter Status der ausgelieferten security.txt (RFC 9116).', 'wm-cra-sbom-beacon' ),
					'return'      => [ $this, 'render_dynamic_tag' ],
				]
			);
		}
	}

	/**
	 * Resolve a computed value for the WP 6.5+ Block Bindings source `wm-cra-beacon/status`.
	 *
	 * @param array<string, mixed> $source_args    Binding arguments (optional `key`: summary|state|expires|contact|advisories_count).
	 * @param mixed                $block_instance Block instance.
	 * @param string               $attribute_name Bound attribute name.
	 */
	public function get_block_binding_value( array $source_args = [], $block_instance = null, string $attribute_name = '' ): ?string {
		$key    = isset( $source_args['key'] ) ? sanitize_key( (string) $source_args['key'] ) : 'summary';
		$status = $this->security_txt->status();

		return match ( $key ) {
			'state'            => $status['state'],
			'expires'          => '' !== $status['expires'] ? substr( $status['expires'], 0, 10 ) : '',
			'contact'          => (string) preg_replace( '/^mailto:/i', '', $this->security_txt->get_fields()['contact'] ),
			'advisories_count' => (string) $this->csaf_publisher->count_advisories(),
			'summary', 'status', '' => AdminDashboard::state_label( $status ),
			default            => null,
		};
	}

	/**
	 * Callback for GenerateBlocks 2.x `{{wm_cra_beacon_status}}` dynamic tag.
	 *
	 * @param array<string, mixed> $options  Tag options (optional `key` or `field`).
	 * @param mixed                $block    Block data.
	 * @param mixed                $instance Dynamic tag instance.
	 */
	public function render_dynamic_tag( array $options = [], $block = [], $instance = null ): string {
		$field = isset( $options['key'] ) ? (string) $options['key'] : (string) ( $options['field'] ?? 'summary' );
		return (string) ( $this->get_block_binding_value( [ 'key' => $field ] ) ?? '' );
	}

	/**
	 * Filter GenerateBlocks dynamic tag replacements for `{{wm_cra_beacon_status}}`.
	 *
	 * @param mixed $replacement Current replacement value.
	 * @param mixed $tag_details Tag details array.
	 * @param mixed $block       Block context.
	 */
	public function filter_generateblocks_dynamic_tag( mixed $replacement, mixed $tag_details = [], mixed $block = null ): mixed {
		if ( ! is_array( $tag_details ) || ( $tag_details['tag'] ?? '' ) !== self::GB_DYNAMIC_TAG ) {
			return $replacement;
		}
		$options = isset( $tag_details['options'] ) && is_array( $tag_details['options'] ) ? $tag_details['options'] : [];
		return $this->render_dynamic_tag( $options, $block );
	}

	/**
	 * Render the public PSIRT disclosure box.
	 *
	 * @param mixed $atts Block or shortcode attributes.
	 */
	public function render_portal( $atts = [] ): string {
		$atts            = is_array( $atts ) ? $atts : [];
		$show_json_links = ! array_key_exists( 'showJsonLinks', $atts ) || (bool) $atts['showJsonLinks'];
		$show_advisories = ! array_key_exists( 'showAdvisories', $atts ) || (bool) $atts['showAdvisories'];

		$feed       = $this->csaf_publisher->get_feed();
		$advisories = $feed['advisories'] ?? [];
		// The contact the served security.txt uses, shown without the URI scheme.
		$contact = (string) preg_replace( '/^mailto:/i', '', $this->security_txt->get_fields()['contact'] );

		ob_start();
		?>
		<div class="wm-cra-psirt-portal" style="background:#090d16; color:#f1f5f9; border:1px solid rgba(255,255,255,0.08); border-radius:12px; padding:2.25rem; max-width:860px; margin:2rem auto; box-shadow:0 20px 40px rgba(0,0,0,0.5); font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;">
			<div style="margin-bottom: 2rem;">
				<div style="display:inline-block; background:rgba(0,242,254,0.12); color:#00f2fe; font-size:0.75rem; font-weight:700; text-transform:uppercase; letter-spacing:0.06em; padding:4px 10px; border-radius:4px; margin-bottom:0.75rem; border:1px solid rgba(0,242,254,0.25);">
					<?php esc_html_e( 'security.txt (RFC 9116)', 'wm-cra-sbom-beacon' ); ?>
				</div>
				<h2 style="font-size:1.6rem; font-weight:700; color:#ffffff; margin:0 0 0.5rem 0; letter-spacing:-0.02em;">
					<?php esc_html_e( 'Sicherheitshinweise und Meldung von Schwachstellen', 'wm-cra-sbom-beacon' ); ?>
				</h2>
				<p style="font-size:0.92rem; color:#94a3b8; margin:0; line-height:1.5;">
					<?php esc_html_e( 'Schwachstellen in dieser Website melden Sie an die unten genannte Adresse. Die Liste der eingesetzten Software und die veröffentlichten Sicherheitshinweise stehen als JSON bereit.', 'wm-cra-sbom-beacon' ); ?>
				</p>
			</div>

			<div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1rem; margin-bottom: 2rem;">
				<div style="background:#0b0f19; padding:1.25rem; border-radius:8px; border:1px solid rgba(255,255,255,0.08);">
					<div style="font-size:0.8rem; color:#94a3b8; text-transform:uppercase; margin-bottom:0.4rem;"><?php esc_html_e( 'Kontakt für Sicherheitsmeldungen', 'wm-cra-sbom-beacon' ); ?></div>
					<div style="font-weight:600; color:#00f2fe; word-break:break-all; font-size:0.95rem;">
						<?php echo '' !== $contact ? esc_html( $contact ) : esc_html__( 'Nicht hinterlegt', 'wm-cra-sbom-beacon' ); ?>
					</div>
				</div>
				<?php if ( $show_json_links ) : ?>
				<div style="background:#0b0f19; padding:1.25rem; border-radius:8px; border:1px solid rgba(255,255,255,0.08);">
					<div style="font-size:0.8rem; color:#94a3b8; text-transform:uppercase; margin-bottom:0.4rem;"><?php esc_html_e( 'Software-Liste (CycloneDX 1.6)', 'wm-cra-sbom-beacon' ); ?></div>
					<a href="<?php echo esc_url( rest_url( 'wm-cra/v1/sbom' ) ); ?>" style="color:#38bdf8; text-decoration:none; font-weight:600; font-size:0.95rem;">/wp-json/wm-cra/v1/sbom</a>
				</div>
				<div style="background:#0b0f19; padding:1.25rem; border-radius:8px; border:1px solid rgba(255,255,255,0.08);">
					<div style="font-size:0.8rem; color:#94a3b8; text-transform:uppercase; margin-bottom:0.4rem;"><?php esc_html_e( 'Sicherheitshinweise (JSON)', 'wm-cra-sbom-beacon' ); ?></div>
					<a href="<?php echo esc_url( rest_url( 'wm-cra/v1/csaf' ) ); ?>" style="color:#38bdf8; text-decoration:none; font-weight:600; font-size:0.95rem;">/wp-json/wm-cra/v1/csaf</a>
				</div>
				<?php endif; ?>
			</div>

			<?php if ( $show_advisories ) : ?>
			<h3 style="color:#ffffff; font-size:1.15rem; margin-bottom:1rem; border-bottom:1px solid rgba(255,255,255,0.08); padding-bottom:0.5rem;">
				<?php esc_html_e( 'Veröffentlichte Sicherheitshinweise', 'wm-cra-sbom-beacon' ); ?>
			</h3>

			<?php if ( empty( $advisories ) ) : ?>
				<div style="padding:1.5rem; background:#0b0f19; border-radius:8px; text-align:center; color:#94a3b8; font-size:0.9rem;">
					<?php esc_html_e( 'Derzeit sind keine Sicherheitshinweise veröffentlicht.', 'wm-cra-sbom-beacon' ); ?>
				</div>
			<?php else : ?>
				<div style="display:flex; flex-direction:column; gap:0.75rem;">
					<?php
					foreach ( $advisories as $adv ) :
						// Only what the document states: no placeholder CVE, id or score (until 2026-09-15 a missing
						// score was shown as "CVSS 0.0" and a missing CVE as "CVE-2026").
						$title    = (string) ( $adv['document']['title'] ?? '' );
						$track_id = (string) ( $adv['document']['tracking']['id'] ?? '' );
						$cve      = (string) ( $adv['vulnerabilities'][0]['cve'] ?? '' );
						$severity = (string) ( $adv['document']['aggregate_severity']['text'] ?? '' );
						$meta     = implode( ' · ', array_filter( [ $track_id, $cve ], 'strlen' ) );
						?>
					<div style="background:#0b0f19; border:1px solid rgba(255,255,255,0.08); padding:1rem 1.25rem; border-radius:8px; display:flex; justify-content:space-between; align-items:center;">
						<div>
							<div style="font-size:0.78rem; color:#94a3b8; margin-bottom:0.25rem; font-family:monospace;"><?php echo esc_html( $meta ); ?></div>
							<div style="color:#ffffff; font-weight:600; font-size:0.95rem;"><?php echo esc_html( $title ); ?></div>
						</div>
						<?php if ( '' !== $severity ) : ?>
						<div style="display:flex; gap:0.5rem; align-items:center;">
							<span style="background:rgba(245,158,11,0.15); color:#f59e0b; border:1px solid rgba(245,158,11,0.3); padding:4px 8px; border-radius:4px; font-weight:700; font-size:0.8rem;">
								<?php
								/* translators: %s: severity of the advisory as stated by the publisher (low, medium, high, critical) */
								$severity_text = __( 'Schweregrad: %s', 'wm-cra-sbom-beacon' );
								echo esc_html( sprintf( $severity_text, $severity ) );
								?>
							</span>
						</div>
						<?php endif; ?>
					</div>
					<?php endforeach; ?>
				</div>
			<?php endif; ?>
			<?php endif; ?>
		</div>
		<?php
		return (string) ob_get_clean();
	}
}
