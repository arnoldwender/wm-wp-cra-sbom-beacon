<?php
/**
 * Runtime check inside a real WordPress: security.txt route and state, REST outputs, admin screen, settings save,
 * hub adapter.
 *
 *   wp eval-file tests/wp-runtime-cra.php --user=1
 *
 * It posts the settings form once with the values already stored and puts every option back as it found it
 * (including absent ones and the confirmation stamp). Nothing else is written. Exit 1 (WP_CLI::error) on failure.
 *
 * `wp eval-file` runs the file inside a method: state lives in $GLOBALS, and there is no declare() because a
 * declare after the docblock is fatal there.
 *
 * @package WMCyber\CRA
 */

defined( 'ABSPATH' ) || exit; // the local install serves the plugin folder over HTTP; this file is for wp eval-file only.

use WMCyber\CRA\Adapters\Cra_Spoke_Adapter;
use WMCyber\CRA\Admin\AdminDashboard;
use WMCyber\CRA\Beacon\SecurityTxtHandler;
use WMCyber\CRA\Core\Plugin;

$GLOBALS['wm_cra_rt'] = [ 'pass' => 0, 'fail' => 0 ];

function wm_cra_rt_check( string $name, bool $ok, string $details = '' ): void {
	$GLOBALS['wm_cra_rt'][ $ok ? 'pass' : 'fail' ]++;
	WP_CLI::log( ( $ok ? '[PASS] ' : '[FAIL] ' ) . $name . ( $ok || '' === $details ? '' : ': ' . $details ) );
}

function wm_cra_rt_render( callable $fn ): string {
	ob_start();
	$fn();
	return (string) ob_get_clean();
}

if ( ! class_exists( Plugin::class ) ) {
	WP_CLI::error( 'wm-cra-sbom-beacon is not loaded.' );
}
if ( ! current_user_can( 'manage_options' ) ) {
	WP_CLI::error( 'Run with --user=<an administrator>.' );
}

$plugin  = Plugin::instance();
$handler = $plugin->get_security_txt();

// -----------------------------------------------------------------------------------------------------------------
// security.txt
// -----------------------------------------------------------------------------------------------------------------
$status = $handler->status();
WP_CLI::log( 'security.txt status ' . wp_json_encode( $status ) );
wm_cra_rt_check( 'the /.well-known/security.txt rule is in the stored rewrite rules', '' === (string) get_option( 'permalink_structure' ) || $handler->route_stored() );
$content = $handler->generate_security_txt_content();
wm_cra_rt_check( 'served content has Contact and Expires and no CSAF:/SBOM: field', 1 === preg_match( '/^Contact: \S+/m', $content ) && 1 === preg_match( '/^Expires: \S+/m', $content ) && 0 === preg_match( '/^(CSAF|SBOM):/m', $content ), $content );

// -----------------------------------------------------------------------------------------------------------------
// REST
// -----------------------------------------------------------------------------------------------------------------
$sbom_res = rest_do_request( new WP_REST_Request( 'GET', '/wm-cra/v1/sbom' ) );
$sbom     = (array) $sbom_res->get_data();
$bad_lic  = [];
foreach ( (array) ( $sbom['components'] ?? [] ) as $c ) {
	foreach ( (array) ( $c['licenses'] ?? [] ) as $l ) {
		if ( isset( $l['license']['id'], $l['license']['name'] ) || 'Proprietary' === ( $l['license']['id'] ?? '' ) ) {
			$bad_lic[] = $c['name'];
		}
	}
	if ( str_ends_with( (string) ( $c['purl'] ?? '' ), '@' ) ) {
		$bad_lic[] = $c['name'] . ' (purl ends in @)';
	}
}
$active = count( (array) get_option( 'active_plugins', [] ) );
WP_CLI::log( sprintf( 'SBOM: %d components for %d active plugins', count( (array) ( $sbom['components'] ?? [] ) ), $active ) );
wm_cra_rt_check( 'REST SBOM: 200, CycloneDX 1.6, no hashes, no invented licence or empty version', 200 === $sbom_res->get_status() && 'CycloneDX' === ( $sbom['bomFormat'] ?? '' ) && ! str_contains( (string) wp_json_encode( $sbom ), '"hashes"' ) && [] === $bad_lic, implode( ', ', $bad_lic ) );
wm_cra_rt_check( 'REST SBOM lists every active plugin', count( (array) ( $sbom['components'] ?? [] ) ) >= $active + 2 );

$csaf_res = rest_do_request( new WP_REST_Request( 'GET', '/wm-cra/v1/csaf' ) );
$csaf     = (string) wp_json_encode( $csaf_res->get_data() );
wm_cra_rt_check( 'REST advisory index: 200, no issuing authority, marked as not a provider feed', 200 === $csaf_res->get_status() && ! str_contains( $csaf, 'issuing_authority' ) && str_contains( $csaf, 'Not a CSAF provider-metadata.json' ) );

// -----------------------------------------------------------------------------------------------------------------
// Admin screen
// -----------------------------------------------------------------------------------------------------------------
$dash = new AdminDashboard( $plugin->get_sbom_generator(), $handler, $plugin->get_csaf_publisher() );
$_GET = [ 'page' => 'wm-cra-beacon', 'tab' => 'overview' ];
$page = wm_cra_rt_render( static fn() => $dash->render_dashboard_page() );
$_GET = [];
wm_cra_rt_check( 'admin overview shows the served file and no fixed badges', str_contains( $page, esc_html( $content ) ) && ! preg_match( '/CIBERRESILIENCIA|RFC 9116 verificado|2027-08-27T00:00:00Z/u', $page ) );
$widget = wm_cra_rt_render( static fn() => $dash->render_dashboard_widget() );
wm_cra_rt_check( 'widget without signature claim or fixed count', ! str_contains( $widget, 'Signatur' ) && ! preg_match( '/>\s*18\s*</', $widget ) );

// -----------------------------------------------------------------------------------------------------------------
// Settings save with the stored values, then restore
// -----------------------------------------------------------------------------------------------------------------
$names  = [ SecurityTxtHandler::OPT_CONTACT, SecurityTxtHandler::OPT_EXPIRES, SecurityTxtHandler::OPT_LANGUAGES, SecurityTxtHandler::OPT_POLICY, SecurityTxtHandler::OPT_ENCRYPTION, SecurityTxtHandler::OPT_CONFIRMED, 'wm_cra_settings' ];
$before = [];
foreach ( $names as $n ) {
	$before[ $n ] = get_option( $n, null );
}
$f      = $handler->get_fields();
$errors = $dash->save_settings( [
	'contact'    => preg_replace( '/^mailto:/i', '', $f['contact'] ),
	'expires'    => substr( $f['expires'], 0, 10 ),
	'languages'  => $f['languages'],
	'policy'     => $f['policy'],
	'encryption' => $f['encryption'],
] );
$served_after = $handler->generate_security_txt_content();
$contact_ok   = str_contains( $served_after, 'Contact: ' . $f['contact'] );
// The fields the stored values should be refused for, computed independently of save_settings().
$expected = [];
if ( null === SecurityTxtHandler::sanitize_contact( $f['contact'] ) ) {
	$expected[] = 'contact';
}
if ( null === SecurityTxtHandler::sanitize_expires( substr( $f['expires'], 0, 10 ) ) ) {
	$expected[] = 'expires';
}
if ( null === SecurityTxtHandler::sanitize_languages( $f['languages'] ) ) {
	$expected[] = 'languages';
}
if ( null === SecurityTxtHandler::sanitize_https_url( $f['policy'] ) ) {
	$expected[] = 'policy';
}
if ( null === SecurityTxtHandler::sanitize_https_url( $f['encryption'] ) ) {
	$expected[] = 'encryption';
}
$contact_before = get_option( SecurityTxtHandler::OPT_CONTACT );
$bad            = $dash->save_settings( [ 'contact' => 'not-an-email', 'expires' => gmdate( 'Y-m-d', time() + 30 * DAY_IN_SECONDS ) ] );
$unchanged      = get_option( SecurityTxtHandler::OPT_CONTACT ) === $contact_before;

foreach ( $before as $n => $v ) {
	if ( null === $v ) {
		delete_option( $n );
	} else {
		update_option( $n, $v );
	}
}
$restored = true;
foreach ( $before as $n => $v ) {
	$restored = $restored && get_option( $n, null ) === $v;
}
WP_CLI::log( 'save with stored values: errors ' . wp_json_encode( $errors ) . ', expected ' . wp_json_encode( $expected ) );
wm_cra_rt_check( 'saving the stored values refuses exactly the invalid ones, or keeps the served contact', $expected === $errors && ( [] !== $errors || $contact_ok ), wp_json_encode( $errors ) );
wm_cra_rt_check( 'an invalid contact is refused and nothing is written', [ 'contact' ] === $bad && $unchanged, wp_json_encode( $bad ) );
wm_cra_rt_check( 'options after the check equal the options before', $restored );

// -----------------------------------------------------------------------------------------------------------------
// Hub adapter
// -----------------------------------------------------------------------------------------------------------------
if ( ! class_exists( Cra_Spoke_Adapter::class ) ) {
	WP_CLI::log( '[SKIP] hub adapter: WM Suite Hub interface not loaded' );
} else {
	$adapter = new Cra_Spoke_Adapter();
	$health  = $adapter->get_health_status();
	$self    = $adapter->execute_action( 'self_test' );
	$status  = $handler->status();
	$expect  = ( 'ok' === $status['state'] && ! $status['confirmed'] ) ? 'NEEDS_CONFIG' : ( [ 'ok' => 'HEALTHY', 'expiring' => 'DEGRADED', 'not_configured' => 'NEEDS_CONFIG' ][ $status['state'] ] ?? 'ERROR' );
	WP_CLI::log( 'hub health ' . $health . ' | self_test ' . wp_json_encode( $self ) );
	wm_cra_rt_check( 'hub health follows the security.txt state', $expect === $health, $health . ' expected ' . $expect );
	wm_cra_rt_check( 'hub self test succeeds only when healthy', ( 'HEALTHY' === $health ) === $self['success'] );
	parse_str( (string) wp_parse_url( (string) $adapter->get_settings_url(), PHP_URL_QUERY ), $q );
	wm_cra_rt_check( 'hub settings link names the registered page', 'wm-cra-beacon' === ( $q['page'] ?? '' ) );
}

WP_CLI::log( sprintf( '=== RUNTIME: %d passed, %d failed ===', $GLOBALS['wm_cra_rt']['pass'], $GLOBALS['wm_cra_rt']['fail'] ) );
if ( $GLOBALS['wm_cra_rt']['fail'] > 0 ) {
	WP_CLI::error( 'runtime check failed' );
}
