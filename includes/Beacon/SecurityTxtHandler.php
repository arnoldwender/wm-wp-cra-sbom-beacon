<?php
declare(strict_types=1);

namespace WMCyber\CRA\Beacon;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Serves /.well-known/security.txt (RFC 9116) from five options and reports whether the file is usable.
 *
 * RFC 9116 (checked 2026-09-15, rfc-editor.org): Contact and Expires are required; Contact is a URI (mailto: for
 * e-mail); Expires is an RFC 3339 date and SHOULD be less than a year ahead; Policy, Canonical and Encryption are
 * https URIs; researchers must ignore fields they do not support.
 */
final class SecurityTxtHandler {
	public const OPT_CONTACT    = 'wm_cra_security_txt_contact';
	public const OPT_EXPIRES    = 'wm_cra_security_txt_expires';
	public const OPT_LANGUAGES  = 'wm_cra_security_txt_languages';
	public const OPT_POLICY     = 'wm_cra_security_txt_policy';
	public const OPT_ENCRYPTION = 'wm_cra_security_txt_encryption';
	// Set when an administrator saved the form. The activation default is a guessed address that may not exist.
	public const OPT_CONFIRMED  = 'wm_cra_security_txt_confirmed';

	// Days before Expires from which the admin screen and the hub report the file as expiring.
	public const EXPIRING_DAYS = 30;

	private const RULE_REGEX = '^\\.well-known/security\\.txt$';

	public function init(): void {
		add_action( 'init', [ $this, 'add_rewrite_rules' ] );
		add_action( 'wp_loaded', [ $this, 'ensure_rules_stored' ] );
		add_filter( 'query_vars', [ $this, 'register_query_vars' ] );
		// Priority 0: redirect_canonical() runs on template_redirect at 10 and answered /.well-known/security.txt with a
		// 301 to /.well-known/security.txt/ before the file was printed (measured on a local WordPress install, WordPress 7.1).
		add_action( 'template_redirect', [ $this, 'render_security_txt' ], 0 );
	}

	/**
	 * Sites activated before 2026-09-15 stored their rewrite rules without this route (see Schema::activate_site).
	 * One soft flush once the rule is registered repairs them; afterwards the check is a key lookup.
	 */
	public function ensure_rules_stored(): void {
		if ( '' === (string) get_option( 'permalink_structure', '' ) ) {
			return; // Plain permalinks: WordPress stores no rules, a flush would change nothing.
		}
		if ( ! $this->route_stored() ) {
			flush_rewrite_rules( false );
		}
	}

	/** Whether the stored rewrite rules contain the /.well-known/security.txt route. */
	public function route_stored(): bool {
		$rules = get_option( 'rewrite_rules' );
		return is_array( $rules ) && isset( $rules[ self::RULE_REGEX ] );
	}

	public function add_rewrite_rules(): void {
		add_rewrite_rule( self::RULE_REGEX, 'index.php?wm_cra_security_txt=1', 'top' );
		add_rewrite_rule( '^security\.txt$', 'index.php?wm_cra_security_txt=1', 'top' );
	}

	public function register_query_vars( array $vars ): array {
		$vars[] = 'wm_cra_security_txt';
		return $vars;
	}

	public function render_security_txt(): void {
		if ( (int) get_query_var( 'wm_cra_security_txt' ) !== 1 ) {
			return;
		}

		if ( ! headers_sent() ) {
			header( 'Content-Type: text/plain; charset=utf-8' );
			header( 'X-Content-Type-Options: nosniff' );
		}

		$txt = $this->generate_security_txt_content();
		// text/plain with nosniff: esc_html() would entity-encode the colons and angle brackets
		// that RFC 9116 requires, producing an invalid file. The values are validated when they
		// are saved (sanitize_* below) and filtered again in generate_security_txt_content().
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo (string) apply_filters( 'wm_cra_security_txt_output', $txt );
		if ( ! defined( 'WM_CRA_TESTING' ) ) {
			exit;
		}
	}

	public static function default_contact(): string {
		return 'mailto:security@' . ( wp_parse_url( home_url(), PHP_URL_HOST ) ?: 'localhost' );
	}

	/**
	 * The stored field values. No invented values: a missing Expires stays empty and makes the file invalid.
	 *
	 * @return array{contact: string, expires: string, languages: string, policy: string, encryption: string}
	 */
	public function get_fields(): array {
		return [
			'contact'    => sanitize_text_field( (string) get_option( self::OPT_CONTACT, '' ) ),
			'expires'    => sanitize_text_field( (string) get_option( self::OPT_EXPIRES, '' ) ),
			'languages'  => sanitize_text_field( (string) get_option( self::OPT_LANGUAGES, '' ) ),
			'policy'     => sanitize_text_field( (string) get_option( self::OPT_POLICY, '' ) ),
			'encryption' => sanitize_text_field( (string) get_option( self::OPT_ENCRYPTION, '' ) ),
		];
	}

	public function generate_security_txt_content(): string {
		$f = $this->get_fields();

		$lines   = [];
		$lines[] = '# security.txt (RFC 9116)';
		if ( '' !== $f['contact'] ) {
			$lines[] = 'Contact: ' . $f['contact'];
		}
		if ( '' !== $f['expires'] ) {
			$lines[] = 'Expires: ' . $f['expires'];
		}
		if ( '' !== $f['encryption'] ) {
			$lines[] = 'Encryption: ' . $f['encryption'];
		}
		if ( '' !== $f['languages'] ) {
			$lines[] = 'Preferred-Languages: ' . $f['languages'];
		}
		$lines[] = 'Canonical: ' . home_url( '/.well-known/security.txt' );
		if ( '' !== $f['policy'] ) {
			$lines[] = 'Policy: ' . $f['policy'];
		}

		// Comments, not fields: "SBOM" is not a registered security.txt field, and the CSAF field must point to a
		// provider-metadata.json (CSAF 2.0, requirement 8), which this plugin does not publish. Until 2026-09-15 a
		// "CSAF:" line pointed to the plugin's own advisory index.
		$lines[] = '# Software inventory (CycloneDX 1.6 JSON): ' . esc_url_raw( rest_url( 'wm-cra/v1/sbom' ) );
		$lines[] = '# Advisory index of this site (JSON): ' . esc_url_raw( rest_url( 'wm-cra/v1/csaf' ) );

		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * State of the served file, for the admin screen, the widget and the hub.
	 *
	 * @param int|null $now Unix time; null means time().
	 * @return array{state: string, expires: string, days_left: int|null, confirmed: bool, route: bool}
	 *   state: not_configured (no Contact), invalid (Contact not an e-mail or https URL, or Expires missing or
	 *   unreadable), no_route (plain permalinks or rule not stored), expired, expiring, ok.
	 */
	public function status( ?int $now = null ): array {
		$now       = $now ?? time();
		$f         = $this->get_fields();
		$confirmed = '' !== (string) get_option( self::OPT_CONFIRMED, '' );
		$route     = $this->route_stored();
		$result    = [ 'state' => 'ok', 'expires' => $f['expires'], 'days_left' => null, 'confirmed' => $confirmed, 'route' => $route ];

		if ( '' === $f['contact'] ) {
			$result['state'] = 'not_configured';
			return $result;
		}
		// The activation default security@<host> is not a deliverable address on a host without a dot (localhost).
		if ( null === self::sanitize_contact( $f['contact'] ) ) {
			$result['state'] = 'invalid';
			return $result;
		}
		if ( ! $route ) {
			$result['state'] = 'no_route';
			return $result;
		}

		$ts = self::parse_rfc3339( $f['expires'] );
		if ( null === $ts ) {
			$result['state'] = 'invalid';
			return $result;
		}

		$result['days_left'] = (int) floor( ( $ts - $now ) / DAY_IN_SECONDS );
		if ( $ts <= $now ) {
			$result['state'] = 'expired';
		} elseif ( $ts - $now <= self::EXPIRING_DAYS * DAY_IN_SECONDS ) {
			$result['state'] = 'expiring';
		}
		return $result;
	}

	public static function parse_rfc3339( string $value ): ?int {
		if ( ! preg_match( '/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/', $value ) ) {
			return null;
		}
		$ts = strtotime( $value );
		return false === $ts ? null : $ts;
	}

	// ---------------------------------------------------------------------------------------------------------
	// Validation for the settings form. Each returns null for input that must be refused.
	// ---------------------------------------------------------------------------------------------------------

	/** An e-mail address becomes a mailto: URI; an https URL (a contact form) is kept. */
	public static function sanitize_contact( string $value ): ?string {
		$value = trim( $value );
		if ( str_starts_with( strtolower( $value ), 'mailto:' ) ) {
			$value = substr( $value, 7 );
		}
		if ( '' === $value ) {
			return null; // Contact is required.
		}
		if ( is_email( $value ) ) {
			return 'mailto:' . $value;
		}
		return self::sanitize_https_url( $value );
	}

	/** A Y-m-d date from the form, end of that day UTC, in the future and at most one year ahead (RFC 9116 2.5.5). */
	public static function sanitize_expires( string $value, ?int $now = null ): ?string {
		$now = $now ?? time();
		if ( ! preg_match( '/^(\d{4})-(\d{2})-(\d{2})$/', trim( $value ), $m ) || ! checkdate( (int) $m[2], (int) $m[3], (int) $m[1] ) ) {
			return null;
		}
		$ts = gmmktime( 23, 59, 59, (int) $m[2], (int) $m[3], (int) $m[1] );
		if ( $ts <= $now || $ts > $now + YEAR_IN_SECONDS ) {
			return null;
		}
		return gmdate( 'Y-m-d\TH:i:s\Z', $ts );
	}

	/** Comma-separated language tags such as "de, en" (RFC 9116 2.5.8, tags per RFC 5646). Empty is allowed. */
	public static function sanitize_languages( string $value ): ?string {
		$parts = array_values( array_filter( array_map( 'trim', explode( ',', $value ) ), 'strlen' ) );
		foreach ( $parts as $tag ) {
			if ( ! preg_match( '/^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$/', $tag ) ) {
				return null;
			}
		}
		return implode( ', ', $parts );
	}

	/**
	 * An https URL, or empty (the field is optional). The scheme and host are checked on the input itself:
	 * esc_url_raw( 'not-an-email', [ 'https' ] ) returns "https://not-an-email" (measured on WordPress 7.1), so its
	 * output alone accepted any word. User info ("https://user@host") is refused.
	 */
	public static function sanitize_https_url( string $value ): ?string {
		$value = trim( $value );
		if ( '' === $value ) {
			return '';
		}
		$parts = wp_parse_url( $value );
		if ( ! is_array( $parts ) || 'https' !== strtolower( (string) ( $parts['scheme'] ?? '' ) ) || '' === (string) ( $parts['host'] ?? '' ) || isset( $parts['user'] ) || isset( $parts['pass'] ) ) {
			return null;
		}
		$url = esc_url_raw( $value, [ 'https' ] );
		return str_starts_with( $url, 'https://' ) ? $url : null;
	}
}
