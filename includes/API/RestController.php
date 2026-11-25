<?php
declare(strict_types=1);

namespace WMCyber\CRA\API;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WMCyber\CRA\Beacon\SecurityTxtHandler;
use WMCyber\CRA\CSAF\CsafPublisher;
use WMCyber\CRA\SBOM\CryptoInventory;
use WMCyber\CRA\SBOM\CycloneDxGenerator;
use WMCyber\CRA\SPDX\Spdx3Generator;
use WMCyber\CRA\Vuln\OpenVexEngine;
use WMCyber\CRA\Vuln\VulnerabilityAudit;
use WP_Error;
use WP_REST_Response;

final class RestController {
	private const REST_NAMESPACE = 'wm-cra/v1';

	public const OPT_PUBLIC_ENDPOINTS    = 'wm_cra_public_endpoints';
	public const OPT_API_TOKEN_HASH      = 'wm_cra_api_token_hash';
	public const OPT_CACHE_BUST          = 'wm_cra_cache_bust';
	public const OPT_DELETE_ON_UNINSTALL = 'wm_cra_beacon_delete_data_on_uninstall';

	public const CACHE_TTL      = 3600;
	public const RATE_LIMIT_MAX = 60;

	public function __construct(
		private readonly CycloneDxGenerator $sbom_generator,
		private readonly SecurityTxtHandler $security_txt,
		private readonly CsafPublisher $csaf_publisher
	) {}

	public function register_routes(): void {
		add_action( 'activated_plugin', [ self::class, 'flush_caches' ] );
		add_action( 'deactivated_plugin', [ self::class, 'flush_caches' ] );
		add_action( 'switch_theme', [ self::class, 'flush_caches' ] );
		add_action( 'upgrader_process_complete', [ self::class, 'flush_caches' ] );

		add_action( 'rest_api_init', function (): void {
			// Protected by default (manage_options or Bearer token); opt-in public access adds rate-limiting and 1h transient caching.
			register_rest_route( self::REST_NAMESPACE, '/sbom', [
				'methods'             => 'GET',
				'callback'            => [ $this, 'get_sbom' ],
				'permission_callback' => [ $this, 'check_read_permission' ],
			] );

			register_rest_route( self::REST_NAMESPACE, '/spdx', [
				'methods'             => 'GET',
				'callback'            => [ $this, 'get_spdx' ],
				'permission_callback' => [ $this, 'check_read_permission' ],
			] );

			register_rest_route( self::REST_NAMESPACE, '/vex', [
				'methods'             => 'GET',
				'callback'            => [ $this, 'get_vex' ],
				'permission_callback' => [ $this, 'check_read_permission' ],
			] );

			register_rest_route( self::REST_NAMESPACE, '/csaf', [
				'methods'             => 'GET',
				'callback'            => [ $this, 'get_csaf' ],
				'permission_callback' => [ $this, 'check_read_permission' ],
			] );
		} );
	}

	public static function is_public_enabled(): bool {
		return (bool) get_option( self::OPT_PUBLIC_ENDPOINTS, 0 );
	}

	public static function has_api_token(): bool {
		if ( defined( 'WM_CRA_API_TOKEN' ) && '' !== trim( (string) WM_CRA_API_TOKEN ) ) {
			return true;
		}
		$hash = (string) get_option( self::OPT_API_TOKEN_HASH, '' );
		return 1 === preg_match( '/^[a-f0-9]{64}$/', $hash );
	}

	/**
	 * Mint a random 256-bit Bearer token, store only its SHA-256 digest in wp_options, and return the raw token once.
	 */
	public static function rotate_api_token(): string {
		$token = bin2hex( random_bytes( 32 ) );
		update_option( self::OPT_API_TOKEN_HASH, hash( 'sha256', $token ), false );
		return $token;
	}

	public static function revoke_api_token(): void {
		delete_option( self::OPT_API_TOKEN_HASH );
	}

	public static function verify_bearer_token( string $candidate ): bool {
		$candidate = trim( $candidate );
		if ( '' === $candidate ) {
			return false;
		}
		if ( defined( 'WM_CRA_API_TOKEN' ) && '' !== trim( (string) WM_CRA_API_TOKEN ) ) {
			if ( hash_equals( trim( (string) WM_CRA_API_TOKEN ), $candidate ) ) {
				return true;
			}
		}
		$stored_hash = (string) get_option( self::OPT_API_TOKEN_HASH, '' );
		if ( 1 === preg_match( '/^[a-f0-9]{64}$/', $stored_hash ) ) {
			return hash_equals( $stored_hash, hash( 'sha256', $candidate ) );
		}
		return false;
	}

	/**
	 * Permission callback for /sbom, /spdx, /vex, /csaf:
	 * 1. Administrator session (`manage_options`), OR
	 * 2. Valid `Authorization: Bearer <token>` header, OR
	 * 3. Explicit public opt-in (`wm_cra_public_endpoints = 1`) within per-IP rate budget.
	 *
	 * @param mixed $request WP_REST_Request instance.
	 * @return bool|WP_Error
	 */
	public function check_read_permission( $request = null ): bool|WP_Error {
		if ( current_user_can( 'manage_options' ) ) {
			return true;
		}

		$auth_header = '';
		if ( is_object( $request ) && method_exists( $request, 'get_header' ) ) {
			$auth_header = (string) $request->get_header( 'authorization' );
		}
		if ( '' === $auth_header && isset( $_SERVER['HTTP_AUTHORIZATION'] ) ) {
			$auth_header = sanitize_text_field( wp_unslash( (string) $_SERVER['HTTP_AUTHORIZATION'] ) );
		}

		if ( 1 === preg_match( '/^Bearer\s+(\S+)$/i', trim( $auth_header ), $m ) ) {
			if ( self::verify_bearer_token( $m[1] ) ) {
				return true;
			}
			return new WP_Error(
				'wm_cra_invalid_token',
				__( 'Ungültiges Bearer-Token.', 'wm-cra-sbom-beacon' ),
				[ 'status' => 401 ]
			);
		}

		if ( ! self::is_public_enabled() ) {
			return new WP_Error(
				'wm_cra_forbidden',
				__( 'Zugriff verweigert: Anmeldung oder Bearer-Token erforderlich.', 'wm-cra-sbom-beacon' ),
				[ 'status' => 401 ]
			);
		}

		if ( ! self::consume_rate_limit() ) {
			return new WP_Error(
				'wm_cra_rate_limited',
				__( 'Zu viele Anfragen. Bitte später erneut versuchen.', 'wm-cra-sbom-beacon' ),
				[ 'status' => 429 ]
			);
		}

		return true;
	}

	/**
	 * GDPR-safe transient rate limiter keyed on a salted SHA-256 digest of REMOTE_ADDR (never stores raw IPs).
	 */
	public static function consume_rate_limit( ?string $remote_addr = null ): bool {
		if ( ! function_exists( 'get_transient' ) || ! function_exists( 'set_transient' ) ) {
			return true;
		}
		$ip   = null !== $remote_addr ? $remote_addr : sanitize_text_field( wp_unslash( (string) ( $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0' ) ) );
		$salt = function_exists( 'wp_salt' ) ? wp_salt( 'auth' ) : ABSPATH;
		$key  = 'wm_cra_rl_' . substr( hash( 'sha256', $ip . '|' . $salt ), 0, 20 );

		$hits = (int) get_transient( $key );
		if ( $hits >= self::RATE_LIMIT_MAX ) {
			return false;
		}
		set_transient( $key, $hits + 1, 60 );
		return true;
	}

	public static function flush_caches(): void {
		$bust = (int) get_option( self::OPT_CACHE_BUST, 0 );
		update_option( self::OPT_CACHE_BUST, $bust + 1, false );
	}

	private function inventory_cache_suffix(): string {
		$state = [
			'plugins' => get_option( 'active_plugins', [] ),
			'crypto'  => CryptoInventory::enabled(),
			'bust'    => (int) get_option( self::OPT_CACHE_BUST, 0 ),
		];
		return substr( hash( 'sha256', (string) wp_json_encode( $state ) ), 0, 16 );
	}

	private function cached_sbom(): array {
		$key = 'wm_cra_sbom_' . $this->inventory_cache_suffix();
		if ( function_exists( 'get_transient' ) ) {
			$cached = get_transient( $key );
			if ( is_array( $cached ) ) {
				return $cached;
			}
		}
		$sbom = $this->sbom_generator->generate_sbom();
		if ( function_exists( 'set_transient' ) ) {
			set_transient( $key, $sbom, self::CACHE_TTL );
		}
		return $sbom;
	}

	public function get_sbom(): WP_REST_Response {
		return new WP_REST_Response( $this->cached_sbom(), 200 );
	}

	public function get_spdx(): WP_REST_Response {
		$key = 'wm_cra_spdx_' . $this->inventory_cache_suffix();
		if ( function_exists( 'get_transient' ) ) {
			$cached = get_transient( $key );
			if ( is_array( $cached ) ) {
				return new WP_REST_Response( $cached, 200 );
			}
		}
		$doc = ( new Spdx3Generator() )->generate( $this->cached_sbom() );
		if ( function_exists( 'set_transient' ) ) {
			set_transient( $key, $doc, self::CACHE_TTL );
		}
		return new WP_REST_Response( $doc, 200 );
	}

	public function get_vex(): WP_REST_Response {
		$key = 'wm_cra_vex_' . substr(
			hash(
				'sha256',
				OpenVexEngine::version()
				. '|' . (int) get_option( self::OPT_CACHE_BUST, 0 )
				. '|' . (string) wp_json_encode( VulnerabilityAudit::state() )
			),
			0,
			16
		);
		if ( function_exists( 'get_transient' ) ) {
			$cached = get_transient( $key );
			if ( is_array( $cached ) ) {
				return new WP_REST_Response( $cached, 200 );
			}
		}
		$doc = OpenVexEngine::document();
		if ( function_exists( 'set_transient' ) ) {
			set_transient( $key, $doc, self::CACHE_TTL );
		}
		return new WP_REST_Response( $doc, 200 );
	}

	public function get_csaf(): WP_REST_Response {
		$key = 'wm_cra_csaf_' . (int) get_option( self::OPT_CACHE_BUST, 0 );
		if ( function_exists( 'get_transient' ) ) {
			$cached = get_transient( $key );
			if ( is_array( $cached ) ) {
				return new WP_REST_Response( $cached, 200 );
			}
		}
		$feed = $this->csaf_publisher->get_feed();
		if ( function_exists( 'set_transient' ) ) {
			set_transient( $key, $feed, self::CACHE_TTL );
		}
		return new WP_REST_Response( $feed, 200 );
	}
}
