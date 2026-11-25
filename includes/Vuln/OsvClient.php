<?php
declare(strict_types=1);

namespace WMCyber\CRA\Vuln;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Queries OSV (osv.dev) for the Composer and npm libraries the inventory found.
 *
 * **OSV has no usable data for WordPress components.** Measured 2026-09-16: the ecosystem strings
 * `WordPress`, `WordPress:Core`, `WordPress:Plugin` and `WordPress:Theme` are accepted by the API
 * (an unknown ecosystem is rejected with `invalid ecosystem`), but they answer `{}` for
 * `contact-form-7 5.7.1`, `elementor 3.5.0`, `wordpress 6.4` and `twentytwentyone`, and
 * `CVE-2023-6553` — a WordPress plugin RCE — is not in the database at all. A connector that sent
 * plugins here would report "no vulnerabilities" for every site forever: a check with no variance,
 * which is worse than no check because it looks like one.
 *
 * So this client is for what OSV does cover, and covers well: the Packagist and npm packages the
 * plugins bundle (verified: `symfony/http-kernel 4.4.0` returns two advisories, with or without the
 * `v` prefix a `composer.lock` writes). WordPress components go to NVD instead.
 */
final class OsvClient {

	public const QUERY_BATCH_ENDPOINT = 'https://api.osv.dev/v1/querybatch';
	public const VULN_ENDPOINT        = 'https://api.osv.dev/v1/vulns/';

	/** Ecosystems whose purls this client sends. */
	public const SUPPORTED_PURL_PREFIXES = [ 'pkg:composer/', 'pkg:npm/' ];

	/** The API takes up to 1000 queries in one batch; this stays well inside it. */
	public const BATCH_SIZE = 200;

	/** Most detail requests one run makes, so a badly outdated site cannot stall the cron. */
	public const MAX_DETAIL_REQUESTS = 60;

	private const TIMEOUT = 20;

	/**
	 * Purls this client can ask about.
	 *
	 * @param list<string> $purls Component purls.
	 * @return list<string>
	 */
	public static function supported( array $purls ): array {
		$supported = [];
		foreach ( $purls as $purl ) {
			foreach ( self::SUPPORTED_PURL_PREFIXES as $prefix ) {
				if ( str_starts_with( (string) $purl, $prefix ) ) {
					$supported[] = (string) $purl;
					break;
				}
			}
		}

		return array_values( array_unique( $supported ) );
	}

	/**
	 * The request body for one batch.
	 *
	 * @param list<string> $purls Purls.
	 * @return array{queries: list<array{package: array{purl: string}}>}
	 */
	public static function batch_body( array $purls ): array {
		$queries = [];
		foreach ( $purls as $purl ) {
			$queries[] = [ 'package' => [ 'purl' => (string) $purl ] ];
		}

		return [ 'queries' => $queries ];
	}

	/**
	 * Advisory ids per purl, from a batch response.
	 *
	 * The response is positional: `results[i]` answers `queries[i]`, and a package with nothing
	 * against it is an empty object rather than a missing entry. Reading it by position is the only
	 * correct way; there is no package name in the answer to match on.
	 *
	 * @param array<string, mixed> $response Decoded batch response.
	 * @param list<string>         $purls    The purls that were sent, in order.
	 * @return array<string, list<string>>
	 */
	public static function ids_by_purl( array $response, array $purls ): array {
		$results = (array) ( $response['results'] ?? [] );
		$by_purl = [];

		foreach ( array_values( $purls ) as $index => $purl ) {
			$ids = [];
			foreach ( (array) ( $results[ $index ]['vulns'] ?? [] ) as $vuln ) {
				$id = (string) ( $vuln['id'] ?? '' );
				if ( '' !== $id ) {
					$ids[] = $id;
				}
			}
			if ( [] !== $ids ) {
				$by_purl[ (string) $purl ] = $ids;
			}
		}

		return $by_purl;
	}

	/**
	 * Query OSV for a list of purls.
	 *
	 * @param list<string> $purls Purls.
	 * @return array{findings: array<string, list<array<string, mixed>>>, checked: list<string>, error: ?string}
	 */
	public function query( array $purls ): array {
		$purls = self::supported( $purls );
		if ( [] === $purls ) {
			return [ 'findings' => [], 'checked' => [], 'error' => null ];
		}

		$findings = [];
		$checked  = [];
		$details  = 0;

		foreach ( array_chunk( $purls, self::BATCH_SIZE ) as $chunk ) {
			$response = $this->post( self::QUERY_BATCH_ENDPOINT, self::batch_body( $chunk ) );
			if ( null !== $response['error'] ) {
				// Everything in this chunk stays unchecked. A source that could not be reached must
				// not leave its components looking clean.
				return [ 'findings' => $findings, 'checked' => $checked, 'error' => $response['error'] ];
			}

			$checked = array_merge( $checked, $chunk );

			foreach ( self::ids_by_purl( $response['body'], $chunk ) as $purl => $ids ) {
				foreach ( $ids as $id ) {
					if ( $details >= self::MAX_DETAIL_REQUESTS ) {
						break 2;
					}
					++$details;
					$detail = $this->get( self::VULN_ENDPOINT . rawurlencode( $id ) );
					$findings[ $purl ][] = null === $detail['error']
						? self::finding( $id, $detail['body'] )
						: self::finding( $id, [] );
				}
			}
		}

		return [ 'findings' => $findings, 'checked' => $checked, 'error' => null ];
	}

	/**
	 * One advisory as this plugin stores it. Nothing absent is filled in.
	 *
	 * @param array<string, mixed> $vuln Decoded OSV advisory.
	 * @return array<string, mixed>
	 */
	public static function finding( string $id, array $vuln ): array {
		$aliases = array_values( array_filter( array_map( 'strval', (array) ( $vuln['aliases'] ?? [] ) ) ) );
		$cve     = '';
		foreach ( $aliases as $alias ) {
			if ( str_starts_with( $alias, 'CVE-' ) ) {
				$cve = $alias;
				break;
			}
		}
		if ( '' === $cve && str_starts_with( $id, 'CVE-' ) ) {
			$cve = $id;
		}

		$finding = [
			'source'     => 'osv',
			'advisory'   => $id,
			'summary'    => trim( (string) ( $vuln['summary'] ?? '' ) ),
			'severity'   => '',
			'score'      => null,
			'published'  => (string) ( $vuln['published'] ?? '' ),
		];
		if ( '' !== $cve ) {
			$finding['cve'] = $cve;
		}

		// OSV states severity as a CVSS vector, not a number. The vector is kept as it stands; a
		// score is not derived from it here, because computing one would mean publishing a figure
		// this plugin calculated and presenting it as the advisory's.
		foreach ( (array) ( $vuln['severity'] ?? [] ) as $severity ) {
			$vector = trim( (string) ( $severity['score'] ?? '' ) );
			if ( '' !== $vector ) {
				$finding['cvss_vector'] = $vector;
				break;
			}
		}

		return $finding;
	}

	/**
	 * @return array{body: array<string, mixed>, error: ?string}
	 */
	private function post( string $url, array $body ): array {
		$response = wp_remote_post( $url, [
			'timeout'    => self::TIMEOUT,
			'headers'    => [ 'Content-Type' => 'application/json' ],
			'body'       => (string) wp_json_encode( $body ),
			'user-agent' => self::user_agent(),
		] );

		return self::decode( $response, 'osv.dev' );
	}

	/**
	 * @return array{body: array<string, mixed>, error: ?string}
	 */
	private function get( string $url ): array {
		return self::decode( wp_remote_get( $url, [ 'timeout' => self::TIMEOUT, 'user-agent' => self::user_agent() ] ), 'osv.dev' );
	}

	/**
	 * @param mixed $response Result of a wp_remote_* call.
	 * @return array{body: array<string, mixed>, error: ?string}
	 */
	public static function decode( $response, string $service ): array {
		if ( is_wp_error( $response ) ) {
			/* translators: %s: name of the vulnerability database */
			return [ 'body' => [], 'error' => sprintf( __( '%s war nicht erreichbar.', 'wm-cra-sbom-beacon' ), $service ) ];
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			return [
				'body'  => [],
				/* translators: 1: name of the vulnerability database, 2: HTTP status code */
				'error' => sprintf( __( '%1$s antwortete mit HTTP %2$d.', 'wm-cra-sbom-beacon' ), $service, $code ),
			];
		}

		$decoded = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $decoded ) ) {
			/* translators: %s: name of the vulnerability database */
			return [ 'body' => [], 'error' => sprintf( __( 'Die Antwort von %s war kein JSON.', 'wm-cra-sbom-beacon' ), $service ) ];
		}

		return [ 'body' => $decoded, 'error' => null ];
	}

	private static function user_agent(): string {
		return 'WM CRA SBOM Beacon/' . ( defined( 'WM_CRA_VERSION' ) ? WM_CRA_VERSION : '0.0.0' );
	}
}
