<?php
declare(strict_types=1);

namespace WMCyber\CRA\Vuln;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Queries the NVD 2.0 API for the WordPress components OSV does not cover.
 *
 * The query asks for a product name with a **wildcard vendor** — `cpe:2.3:a:*:contact_form_7` —
 * because a plugin header states no CPE vendor and guessing one would be inventing part of somebody
 * else's identifier. `CpeMatcher` then keeps only the matches whose `target_sw` is `wordpress` and
 * whose version bounds contain the installed version, which is what turns a name match into a
 * statement about this installation.
 *
 * **Rate limit.** NVD allows 5 requests per rolling 30 seconds without an API key and 50 with one
 * (documented, and the reason for the pause between requests). One request per component and about
 * thirty active plugins would be three minutes of waiting, so a run takes a budget of components
 * and a cursor: the daily cron walks the list over several days, and every component records **when
 * it was last checked**. A component that has not been checked yet says so. It never says it is
 * clean.
 */
final class NvdClient {

	public const ENDPOINT = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

	/** Option holding an optional API key, which raises the rate limit from 5 to 50 per 30 seconds. */
	public const OPT_API_KEY = 'wm_cra_nvd_api_key';

	/** Seconds to wait between requests: 30/5 without a key, 30/50 with one, rounded up. */
	public const PAUSE_WITHOUT_KEY = 7;
	public const PAUSE_WITH_KEY    = 1;

	/** Components one run checks. Raised when a key is configured, since the limit is ten times higher. */
	public const BUDGET_WITHOUT_KEY = 8;
	public const BUDGET_WITH_KEY    = 40;

	private const TIMEOUT = 30;

	/** How many components this run may check. */
	public static function budget(): int {
		return self::has_key() ? self::BUDGET_WITH_KEY : self::BUDGET_WITHOUT_KEY;
	}

	/**
	 * Seconds to wait between two requests.
	 *
	 * Filterable so the suite can drive a whole run without spending a minute asleep; the default
	 * is what the documented limit requires and nothing in the plugin changes it.
	 */
	public static function pause(): int {
		return (int) \apply_filters( 'wm_cra_nvd_pause', self::has_key() ? self::PAUSE_WITH_KEY : self::PAUSE_WITHOUT_KEY );
	}

	public static function has_key(): bool {
		return '' !== trim( (string) \get_option( self::OPT_API_KEY, '' ) );
	}

	/**
	 * The request URL for one product.
	 *
	 * `resultsPerPage` is capped: a product with more matches than this is reported as partially
	 * checked rather than silently truncated.
	 */
	public static function url( string $product, int $results_per_page = 200 ): string {
		return self::ENDPOINT . '?' . http_build_query( [
			'virtualMatchString' => 'cpe:2.3:a:*:' . $product,
			'resultsPerPage'     => $results_per_page,
		] );
	}

	/**
	 * Check one component.
	 *
	 * @param string $slug    WordPress slug, e.g. `contact-form-7`.
	 * @param string $version Installed version; '' when the header states none.
	 * @return array{findings: list<array<string, mixed>>, error: ?string, total: int, truncated: bool}
	 */
	public function check( string $slug, string $version ): array {
		$product = CpeMatcher::product_from_slug( $slug );
		if ( '' === $product ) {
			return [ 'findings' => [], 'error' => __( 'Kein Produktname für die Abfrage.', 'wm-cra-sbom-beacon' ), 'total' => 0, 'truncated' => false ];
		}

		$headers = [ 'Accept' => 'application/json' ];
		$key     = trim( (string) \get_option( self::OPT_API_KEY, '' ) );
		if ( '' !== $key ) {
			$headers['apiKey'] = $key;
		}

		$decoded = OsvClient::decode(
			wp_remote_get( self::url( $product ), [
				'timeout'    => self::TIMEOUT,
				'headers'    => $headers,
				'user-agent' => 'WM CRA SBOM Beacon/' . ( defined( 'WM_CRA_VERSION' ) ? WM_CRA_VERSION : '0.0.0' ),
			] ),
			'NVD'
		);

		if ( null !== $decoded['error'] ) {
			return [ 'findings' => [], 'error' => $decoded['error'], 'total' => 0, 'truncated' => false ];
		}

		return self::findings_from( $decoded['body'], $product, $version );
	}

	/**
	 * The affecting CVEs in one NVD response.
	 *
	 * Pure, so the whole match — target_sw, product, version bounds, severity — is measured in the
	 * suite against recorded responses instead of against the network.
	 *
	 * @param array<string, mixed> $body    Decoded NVD response.
	 * @param string               $product CPE product name.
	 * @param string               $version Installed version.
	 * @return array{findings: list<array<string, mixed>>, error: ?string, total: int, truncated: bool}
	 */
	public static function findings_from( array $body, string $product, string $version ): array {
		$total     = (int) ( $body['totalResults'] ?? 0 );
		$returned  = (array) ( $body['vulnerabilities'] ?? [] );
		$truncated = $total > count( $returned );

		if ( '' === CpeMatcher::normalise( $version ) ) {
			// Without a version nothing can be said about this installation, and saying "nothing
			// found" would be saying something. The caller records it as unknown.
			return [
				'findings'  => [],
				'error'     => __( 'Die Version dieser Komponente ist unbekannt; ein Abgleich gegen Versionsbereiche war nicht möglich.', 'wm-cra-sbom-beacon' ),
				'total'     => $total,
				'truncated' => $truncated,
			];
		}

		$findings = [];
		foreach ( $returned as $entry ) {
			$cve = (array) ( $entry['cve'] ?? [] );
			$id  = (string) ( $cve['id'] ?? '' );
			if ( '' === $id || ! CpeMatcher::cve_affects( $cve, $product, $version ) ) {
				continue;
			}

			$severity   = CpeMatcher::severity_of( $cve );
			$finding    = [
				'source'    => 'nvd',
				'advisory'  => $id,
				'cve'       => $id,
				'summary'   => self::description( $cve ),
				'severity'  => $severity['severity'],
				'score'     => $severity['score'],
				'published' => (string) ( $cve['published'] ?? '' ),
			];
			if ( '' !== $severity['metric'] ) {
				$finding['metric'] = $severity['metric'];
			}
			$findings[] = $finding;
		}

		return [ 'findings' => $findings, 'error' => null, 'total' => $total, 'truncated' => $truncated ];
	}

	/** The English description NVD states, cut to a length a log row can hold. */
	private static function description( array $cve ): string {
		foreach ( (array) ( $cve['descriptions'] ?? [] ) as $description ) {
			if ( 'en' === ( $description['lang'] ?? '' ) ) {
				return trim( mb_substr( (string) ( $description['value'] ?? '' ), 0, 500 ) );
			}
		}

		return '';
	}
}
