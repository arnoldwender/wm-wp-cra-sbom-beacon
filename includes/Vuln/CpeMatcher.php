<?php
declare(strict_types=1);

namespace WMCyber\CRA\Vuln;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Decides whether an installed version falls inside the range an NVD configuration describes.
 *
 * Without this, an audit that found any CVE ever filed against a plugin would report it whatever
 * version is installed — a permanently red screen that the operator learns to ignore, which is the
 * same failure as a monitor that cries wolf. The bounds are what turn "this plugin has had
 * vulnerabilities" into "this installation is affected".
 *
 * Every field name and position below was read from a live NVD 2.0 response on 2026-09-16, not
 * recalled: `cpeMatch` carries `criteria`, `vulnerable` and up to four bounds, and the criteria is a
 * CPE 2.3 string whose eleventh colon-separated field is `target_sw`.
 */
final class CpeMatcher {

	/**
	 * Index of `target_sw` in a colon-split CPE 2.3 string.
	 *
	 * `cpe:2.3:a:rocklobster:contact_form_7:*:*:*:*:*:wordpress:*:*`
	 *  0   1   2 3           4              5 6 7 8 9 10        11 12
	 */
	public const TARGET_SW_INDEX = 10;

	/** Index of the product field, used to check that a match is about the component we asked for. */
	public const PRODUCT_INDEX = 4;

	/** Index of the version field; '*' means the bounds decide. */
	public const VERSION_INDEX = 5;

	/**
	 * Whether a CPE criteria describes WordPress software.
	 *
	 * The query asks NVD for a product name with a wildcard vendor, so a name collision with
	 * unrelated software is possible. `target_sw` is what separates the WordPress plugin from a
	 * desktop program that happens to share a name.
	 */
	public static function targets_wordpress( string $criteria ): bool {
		$parts = explode( ':', $criteria );

		return 'wordpress' === strtolower( $parts[ self::TARGET_SW_INDEX ] ?? '' );
	}

	/** The product field of a CPE criteria. */
	public static function product( string $criteria ): string {
		$parts = explode( ':', $criteria );

		return strtolower( $parts[ self::PRODUCT_INDEX ] ?? '' );
	}

	/**
	 * Whether `$version` is inside what one `cpeMatch` entry describes.
	 *
	 * @param array<string, mixed> $cpe_match One entry of `configurations[].nodes[].cpeMatch`.
	 */
	public static function matches( array $cpe_match, string $version, string $product ): bool {
		$criteria = (string) ( $cpe_match['criteria'] ?? '' );

		// `vulnerable: false` marks a platform a vulnerability needs in order to apply, not the
		// affected product itself. Treating it as a hit reports the operating system as vulnerable.
		if ( empty( $cpe_match['vulnerable'] ) || '' === $criteria ) {
			return false;
		}
		if ( ! self::targets_wordpress( $criteria ) || self::product( $criteria ) !== strtolower( $product ) ) {
			return false;
		}

		$version = self::normalise( $version );
		if ( '' === $version ) {
			// Nothing to compare against. A component whose version is unknown is not declared
			// unaffected; the audit records it as "version unknown" instead, which is not a pass.
			return false;
		}

		$pinned = self::normalise( (string) ( explode( ':', $criteria )[ self::VERSION_INDEX ] ?? '' ) );
		if ( '' !== $pinned && '*' !== $pinned && '-' !== $pinned ) {
			return 0 === version_compare( $pinned, $version );
		}

		return self::within_bounds( $cpe_match, $version );
	}

	/**
	 * The four bounds NVD uses. Absent bounds are open ends.
	 *
	 * @param array<string, mixed> $cpe_match One cpeMatch entry.
	 */
	public static function within_bounds( array $cpe_match, string $version ): bool {
		$start_including = self::normalise( (string) ( $cpe_match['versionStartIncluding'] ?? '' ) );
		$start_excluding = self::normalise( (string) ( $cpe_match['versionStartExcluding'] ?? '' ) );
		$end_including   = self::normalise( (string) ( $cpe_match['versionEndIncluding'] ?? '' ) );
		$end_excluding   = self::normalise( (string) ( $cpe_match['versionEndExcluding'] ?? '' ) );

		// A wildcard criteria with no bound at all covers every version ever released. NVD does
		// publish such entries, and they are true: the product is affected in all versions.
		if ( '' !== $start_including && version_compare( $version, $start_including, '<' ) ) {
			return false;
		}
		if ( '' !== $start_excluding && version_compare( $version, $start_excluding, '<=' ) ) {
			return false;
		}
		if ( '' !== $end_including && version_compare( $version, $end_including, '>' ) ) {
			return false;
		}
		if ( '' !== $end_excluding && version_compare( $version, $end_excluding, '>=' ) ) {
			return false;
		}

		return true;
	}

	/**
	 * A version as `version_compare()` can read it.
	 *
	 * WordPress plugins publish versions such as `5.7.1`, `1.0`, `2.1.0-beta2` and `v3.4`; the
	 * leading `v` that Composer tags carry is not part of the number.
	 */
	public static function normalise( string $version ): string {
		$version = trim( $version );
		if ( '' === $version || '*' === $version || '-' === $version ) {
			return '';
		}

		return ltrim( $version, 'vV' );
	}

	/**
	 * The CPE product name a WordPress slug would carry.
	 *
	 * NVD writes product names with underscores (`contact_form_7`), WordPress slugs with hyphens
	 * (`contact-form-7`). This is a transliteration of a name, not a guess at a vendor: the vendor
	 * field stays a wildcard in the query, and `target_sw` decides whether a hit is about WordPress.
	 */
	public static function product_from_slug( string $slug ): string {
		return str_replace( '-', '_', strtolower( trim( $slug ) ) );
	}

	/**
	 * Every WordPress-targeted match in one CVE that covers this component and version.
	 *
	 * @param array<string, mixed> $cve     One `vulnerabilities[].cve` object.
	 * @param string               $product CPE product name.
	 * @param string               $version Installed version.
	 * @return bool
	 */
	public static function cve_affects( array $cve, string $product, string $version ): bool {
		foreach ( (array) ( $cve['configurations'] ?? [] ) as $configuration ) {
			foreach ( (array) ( $configuration['nodes'] ?? [] ) as $node ) {
				foreach ( (array) ( $node['cpeMatch'] ?? [] ) as $cpe_match ) {
					if ( is_array( $cpe_match ) && self::matches( $cpe_match, $version, $product ) ) {
						return true;
					}
				}
			}
		}

		return false;
	}

	/**
	 * The highest CVSS base score NVD states, with the metric it came from.
	 *
	 * Newer metrics first: a CVE scored under both v2 and v3.1 is a v3.1 score, and reporting the
	 * v2 number would understate it. Nothing is computed — a CVE without a score gets none.
	 *
	 * @param array<string, mixed> $cve One cve object.
	 * @return array{score: ?float, severity: string, metric: string}
	 */
	public static function severity_of( array $cve ): array {
		foreach ( [ 'cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2' ] as $metric ) {
			$entries = (array) ( $cve['metrics'][ $metric ] ?? [] );
			foreach ( $entries as $entry ) {
				$data     = (array) ( $entry['cvssData'] ?? [] );
				$score    = $data['baseScore'] ?? null;
				$severity = (string) ( $data['baseSeverity'] ?? ( $entry['baseSeverity'] ?? '' ) );
				if ( is_numeric( $score ) ) {
					return [ 'score' => (float) $score, 'severity' => strtolower( $severity ), 'metric' => $metric ];
				}
			}
		}

		return [ 'score' => null, 'severity' => '', 'metric' => '' ];
	}
}
