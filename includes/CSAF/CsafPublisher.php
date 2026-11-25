<?php
declare(strict_types=1);

namespace WMCyber\CRA\CSAF;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Stores advisories as CSAF 2.0 documents of the base profile (document category "csaf_base") and lists them in a
 * JSON index.
 *
 * Checked against the OASIS CSAF 2.0 JSON schema and specification on 2026-09-15: /document requires category,
 * csaf_version, publisher (category, name, namespace), title and tracking (current_release_date, id,
 * initial_release_date, revision_history with date/number/summary, status, version). The "Security Advisory"
 * profile additionally requires a product_tree and product_status, which this plugin cannot state, so it does not
 * claim that profile. Until 2026-09-15 documents used "csaf_security_advisory" without those, carried no
 * revision_history, a CVSS object without version or vector, a fixed CVE "CVE-2026-CRA-LOCAL" and score 7.5/9.8
 * from the CLI, and the index named a "WM Suite PSIRT / BSI CSIRT Liaison" as issuing authority on every site.
 */
final class CsafPublisher {
	public const SEVERITIES = [ 'low', 'medium', 'high', 'critical' ];

	private function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'wm_cra_advisories';
	}

	public function table_exists(): bool {
		global $wpdb;
		$table = $this->table();
		return $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) ) === $table;
	}

	public function count_advisories(): int {
		global $wpdb;
		if ( ! $this->table_exists() ) {
			return 0;
		}
		return (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i', $this->table() ) );
	}

	/**
	 * The index behind GET /wp-json/wm-cra/v1/csaf. It is not a CSAF provider-metadata.json or ROLIE feed.
	 *
	 * @return array<string, mixed>
	 */
	public function get_feed(): array {
		global $wpdb;

		$advisories = [];
		if ( $this->table_exists() ) {
			$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT csaf_json FROM %i ORDER BY id DESC LIMIT 50', $this->table() ), ARRAY_A );
			foreach ( (array) $rows as $row ) {
				$doc = json_decode( (string) $row['csaf_json'], true );
				if ( is_array( $doc ) ) {
					$advisories[] = $doc;
				}
			}
		}

		return [
			'index'        => 'Advisories published on this site (newest 50). Not a CSAF provider-metadata.json or ROLIE feed.',
			'publisher'    => self::publisher(),
			'generated_at' => gmdate( 'Y-m-d\TH:i:s\Z' ),
			'advisories'   => $advisories,
		];
	}

	/**
	 * Create or update an advisory. A re-publication keeps the initial release date, raises the version by one and
	 * appends to the revision history (CSAF 2.0 integer versioning).
	 *
	 * @param array{cve?: string, description?: string, summary?: string} $details
	 * @return array{saved: bool, error: string, document: array<string, mixed>}
	 */
	public function publish_advisory( string $tracking_id, string $title, string $severity, array $details = [] ): array {
		global $wpdb;

		$tracking_id = trim( $tracking_id );
		$title       = trim( $title );
		$severity    = strtolower( trim( $severity ) );
		$cve         = strtoupper( trim( (string) ( $details['cve'] ?? '' ) ) );
		$description = trim( (string) ( $details['description'] ?? '' ) );

		$fail = static fn( string $error ): array => [ 'saved' => false, 'error' => $error, 'document' => [] ];

		// CSAF tracking id: printable, no leading/trailing whitespace; kept short for the UNIQUE column.
		if ( ! preg_match( '/^[\S](?:[\S ]{0,62}[\S])?$/', $tracking_id ) ) {
			return $fail( 'The tracking id must be 1 to 64 printable characters.' );
		}
		if ( '' === $title ) {
			return $fail( 'The title must not be empty.' );
		}
		if ( ! in_array( $severity, self::SEVERITIES, true ) ) {
			return $fail( 'The severity must be one of: ' . implode( ', ', self::SEVERITIES ) . '.' );
		}
		if ( '' !== $cve && ! preg_match( '/^CVE-\d{4}-\d{4,}$/', $cve ) ) {
			return $fail( 'The CVE id must look like CVE-2026-12345.' );
		}
		if ( ! $this->table_exists() ) {
			return $fail( 'The advisories table does not exist; deactivate and activate the plugin.' );
		}

		$now      = gmdate( 'Y-m-d\TH:i:s\Z' );
		$existing = $wpdb->get_row( $wpdb->prepare( 'SELECT csaf_json, published_at FROM %i WHERE tracking_id = %s', $this->table(), $tracking_id ), ARRAY_A );
		$previous = is_array( $existing ) ? json_decode( (string) $existing['csaf_json'], true ) : null;
		$history  = is_array( $previous['document']['tracking']['revision_history'] ?? null ) ? $previous['document']['tracking']['revision_history'] : [];
		$initial  = is_string( $previous['document']['tracking']['initial_release_date'] ?? null ) ? $previous['document']['tracking']['initial_release_date'] : $now;
		$number   = count( $history ) + 1;

		$history[] = [
			'date'    => $now,
			'number'  => (string) $number,
			'summary' => 1 === $number ? 'Initial release.' : 'Updated.',
		];

		$document = [
			'document' => [
				'category'           => 'csaf_base',
				'csaf_version'       => '2.0',
				'publisher'          => self::publisher(),
				'title'              => $title,
				'aggregate_severity' => [ 'text' => $severity ],
				'tracking'           => [
					'id'                   => $tracking_id,
					'status'               => 'final',
					'version'              => (string) $number,
					'initial_release_date' => $initial,
					'current_release_date' => $now,
					'revision_history'     => $history,
				],
			],
		];

		$vulnerability = [];
		if ( '' !== $cve ) {
			$vulnerability['cve'] = $cve;
		}
		if ( '' !== $description ) {
			$vulnerability['notes'] = [ [ 'category' => 'description', 'text' => $description ] ];
		}
		if ( [] !== $vulnerability ) {
			$document['vulnerabilities'] = [ $vulnerability ];
		}

		$json      = (string) wp_json_encode( $document, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );
		$mysql_now = current_time( 'mysql', true );

		if ( is_array( $existing ) ) {
			$result = $wpdb->update(
				$this->table(),
				[ 'title' => $title, 'severity' => $severity, 'csaf_json' => $json, 'updated_at' => $mysql_now ],
				[ 'tracking_id' => $tracking_id ],
				[ '%s', '%s', '%s', '%s' ],
				[ '%s' ]
			);
		} else {
			$result = $wpdb->insert(
				$this->table(),
				[ 'tracking_id' => $tracking_id, 'title' => $title, 'severity' => $severity, 'csaf_json' => $json, 'published_at' => $mysql_now, 'updated_at' => $mysql_now ],
				[ '%s', '%s', '%s', '%s', '%s', '%s' ]
			);
		}

		if ( false === $result ) {
			return $fail( 'The database write failed: ' . (string) $wpdb->last_error );
		}
		if ( class_exists( \WMCyber\CRA\API\RestController::class ) ) {
			\WMCyber\CRA\API\RestController::flush_caches();
		}
		return [ 'saved' => true, 'error' => '', 'document' => $document ];
	}

	/** @return array{category: string, name: string, namespace: string} */
	private static function publisher(): array {
		return [
			'category'  => 'vendor',
			'name'      => trim( (string) get_bloginfo( 'name' ) ) ?: (string) wp_parse_url( home_url(), PHP_URL_HOST ),
			'namespace' => home_url( '/' ),
		];
	}
}
