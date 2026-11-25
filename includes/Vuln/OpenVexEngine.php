<?php
declare(strict_types=1);

namespace WMCyber\CRA\Vuln;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Publishes the operator's position on each vulnerability the audit found, as an OpenVEX document.
 *
 * A scanner reports that a component *has* a published vulnerability. VEX is how the party that
 * ships the product says what that means here: the vulnerable code is not reachable, a mitigation is
 * already in place, the fix is installed, or nobody has looked yet. Without it, a downstream
 * consumer of the SBOM has to treat every finding as live.
 *
 * **The engine never invents a position.** A finding with no statement from the operator is
 * published as `under_investigation`, which is the VEX label for exactly that and the only one of
 * the four that is true without anyone having assessed anything. `not_affected` and `affected` are
 * only ever written because a person wrote them, with the justification the specification demands.
 *
 * Field names, the status labels and the justification labels were read from the OpenVEX v0.2.0
 * specification on 2026-09-16.
 */
final class OpenVexEngine {

	/** The context IRI; the version is part of it, and omitting it means v0.0.1. */
	public const CONTEXT = 'https://openvex.dev/ns/v0.2.0';

	/** Statements the operator has made, and the document version counter. */
	public const OPT_STATEMENTS = 'wm_cra_vex_statements';
	public const OPT_VERSION    = 'wm_cra_vex_version';

	/** The four VEX status labels. */
	public const STATUSES = [ 'not_affected', 'affected', 'fixed', 'under_investigation' ];

	/**
	 * The five justification labels, from the VEX Working Group catalogue of July 2022.
	 *
	 * A `not_affected` statement must carry one of these or a free-text impact statement; the
	 * specification allows nothing else, and a made-up label would make the document unusable for
	 * the automated policies that are the whole point of machine-readable justifications.
	 */
	public const JUSTIFICATIONS = [
		'component_not_present',
		'vulnerable_code_not_present',
		'vulnerable_code_not_in_execute_path',
		'vulnerable_code_cannot_be_controlled_by_adversary',
		'inline_mitigations_already_exist',
	];

	/**
	 * Record the operator's position on one vulnerability in one component.
	 *
	 * @param string $purl          Component purl, which is the product identifier in the document.
	 * @param string $vulnerability CVE or advisory id.
	 * @param string $status        One of STATUSES.
	 * @param array<string, string> $details justification, impact_statement, action_statement, status_notes.
	 * @return array{saved: bool, error: ?string}
	 */
	public static function record( string $purl, string $vulnerability, string $status, array $details = [] ): array {
		$purl          = trim( $purl );
		$vulnerability = trim( $vulnerability );

		if ( '' === $purl || '' === $vulnerability ) {
			return [ 'saved' => false, 'error' => __( 'Produkt und Schwachstelle müssen benannt sein.', 'wm-cra-sbom-beacon' ) ];
		}
		if ( ! in_array( $status, self::STATUSES, true ) ) {
			return [ 'saved' => false, 'error' => __( 'Unbekannter VEX-Status.', 'wm-cra-sbom-beacon' ) ];
		}

		$justification    = trim( (string) ( $details['justification'] ?? '' ) );
		$impact_statement = trim( (string) ( $details['impact_statement'] ?? '' ) );
		$action_statement = trim( (string) ( $details['action_statement'] ?? '' ) );

		if ( 'not_affected' === $status ) {
			if ( '' !== $justification && ! in_array( $justification, self::JUSTIFICATIONS, true ) ) {
				return [ 'saved' => false, 'error' => __( 'Die Begründung ist keine der fünf im VEX-Katalog definierten.', 'wm-cra-sbom-beacon' ) ];
			}
			// The specification requires one of the two. Storing a bare "not affected" would publish
			// an assertion nobody can check, which is the opposite of what VEX is for.
			if ( '' === $justification && '' === $impact_statement ) {
				return [ 'saved' => false, 'error' => __( '„nicht betroffen“ verlangt eine Begründung aus dem Katalog oder eine Erklärung im Klartext.', 'wm-cra-sbom-beacon' ) ];
			}
		}

		if ( 'affected' === $status && '' === $action_statement ) {
			return [ 'saved' => false, 'error' => __( '„betroffen“ verlangt eine Angabe, was dagegen zu tun ist.', 'wm-cra-sbom-beacon' ) ];
		}

		$statements = self::statements();
		$key        = self::key( $purl, $vulnerability );
		$now        = gmdate( 'Y-m-d\TH:i:s\Z' );
		$previous   = $statements[ $key ] ?? null;

		$statement = [
			'purl'          => $purl,
			'vulnerability' => $vulnerability,
			'status'        => $status,
			'first_issued'  => (string) ( $previous['first_issued'] ?? $now ),
			'last_updated'  => $now,
			// A statement carries its own version, incremented on every change, so a consumer can
			// tell a restatement from the original.
			'version'       => null === $previous ? 1 : (int) ( $previous['version'] ?? 1 ) + 1,
		];
		foreach ( [ 'justification' => $justification, 'impact_statement' => $impact_statement, 'action_statement' => $action_statement, 'status_notes' => trim( (string) ( $details['status_notes'] ?? '' ) ) ] as $field => $value ) {
			if ( '' !== $value ) {
				$statement[ $field ] = $value;
			}
		}

		$statements[ $key ] = $statement;
		update_option( self::OPT_STATEMENTS, $statements, false );
		self::bump_version();

		return [ 'saved' => true, 'error' => null ];
	}

	/**
	 * The stored statements.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function statements(): array {
		$stored = get_option( self::OPT_STATEMENTS, [] );

		return is_array( $stored ) ? $stored : [];
	}

	public static function key( string $purl, string $vulnerability ): string {
		return $purl . '|' . $vulnerability;
	}

	/**
	 * The document version, which the specification requires to change whenever the content does.
	 *
	 * The stored value counts the changes; the version is that count plus one, so the document that
	 * exists before anybody has said anything is version 1 and the first statement makes it 2.
	 * Measured on a local WordPress install 2026-09-16: reading the stored counter directly made an empty document
	 * and a one-statement document both report version 1 — the content had changed and the version
	 * had not, which is the one thing the field is for.
	 */
	public static function bump_version(): int {
		$changes = (int) get_option( self::OPT_VERSION, 0 ) + 1;
		update_option( self::OPT_VERSION, $changes, false );

		return self::version();
	}

	/** The version the document reports. */
	public static function version(): int {
		return 1 + max( 0, (int) get_option( self::OPT_VERSION, 0 ) );
	}

	/**
	 * Build the document.
	 *
	 * @param array<string, array<string, mixed>>|null $audit_state Per-component state; read when null.
	 * @param list<array<string, mixed>>|null          $findings    Stored findings; read when null.
	 * @return array<string, mixed>
	 */
	public static function document( ?array $audit_state = null, ?array $findings = null ): array {
		$findings = $findings ?? VulnerabilityAudit::findings( 500 );
		$stored   = self::statements();
		$now      = gmdate( 'Y-m-d\TH:i:s\Z' );

		$statements = [];
		$covered    = [];

		// Everything the audit found, with the operator's position where there is one.
		foreach ( $findings as $finding ) {
			$purl          = (string) ( $finding['component_purl'] ?? '' );
			$vulnerability = (string) ( $finding['cve_id'] ?? '' );
			if ( '' === $vulnerability ) {
				$vulnerability = (string) ( $finding['advisory_id'] ?? '' );
			}
			if ( '' === $purl || '' === $vulnerability ) {
				continue;
			}

			$key             = self::key( $purl, $vulnerability );
			$covered[ $key ] = true;
			$statements[]    = self::statement(
				$stored[ $key ] ?? [
					'purl'          => $purl,
					'vulnerability' => $vulnerability,
					// Nobody has assessed this yet, and that is a thing VEX has a label for.
					'status'        => 'under_investigation',
					'first_issued'  => $now,
					'last_updated'  => $now,
					'version'       => 1,
				],
				(string) ( $finding['summary'] ?? '' )
			);
		}

		// Statements about vulnerabilities the audit no longer reports — a fixed component, for
		// instance — stay in the document: withdrawing them would leave a consumer with the old
		// finding and no answer.
		foreach ( $stored as $key => $statement ) {
			if ( ! isset( $covered[ $key ] ) ) {
				$statements[] = self::statement( $statement, '' );
			}
		}

		return [
			'@context'  => self::CONTEXT,
			'@id'       => self::document_iri(),
			'author'    => self::author(),
			'timestamp' => $now,
			'version'   => self::version(),
			'tooling'   => 'pkg:generic/wm-cra-sbom-beacon@' . ( defined( 'WM_CRA_VERSION' ) ? WM_CRA_VERSION : '0.0.0' ),
			'statements' => $statements,
		];
	}

	/**
	 * One stored statement in the document's shape.
	 *
	 * @param array<string, mixed> $statement Stored statement.
	 * @return array<string, mixed>
	 */
	public static function statement( array $statement, string $description ): array {
		$vulnerability = [ 'name' => (string) $statement['vulnerability'] ];
		if ( str_starts_with( (string) $statement['vulnerability'], 'CVE-' ) ) {
			$vulnerability['@id'] = 'https://nvd.nist.gov/vuln/detail/' . rawurlencode( (string) $statement['vulnerability'] );
		}
		if ( '' !== trim( $description ) ) {
			$vulnerability['description'] = trim( $description );
		}

		$out = [
			'vulnerability' => $vulnerability,
			'products'      => [ [ '@id' => (string) $statement['purl'] ] ],
			'status'        => (string) $statement['status'],
			'timestamp'     => (string) ( $statement['first_issued'] ?? gmdate( 'Y-m-d\TH:i:s\Z' ) ),
			'last_updated'  => (string) ( $statement['last_updated'] ?? gmdate( 'Y-m-d\TH:i:s\Z' ) ),
			'version'       => (int) ( $statement['version'] ?? 1 ),
		];

		foreach ( [ 'justification', 'impact_statement', 'action_statement', 'status_notes' ] as $field ) {
			if ( '' !== trim( (string) ( $statement[ $field ] ?? '' ) ) ) {
				$out[ $field ] = trim( (string) $statement[ $field ] );
			}
		}

		return $out;
	}

	/** The document IRI; it changes with the version, because the content does. */
	public static function document_iri(): string {
		return rtrim( (string) home_url( '/' ), '/' ) . '/vex/' . self::version();
	}

	/**
	 * The author.
	 *
	 * The specification wants a machine-readable identifier of an individual or organisation. The
	 * security contact the operator already confirmed for security.txt is the one identity this
	 * plugin holds; without it the site URL stands in, and the document says so rather than naming
	 * somebody who never agreed to be named.
	 */
	public static function author(): string {
		$contact = trim( (string) get_option( \WMCyber\CRA\Beacon\SecurityTxtHandler::OPT_CONTACT, '' ) );
		$confirmed = '' !== trim( (string) get_option( \WMCyber\CRA\Beacon\SecurityTxtHandler::OPT_CONFIRMED, '' ) );

		if ( $confirmed && '' !== $contact ) {
			return $contact;
		}

		return rtrim( (string) home_url( '/' ), '/' );
	}
}
