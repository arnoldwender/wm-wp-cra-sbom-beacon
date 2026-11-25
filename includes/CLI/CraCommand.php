<?php
declare(strict_types=1);

namespace WMCyber\CRA\CLI;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_CLI;
use WP_CLI_Command;
use WMCyber\CRA\Core\Plugin;
use WMCyber\CRA\SBOM\CycloneDxGenerator;
use WMCyber\CRA\SPDX\Spdx3Generator;
use WMCyber\CRA\Vuln\OpenVexEngine;
use WMCyber\CRA\Vuln\VulnerabilityAudit;

final class CraCommand extends WP_CLI_Command {
	public static function register(): void {
		WP_CLI::add_command( 'cra', self::class );
	}

	/**
	 * Print or write a CycloneDX 1.6 inventory of the active code.
	 *
	 * Without --output the JSON goes to STDOUT and nothing else does, so it can be piped.
	 *
	 * ## OPTIONS
	 *
	 * [--output=<file>]
	 * : Write the JSON to this file instead of STDOUT.
	 *
	 * [--snapshot]
	 * : Also store the SBOM as a snapshot in the database.
	 *
	 * [--crypto]
	 * : Include the cryptographic bill of materials for this run (around 186 further components on a stock PHP 8.3 with OpenSSL 3.5).
	 *
	 * ## EXAMPLES
	 *
	 *     wp cra sbom-generate --output=/tmp/cyclonedx-sbom.json
	 *     wp cra sbom-generate | jq '.components | length'
	 *     wp cra sbom-generate --crypto | jq '[.components[] | select(.type == "cryptographic-asset")] | length'
	 *
	 * @subcommand sbom-generate
	 */
	public function sbom_generate( array $args, array $assoc_args ): void {
		$generator = Plugin::instance()->get_sbom_generator();

		// A flag for one run, through the same filter the setting feeds, so the CLI and the screen
		// cannot drift into producing different documents.
		if ( ! empty( $assoc_args['crypto'] ) ) {
			add_filter( 'wm_cra_sbom_include_crypto', '__return_true' );
		}

		$sbom = $generator->generate_sbom();
		$json = CycloneDxGenerator::serialize( $sbom );

		if ( ! empty( $assoc_args['snapshot'] ) ) {
			$snapshot = $generator->save_snapshot( $sbom );
			if ( ! $snapshot['saved'] ) {
				WP_CLI::error( 'The snapshot could not be stored (does the table wm_cra_sbom_snapshots exist?).' );
			}
			// Debug channel (STDERR), so a JSON pipe on STDOUT stays valid.
			WP_CLI::debug( sprintf( 'Snapshot %d stored: %d components, SHA-256 %s', $snapshot['snapshot_id'], $snapshot['components_count'], $snapshot['sha256'] ), 'cra' );
		}

		$output_file = isset( $assoc_args['output'] ) ? (string) $assoc_args['output'] : '';
		if ( '' === $output_file ) {
			WP_CLI::line( $json );
			return;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- CLI export to a path the operator names.
		$written = @file_put_contents( $output_file, $json . "\n" );
		if ( false === $written ) {
			WP_CLI::error( sprintf( 'Could not write %s.', $output_file ) );
		}
		WP_CLI::success( sprintf( 'CycloneDX 1.6 SBOM with %d components written to %s.', count( $sbom['components'] ), $output_file ) );
	}

	/**
	 * Check the inventory against the vulnerability databases that hold data for it.
	 *
	 * Composer and npm packages go to OSV in one batch; WordPress components go to NVD, which is
	 * rate limited, so a run takes a budget and the cursor remembers where it stopped. Exits with
	 * status 1 when a component is affected.
	 *
	 * ## OPTIONS
	 *
	 * [--all]
	 * : Keep going until every WordPress component has been checked once, pausing for the rate limit (minutes, not seconds).
	 *
	 * ## EXAMPLES
	 *
	 *     wp cra vuln-scan
	 *     wp cra vuln-scan --all
	 *
	 * @subcommand vuln-scan
	 */
	public function vuln_scan( $args, $assoc_args ) {
		$audit = new VulnerabilityAudit( Plugin::instance()->get_sbom_generator() );

		WP_CLI::line( 'Gleiche die Software-Liste gegen OSV und NVD ab ...' );

		$summary = $audit->run( 'cli' );

		// --all keeps running passes until the cursor has been all the way round. Each pass is one
		// budget; nothing is skipped and the rate limit is still respected between requests.
		if ( ! empty( $assoc_args['all'] ) ) {
			$passes = 0;
			while ( $summary['counts'][ VulnerabilityAudit::STATE_NEVER_CHECKED ] > 0 && $passes < 50 ) {
				++$passes;
				$summary = $audit->run( 'cli' );
			}
		}

		WP_CLI::line( sprintf(
			'%d Komponenten erfasst, %d in diesem Lauf geprüft (%d WordPress-Komponenten insgesamt).',
			(int) $summary['components'],
			(int) $summary['checked_this_run'],
			(int) $summary['wordpress_total']
		) );

		foreach ( [
			VulnerabilityAudit::STATE_CHECKED         => 'geprüft',
			VulnerabilityAudit::STATE_NEVER_CHECKED   => 'noch nie geprüft',
			VulnerabilityAudit::STATE_UNKNOWN_VERSION => 'Version unbekannt',
			VulnerabilityAudit::STATE_SOURCE_ERROR    => 'Quelle nicht erreichbar',
		] as $state => $label ) {
			WP_CLI::line( sprintf( '  %-24s %d', $label . ':', (int) ( $summary['counts'][ $state ] ?? 0 ) ) );
		}

		foreach ( array_slice( VulnerabilityAudit::findings(), 0, 25 ) as $row ) {
			WP_CLI::line( sprintf(
				'  %s  %s  %s  %s',
				(string) $row['component_purl'],
				'' !== (string) $row['cve_id'] ? (string) $row['cve_id'] : (string) $row['advisory_id'],
				'' !== (string) $row['severity'] ? strtoupper( (string) $row['severity'] ) : '-',
				null !== $row['cvss_score'] ? (string) $row['cvss_score'] : '-'
			) );
		}

		if ( ! $summary['complete'] ) {
			WP_CLI::warning( 'Noch nicht jede Komponente wurde geprüft. Eine nicht geprüfte Komponente ist keine unauffällige Komponente.' );
		}

		if ( (int) $summary['findings'] > 0 ) {
			WP_CLI::error( sprintf( '%d Treffer für installierte Versionen.', (int) $summary['findings'] ) );
		}

		WP_CLI::success( 'Keine Treffer für die geprüften Komponenten und ihre installierten Versionen.' );
	}

	/**
	 * Print the inventory as SPDX 3.0.1 JSON-LD.
	 *
	 * The same measurement as sbom-generate, in the format procurement asks for.
	 *
	 * ## OPTIONS
	 *
	 * [--output=<file>]
	 * : Write the JSON to this file instead of STDOUT.
	 *
	 * ## EXAMPLES
	 *
	 *     wp cra spdx-generate | jq '[."@graph"[] | select(.type == "software_Package")] | length'
	 *
	 * @subcommand spdx-generate
	 */
	public function spdx_generate( array $args, array $assoc_args ): void {
		$document = ( new Spdx3Generator() )->generate( Plugin::instance()->get_sbom_generator()->generate_sbom() );
		$json     = Spdx3Generator::serialize( $document );

		$output_file = isset( $assoc_args['output'] ) ? (string) $assoc_args['output'] : '';
		if ( '' === $output_file ) {
			WP_CLI::line( $json );
			return;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- CLI export to a path the operator names.
		if ( false === @file_put_contents( $output_file, $json . "\n" ) ) {
			WP_CLI::error( sprintf( 'Could not write %s.', $output_file ) );
		}
		WP_CLI::success( sprintf( 'SPDX %s document written to %s.', Spdx3Generator::SPEC_VERSION, $output_file ) );
	}

	/**
	 * Record the site's position on one vulnerability, or print the OpenVEX document.
	 *
	 * Without --status the command prints the document. A finding nobody has assessed is published as
	 * under_investigation; not_affected and affected are only ever written because you wrote them.
	 *
	 * ## OPTIONS
	 *
	 * [<purl>]
	 * : The affected component, by its package URL as the SBOM lists it.
	 *
	 * [<vulnerability>]
	 * : CVE or advisory id.
	 *
	 * [--status=<status>]
	 * : The VEX status.
	 * ---
	 * options:
	 *   - not_affected
	 *   - affected
	 *   - fixed
	 *   - under_investigation
	 * ---
	 *
	 * [--justification=<label>]
	 * : For not_affected, one of the five VEX justification labels.
	 *
	 * [--impact-statement=<text>]
	 * : For not_affected, a free-text explanation instead of a justification label.
	 *
	 * [--action-statement=<text>]
	 * : For affected, what is to be done about it. Required for that status.
	 *
	 * [--notes=<text>]
	 * : How the status was determined.
	 *
	 * ## EXAMPLES
	 *
	 *     wp cra vex
	 *     wp cra vex "pkg:composer/monolog/monolog@3.5.0" CVE-2099-0001 --status=not_affected --justification=vulnerable_code_not_in_execute_path
	 *     wp cra vex "pkg:generic/wordpress-plugin/x@1.0" CVE-2099-0002 --status=affected --action-statement="Update to 1.1"
	 *
	 * @subcommand vex
	 */
	public function vex( $args, $assoc_args ) {
		$status = (string) ( $assoc_args['status'] ?? '' );

		if ( '' === $status ) {
			WP_CLI::line( (string) wp_json_encode( OpenVexEngine::document(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) );
			return;
		}

		$result = OpenVexEngine::record(
			(string) ( $args[0] ?? '' ),
			(string) ( $args[1] ?? '' ),
			$status,
			[
				'justification'    => (string) ( $assoc_args['justification'] ?? '' ),
				'impact_statement' => (string) ( $assoc_args['impact-statement'] ?? '' ),
				'action_statement' => (string) ( $assoc_args['action-statement'] ?? '' ),
				'status_notes'     => (string) ( $assoc_args['notes'] ?? '' ),
			]
		);

		if ( ! $result['saved'] ) {
			WP_CLI::error( (string) $result['error'] );
		}

		WP_CLI::success( sprintf( 'VEX statement recorded: %s is %s for %s.', (string) $args[0], $status, (string) $args[1] ) );
	}

	/**
	 * Print the security.txt the site serves.
	 *
	 * ## EXAMPLES
	 *
	 *     wp cra security-txt
	 *
	 * @subcommand security-txt
	 */
	public function security_txt( array $args, array $assoc_args ): void {
		$handler = Plugin::instance()->get_security_txt();
		WP_CLI::line( rtrim( $handler->generate_security_txt_content(), "\n" ) );

		$status = $handler->status();
		if ( 'ok' !== $status['state'] ) {
			WP_CLI::warning( sprintf( 'security.txt state: %s.', $status['state'] ) );
		}
	}

	/**
	 * Publish or update an advisory as a CSAF 2.0 document (base profile).
	 *
	 * Nothing is filled in for you: without --cve the document names no CVE, and no CVSS score is written.
	 *
	 * ## OPTIONS
	 *
	 * <tracking_id>
	 * : The advisory tracking ID (e.g. WM-2026-001). Publishing the same id again updates it.
	 *
	 * --title=<title>
	 * : Advisory title.
	 *
	 * --severity=<severity>
	 * : Severity as stated by you.
	 * ---
	 * options:
	 *   - low
	 *   - medium
	 *   - high
	 *   - critical
	 * ---
	 *
	 * [--cve=<cve>]
	 * : CVE id, if one was assigned.
	 *
	 * [--description=<text>]
	 * : Description of the vulnerability.
	 *
	 * ## EXAMPLES
	 *
	 *     wp cra csaf-publish WM-2026-001 --title="Stored XSS in the contact form" --severity=high --cve=CVE-2026-12345
	 *
	 * @subcommand csaf-publish
	 */
	public function csaf_publish( array $args, array $assoc_args ): void {
		$result = Plugin::instance()->get_csaf_publisher()->publish_advisory(
			(string) ( $args[0] ?? '' ),
			(string) ( $assoc_args['title'] ?? '' ),
			(string) ( $assoc_args['severity'] ?? '' ),
			[
				'cve'         => (string) ( $assoc_args['cve'] ?? '' ),
				'description' => (string) ( $assoc_args['description'] ?? '' ),
			]
		);

		if ( ! $result['saved'] ) {
			WP_CLI::error( $result['error'] );
		}
		WP_CLI::success( sprintf(
			'Advisory %s stored (version %s).',
			$result['document']['document']['tracking']['id'],
			$result['document']['document']['tracking']['version']
		) );
	}
}
