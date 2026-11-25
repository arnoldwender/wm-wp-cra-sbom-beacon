<?php
declare(strict_types=1);

namespace WMCyber\CRA\SPDX;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WMCyber\CRA\SBOM\CycloneDxGenerator;

/**
 * Serialises the same inventory as SPDX 3.0.1 JSON-LD.
 *
 * One inventory, two wire formats: procurement asks for SPDX, security tooling for CycloneDX, and a
 * document that disagreed with its sibling would be worse than not shipping one. Everything here is
 * a translation of what `CycloneDxGenerator` already measured — nothing is gathered a second time
 * and nothing is added that the CycloneDX document does not contain.
 *
 * **Every term name below was read from the published SPDX 3.0.1 context and vocabularies on
 * 2026-09-16, not recalled.** SPDX 3 renamed almost everything that SPDX 2 users know: the class is
 * `software_Package`, not `Package` (which does not exist in the context at all), the version is
 * `software_packageVersion`, and the relationship, identifier and purpose values are vocabulary
 * entries. Writing SPDX 2 names here would produce a document that validates against nothing.
 */
final class Spdx3Generator {

	/** The context, verified to resolve (36 KB of term definitions). */
	public const CONTEXT = 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld';

	public const SPEC_VERSION = '3.0.1';

	/** SPDX requires a licence for the document's own data; CC0-1.0 is what the spec names. */
	public const DATA_LICENCE = 'https://spdx.org/licenses/CC0-1.0';

	/**
	 * CycloneDX component type to SPDX SoftwarePurpose.
	 *
	 * Both vocabularies were read from their specifications; a type without an equivalent becomes
	 * `other`, which is a defined entry, rather than being left out or guessed at.
	 */
	public const PURPOSE = [
		'application'         => 'application',
		'framework'           => 'framework',
		'library'             => 'library',
		'container'           => 'container',
		'platform'            => 'platform',
		'operating-system'    => 'operatingSystem',
		'device'              => 'device',
		'device-driver'       => 'deviceDriver',
		'firmware'            => 'firmware',
		'file'                => 'file',
		'data'                => 'data',
		'cryptographic-asset' => 'other',
	];

	/**
	 * The whole document.
	 *
	 * @param array<string, mixed>|null $sbom A CycloneDX document; generated when null.
	 * @return array<string, mixed>
	 */
	public function generate( ?array $sbom = null ): array {
		$sbom = $sbom ?? ( new CycloneDxGenerator() )->generate_sbom();

		$namespace = self::namespace_iri();
		$created   = gmdate( 'Y-m-d\TH:i:s\Z' );

		$creation_info = [
			'type'        => 'CreationInfo',
			'@id'         => '_:creationInfo',
			'specVersion' => self::SPEC_VERSION,
			'created'     => $created,
			'createdBy'   => [ $namespace . 'Agent-wm-suite' ],
			'createdUsing' => [ $namespace . 'Tool-wm-cra-sbom-beacon' ],
		];

		$graph = [
			[
				'type'         => 'Organization',
				'spdxId'       => $namespace . 'Agent-wm-suite',
				'creationInfo' => '_:creationInfo',
				'name'         => 'WM Suite',
			],
			[
				'type'                    => 'Tool',
				'spdxId'                  => $namespace . 'Tool-wm-cra-sbom-beacon',
				'creationInfo'            => '_:creationInfo',
				'name'                    => 'WM CRA SBOM & Vulnerability Beacon',
				'software_packageVersion' => defined( 'WM_CRA_VERSION' ) ? (string) WM_CRA_VERSION : '0.0.0',
			],
		];

		$root_id  = $namespace . 'Package-site';
		$graph[]  = [
			'type'                   => 'software_Package',
			'spdxId'                 => $root_id,
			'creationInfo'           => '_:creationInfo',
			'name'                   => (string) ( $sbom['metadata']['component']['name'] ?? 'WordPress site' ),
			'software_primaryPurpose' => 'application',
		];

		$package_ids = [];
		foreach ( (array) ( $sbom['components'] ?? [] ) as $index => $component ) {
			$package         = self::package( (array) $component, $namespace, $index );
			$graph[]         = $package;
			$package_ids[]   = $package['spdxId'];
		}

		// One relationship naming every component, rather than one relationship each: the graph says
		// the same thing and stays readable on a site with three hundred packages.
		if ( [] !== $package_ids ) {
			$graph[] = [
				'type'             => 'Relationship',
				'spdxId'           => $namespace . 'Relationship-contains',
				'creationInfo'     => '_:creationInfo',
				'from'             => $root_id,
				'to'               => $package_ids,
				'relationshipType' => 'contains',
			];
		}

		$graph[] = [
			'type'             => 'software_Sbom',
			'spdxId'           => $namespace . 'Sbom',
			'creationInfo'     => '_:creationInfo',
			// "deployed": this is the software as it is installed and running on this site, which is
			// what the plugin can see. It is not a build or a design inventory.
			'software_sbomType' => [ 'deployed' ],
			'rootElement'      => [ $root_id ],
			'element'          => $package_ids,
		];

		return [
			'@context' => self::CONTEXT,
			'@graph'   => array_merge(
				[
					[
						'type'               => 'SpdxDocument',
						'spdxId'             => $namespace . 'Document',
						'creationInfo'       => '_:creationInfo',
						'name'               => 'SBOM of ' . (string) ( $sbom['metadata']['component']['name'] ?? 'WordPress site' ),
						'dataLicense'        => self::DATA_LICENCE,
						'profileConformance' => [ 'core', 'software' ],
						'rootElement'        => [ $namespace . 'Sbom' ],
					],
					$creation_info,
				],
				$graph
			),
		];
	}

	/**
	 * One CycloneDX component as an SPDX package.
	 *
	 * @param array<string, mixed> $component CycloneDX component.
	 * @return array<string, mixed>
	 */
	public static function package( array $component, string $namespace, int $index ): array {
		$name = (string) ( $component['name'] ?? '' );

		$package = [
			'type'                    => 'software_Package',
			'spdxId'                  => $namespace . 'Package-' . self::slug( $name, $index ),
			'creationInfo'            => '_:creationInfo',
			'name'                    => '' !== $name ? $name : 'component-' . $index,
			'software_primaryPurpose' => self::PURPOSE[ (string) ( $component['type'] ?? '' ) ] ?? 'other',
		];

		// A version the inventory does not have stays absent here too. SPDX has no placeholder that
		// means "we did not find out", and inventing one would make this document disagree with its
		// CycloneDX sibling, which is the one thing a second format must never do.
		$version = trim( (string) ( $component['version'] ?? '' ) );
		if ( '' !== $version ) {
			$package['software_packageVersion'] = $version;
		}

		$purl = trim( (string) ( $component['purl'] ?? '' ) );
		if ( '' !== $purl ) {
			$package['software_packageUrl'] = $purl;
			$package['externalIdentifier']  = [
				[
					'type'                   => 'ExternalIdentifier',
					'externalIdentifierType' => 'packageUrl',
					'identifier'             => $purl,
				],
			];
		}

		$description = trim( (string) ( $component['description'] ?? '' ) );
		if ( '' !== $description ) {
			$package['description'] = $description;
		}

		// CycloneDX carries the licence as free text taken from a file header, which is not an SPDX
		// identifier. It goes into `comment`, where free text belongs, instead of being asserted as
		// a declared licence the plugin cannot actually verify.
		$licence = (string) ( $component['licenses'][0]['license']['name'] ?? '' );
		if ( '' !== trim( $licence ) ) {
			$package['comment'] = 'Licence as stated in the component header: ' . trim( $licence );
		}

		return $package;
	}

	/** The document's IRI namespace: stable per site, so two runs produce comparable identifiers. */
	public static function namespace_iri(): string {
		return rtrim( (string) home_url( '/' ), '/' ) . '/spdx/';
	}

	/** An SPDX identifier fragment: letters, digits, dot and dash only. */
	public static function slug( string $name, int $index ): string {
		$slug = (string) preg_replace( '/[^A-Za-z0-9.\-]+/', '-', $name );
		$slug = trim( $slug, '-' );

		return '' === $slug ? 'component-' . $index : $slug . '-' . $index;
	}

	/** One serialisation, so a hash of the document means the same everywhere. */
	public static function serialize( array $document ): string {
		return (string) wp_json_encode( $document, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );
	}
}
