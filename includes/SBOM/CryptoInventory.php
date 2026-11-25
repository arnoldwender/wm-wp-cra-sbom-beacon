<?php
declare(strict_types=1);

namespace WMCyber\CRA\SBOM;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The cryptographic bill of materials (CBOM): which algorithms and protocol versions this host can
 * actually perform, as CycloneDX 1.6 `cryptographic-asset` components.
 *
 * The point of a CBOM is not to prove that strong cryptography is available; it is to make the weak
 * cryptography that is still available visible — MD5 and SHA-1 are in `hash_algos()` on every stock
 * PHP, and DES and RC4 in `openssl_get_cipher_methods()` on many. An inventory that omitted them
 * would answer the opposite of the question.
 *
 * Off by default (`wm_cra_sbom_include_crypto`): measured on a stock PHP 8.3 with OpenSSL 3.5, this
 * adds 60 hash algorithms and 126 cipher methods to a document that otherwise holds a few dozen
 * components, and most consumers of an SBOM want the software inventory.
 *
 * Every enum value below comes from the CycloneDX 1.6 JSON schema (`cryptoProperties`,
 * `algorithmProperties.primitive`, `.mode`, `.cryptoFunctions`, `protocolProperties.type`), read
 * from the published schema on 2026-09-16 rather than recalled.
 */
final class CryptoInventory {

	/** The setting that turns the CBOM on. */
	public const OPT_INCLUDE = 'wm_cra_sbom_include_crypto';

	/** Extendable-output functions are their own primitive in CycloneDX, not hashes. */
	public const XOF_PREFIXES = [ 'shake' ];

	/** Checksums, not cryptographic hashes: claiming "hash" for crc32 would overstate what they are. */
	public const NON_CRYPTOGRAPHIC = [ 'crc32', 'crc32b', 'crc32c', 'adler32', 'fnv', 'joaat', 'murmur', 'xxh' ];

	/** Suffixes of a cipher method name that name a mode of operation. */
	public const MODES = [ 'cbc', 'ecb', 'ccm', 'gcm', 'cfb', 'ofb', 'ctr' ];

	/** Modes that authenticate as well as encrypt, so the primitive is authenticated encryption. */
	public const AEAD_MODES = [ 'gcm', 'ccm' ];

	/**
	 * Whether the CBOM is part of the document.
	 *
	 * The filter is what `wp cra sbom-generate --crypto` uses, so a one-off run and the setting go
	 * through the same decision and cannot produce two different documents.
	 */
	public static function enabled(): bool {
		return (bool) \apply_filters( self::OPT_INCLUDE, (bool) \get_option( self::OPT_INCLUDE, 0 ) );
	}

	/**
	 * Components for every algorithm and protocol version the host offers.
	 *
	 * @param array<string, mixed> $measured Overrides, so the suite can describe a host it is not running on.
	 * @return list<array<string, mixed>>
	 */
	public static function components( array $measured = [] ): array {
		$hashes   = $measured['hashes'] ?? ( function_exists( 'hash_algos' ) ? hash_algos() : [] );
		$ciphers  = $measured['ciphers'] ?? ( function_exists( 'openssl_get_cipher_methods' ) ? openssl_get_cipher_methods() : [] );
		$tls      = $measured['tls'] ?? self::tls_versions();
		$provider = (string) ( $measured['openssl'] ?? ( defined( 'OPENSSL_VERSION_TEXT' ) ? OPENSSL_VERSION_TEXT : '' ) );

		$components = [];

		if ( '' !== $provider ) {
			$version      = 1 === preg_match( '/(\d+\.\d+(?:\.\d+)?[a-z]?)/', $provider, $match ) ? $match[1] : '';
			$component    = [
				'type'        => 'library',
				'name'        => 'openssl',
				'purl'        => 'pkg:generic/openssl' . ( '' !== $version ? '@' . rawurlencode( $version ) : '' ),
				'description' => trim( $provider ),
			];
			if ( '' !== $version ) {
				$component['version'] = $version;
			}
			$components[] = $component;
		}

		foreach ( self::unique_lower( (array) $hashes ) as $algorithm ) {
			$components[] = self::hash_component( $algorithm );
		}

		foreach ( self::unique_lower( (array) $ciphers ) as $method ) {
			$components[] = self::cipher_component( $method );
		}

		foreach ( (array) $tls as $version ) {
			$components[] = self::tls_component( (string) $version );
		}

		return $components;
	}

	/**
	 * TLS versions the HTTP client can negotiate, as the linked library reports them.
	 *
	 * @return list<string>
	 */
	public static function tls_versions(): array {
		if ( ! function_exists( 'curl_version' ) ) {
			return [];
		}
		$curl = curl_version();
		if ( ! is_array( $curl ) || '' === (string) ( $curl['ssl_version'] ?? '' ) ) {
			return [];
		}

		// cURL does not enumerate the versions it will negotiate, so only what the constants prove
		// this build knows is listed. A version the build cannot request is not in the inventory.
		$versions = [];
		if ( defined( 'CURL_SSLVERSION_TLSv1_2' ) ) {
			$versions[] = '1.2';
		}
		if ( defined( 'CURL_SSLVERSION_TLSv1_3' ) ) {
			$versions[] = '1.3';
		}

		return $versions;
	}

	/**
	 * @return array<string, mixed>
	 */
	public static function hash_component( string $algorithm ): array {
		return [
			'type'             => 'cryptographic-asset',
			'name'             => $algorithm,
			'purl'             => 'pkg:generic/algorithm/' . rawurlencode( $algorithm ),
			'cryptoProperties' => [
				'assetType'           => 'algorithm',
				'algorithmProperties' => array_filter( [
					'primitive'              => self::hash_primitive( $algorithm ),
					'parameterSetIdentifier' => self::bit_length( $algorithm ),
					'executionEnvironment'   => 'software-plain-ram',
					'implementationPlatform' => 'generic',
					'cryptoFunctions'        => [ 'digest' ],
				] ),
			],
		];
	}

	/**
	 * @return array<string, mixed>
	 */
	public static function cipher_component( string $method ): array {
		$mode = self::cipher_mode( $method );

		return [
			'type'             => 'cryptographic-asset',
			'name'             => $method,
			'purl'             => 'pkg:generic/algorithm/' . rawurlencode( $method ),
			'cryptoProperties' => [
				'assetType'           => 'algorithm',
				'algorithmProperties' => array_filter( [
					'primitive'              => self::cipher_primitive( $method, $mode ),
					'parameterSetIdentifier' => self::bit_length( $method ),
					'mode'                   => $mode,
					'executionEnvironment'   => 'software-plain-ram',
					'implementationPlatform' => 'generic',
					'cryptoFunctions'        => [ 'encrypt', 'decrypt' ],
				] ),
			],
		];
	}

	/**
	 * @return array<string, mixed>
	 */
	public static function tls_component( string $version ): array {
		return [
			'type'             => 'cryptographic-asset',
			'name'             => 'TLS ' . $version,
			'purl'             => 'pkg:generic/protocol/tls@' . rawurlencode( $version ),
			'cryptoProperties' => [
				'assetType'          => 'protocol',
				'protocolProperties' => [
					'type'    => 'tls',
					'version' => $version,
				],
			],
		];
	}

	/** Extendable-output functions, checksums and everything else the schema calls a hash. */
	public static function hash_primitive( string $algorithm ): string {
		foreach ( self::XOF_PREFIXES as $prefix ) {
			if ( str_starts_with( $algorithm, $prefix ) ) {
				return 'xof';
			}
		}
		foreach ( self::NON_CRYPTOGRAPHIC as $prefix ) {
			if ( str_starts_with( $algorithm, $prefix ) ) {
				return 'other';
			}
		}

		return 'hash';
	}

	/** A mode that authenticates makes the primitive authenticated encryption, not a block cipher. */
	public static function cipher_primitive( string $method, string $mode ): string {
		if ( in_array( $mode, self::AEAD_MODES, true ) || str_contains( $method, 'poly1305' ) ) {
			return 'ae';
		}
		if ( str_starts_with( $method, 'rc4' ) || str_starts_with( $method, 'chacha' ) ) {
			return 'stream-cipher';
		}

		return 'block-cipher';
	}

	/** The mode named in a method such as "aes-256-gcm"; '' when the name states none. */
	public static function cipher_mode( string $method ): string {
		$parts = preg_split( '/[-_]/', $method ) ?: [];
		foreach ( array_reverse( $parts ) as $part ) {
			$part = strtolower( (string) $part );
			// "cfb1", "cfb8", "ofb128".
			$base = (string) preg_replace( '/\d+$/', '', $part );
			if ( in_array( $base, self::MODES, true ) ) {
				return $base;
			}
		}

		return '';
	}

	/**
	 * The key or digest length the name states, as CycloneDX's parameterSetIdentifier.
	 *
	 * Only a number that is part of the name is used. Deriving a length for a name that does not
	 * carry one would be inventing a property of somebody else's algorithm.
	 */
	public static function bit_length( string $name ): string {
		if ( 1 === preg_match( '/(?:^|[-_])(\d{3,4})(?:$|[-_])/', $name, $match ) ) {
			return $match[1];
		}
		if ( 1 === preg_match( '/^(?:sha|md|blake)\d?-?(\d{3})$/', $name, $match ) ) {
			return $match[1];
		}

		return '';
	}

	/**
	 * @param array<int, mixed> $values Raw list.
	 * @return list<string>
	 */
	private static function unique_lower( array $values ): array {
		$clean = [];
		foreach ( $values as $value ) {
			$value = strtolower( trim( (string) $value ) );
			if ( '' !== $value ) {
				$clean[ $value ] = true;
			}
		}
		$list = array_keys( $clean );
		sort( $list );

		return $list;
	}
}
