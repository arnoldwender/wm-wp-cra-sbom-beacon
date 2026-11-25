<?php
declare(strict_types=1);

namespace WMCyber\CRA\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WMCyber\CRA\SBOM\CycloneDxGenerator;

final class CycloneDxGeneratorTest extends TestCase {
	private CycloneDxGenerator $generator;

	protected function setUp(): void {
		parent::setUp();
		$this->generator = new CycloneDxGenerator();
	}

	public function test_generate_cyclonedx_sbom_structure(): void {
		$sbom = $this->generator->generate_sbom();

		$this->assertSame( 'CycloneDX', $sbom['bomFormat'] );
		$this->assertSame( '1.6', $sbom['specVersion'] );
		$this->assertArrayHasKey( 'metadata', $sbom );
		$this->assertArrayHasKey( 'components', $sbom );
		$this->assertNotEmpty( $sbom['components'] );

		// Core component: no hash (until 2026-09-15 it carried sha256 of the version string).
		$core = $sbom['components'][0];
		$this->assertSame( 'wordpress-core', $core['name'] );
		$this->assertArrayNotHasKey( 'hashes', $core );

		// No licence is invented for a plugin whose header states none.
		$this->assertStringNotContainsString( 'Proprietary', (string) json_encode( $sbom ) );
	}
}
