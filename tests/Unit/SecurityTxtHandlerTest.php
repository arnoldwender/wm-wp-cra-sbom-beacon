<?php
declare(strict_types=1);

namespace WMCyber\CRA\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WMCyber\CRA\Beacon\SecurityTxtHandler;

final class SecurityTxtHandlerTest extends TestCase {
	private SecurityTxtHandler $handler;

	protected function setUp(): void {
		parent::setUp();
		$this->handler = new SecurityTxtHandler();
	}

	public function test_generate_security_txt_conformance(): void {
		global $mock_options;
		$mock_options = array(
			'wm_cra_security_txt_contact' => 'mailto:security@example.test',
			'wm_cra_security_txt_expires' => '2027-01-31T23:59:59Z',
			'wm_cra_security_txt_policy'  => 'https://example.test/policy',
		);
		$content = $this->handler->generate_security_txt_content();

		$this->assertStringContainsString( 'Contact: mailto:security@example.test', $content );
		$this->assertStringContainsString( 'Expires: 2027-01-31T23:59:59Z', $content );
		$this->assertStringContainsString( 'Canonical: ', $content );
		$this->assertStringContainsString( 'Policy: https://example.test/policy', $content );
		// CSAF must point to a provider-metadata.json, which the plugin does not publish; SBOM is not a field.
		$this->assertDoesNotMatchRegularExpression( '/^(CSAF|SBOM):/m', $content );
	}
}
