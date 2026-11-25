<?php
declare(strict_types=1);

namespace WMCyber\CRA\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WMCyber\CRA\SBOM\CycloneDxGenerator;
use WMCyber\CRA\CSAF\CsafPublisher;
use WMCyber\CRA\Beacon\SecurityTxtHandler;
use WMCyber\CRA\API\RestController;
use WMCyber\CRA\CLI\CraCommand;
use WMCyber\CRA\Admin\AdminDashboard;
use WMCyber\CRA\Frontend\PsirtPortal;

final class Plugin {
	private static ?Plugin $instance = null;
	private CycloneDxGenerator $sbom_generator;
	private CsafPublisher $csaf_publisher;
	private SecurityTxtHandler $security_txt;

	private function __construct() {
		$this->sbom_generator = new CycloneDxGenerator();
		$this->csaf_publisher = new CsafPublisher();
		$this->security_txt   = new SecurityTxtHandler();
	}

	public static function instance(): Plugin {
		if ( self::$instance === null ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public function boot(): void {
		\WMCyber\CRA\Database\Schema::maybe_upgrade();

		add_action( 'init', function (): void {
			load_plugin_textdomain(
				'wm-cra-sbom-beacon',
				false,
				dirname( plugin_basename( WM_CRA_FILE ) ) . '/languages'
			);
		} );

		// Until 2026-09-15 every request also ran DirectoryProtector (created uploads/wm-cra/sbom, which nothing writes
		// to) and RequestShield (logged "BLOCK" with the client IP for any GET/POST/cookie value containing a stream
		// wrapper, and blocked nothing). The plugin's REST routes take no parameters, so neither had a job; both
		// classes and three more that had no caller were removed.

		$this->security_txt->init();

		( new RestController( $this->sbom_generator, $this->security_txt, $this->csaf_publisher ) )->register_routes();

		if ( is_admin() ) {
			( new AdminDashboard( $this->sbom_generator, $this->security_txt, $this->csaf_publisher ) )->init();
		}

		// Initialize Frontend PSIRT Disclosure Portal
		( new PsirtPortal( $this->csaf_publisher, $this->security_txt ) )->init();

		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			CraCommand::register();
		}

		/**
		 * Fires after WM CRA SBOM & Vulnerability Beacon has initialized its services and hooks.
		 *
		 * @param Plugin $plugin Active plugin container instance.
		 */
		do_action( 'wm_cra_beacon_ready', $this );
	}

	public function get_sbom_generator(): CycloneDxGenerator {
		return $this->sbom_generator;
	}

	public function get_csaf_publisher(): CsafPublisher {
		return $this->csaf_publisher;
	}

	public function get_security_txt(): SecurityTxtHandler {
		return $this->security_txt;
	}
}
