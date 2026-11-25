<?php
/**
 * Mutations for tests/run-mutations.sh: each entry undoes one correction of 2026-09-15 with literal
 * [file, search, replace] replacements. The suite must report at least one failure for every entry.
 *
 * @package WMCyber\CRA
 */

declare(strict_types=1);

return [
	[
		'activation stores rules without the security.txt route again',
		[
			[ 'includes/Database/Schema.php', '( new SecurityTxtHandler() )->add_rewrite_rules();', '// rules not registered' ],
		],
	],
	[
		'deactivation flushes and stores the rule again',
		[
			[ 'includes/Database/Schema.php', 'delete_option( \'rewrite_rules\' );', 'flush_rewrite_rules();' ],
		],
	],
	[
		'the settings form writes wm_cra_settings, which the served file never reads',
		[
			[ 'includes/Admin/AdminDashboard.php', 'update_option( $option, $value );', 'update_option( \'wm_cra_settings\', $values );' ],
		],
	],
	[
		'invalid settings are written anyway',
		[
			[ 'includes/Admin/AdminDashboard.php', '$errors[] = $codes[ $option ];', 'unset( $codes[ $option ] );' ],
		],
	],
	[
		'any string is accepted as contact',
		[
			[ 'includes/Beacon/SecurityTxtHandler.php', 'if ( is_email( $value ) ) {', 'if ( true ) {' ],
		],
	],
	[
		'an Expires date in the past is accepted',
		[
			[ 'includes/Beacon/SecurityTxtHandler.php', 'if ( $ts <= $now || $ts > $now + YEAR_IN_SECONDS ) {', 'if ( $ts > $now + YEAR_IN_SECONDS ) {' ],
		],
	],
	[
		'an expired file is not reported as expired',
		[
			[ 'includes/Beacon/SecurityTxtHandler.php', 'if ( $ts <= $now ) {', 'if ( false ) {' ],
		],
	],
	[
		'a missing route is not reported',
		[
			[ 'includes/Beacon/SecurityTxtHandler.php', 'if ( ! $route ) {', 'if ( false ) {' ],
		],
	],
	[
		'sites activated before the fix keep the 404',
		[
			[ 'includes/Beacon/SecurityTxtHandler.php', 'if ( ! $this->route_stored() ) {', 'if ( false ) {' ],
		],
	],
	[
		'the served file points CSAF: at the plugin index again',
		[
			[ 'includes/Beacon/SecurityTxtHandler.php', '\'# Advisory index of this site (JSON): \'', '\'CSAF: \'' ],
		],
	],
	[
		'security.txt is printed after redirect_canonical again (301 to a trailing slash)',
		[
			[ 'includes/Beacon/SecurityTxtHandler.php', '[ $this, \'render_security_txt\' ], 0 );', '[ $this, \'render_security_txt\' ] );' ],
		],
	],
	[
		'a bare word passes as https URL again (esc_url_raw prepends https://)',
		[
			[ 'includes/Beacon/SecurityTxtHandler.php', '$parts = wp_parse_url( $value );', '$parts = [ \'scheme\' => \'https\', \'host\' => \'x\' ];' ],
		],
	],
	[
		'an undeliverable contact counts as usable',
		[
			[ 'includes/Beacon/SecurityTxtHandler.php', 'if ( null === self::sanitize_contact( $f[\'contact\'] ) ) {', 'if ( false ) {' ],
		],
	],
	[
		'an expired file is HEALTHY in the hub',
		[
			[ 'includes/Adapters/Cra_Spoke_Adapter.php', '\'expired\'        => \'ERROR\',', '\'expired\'        => \'HEALTHY\',' ],
		],
	],
	[
		'the guessed activation contact counts as configured',
		[
			[ 'includes/Adapters/Cra_Spoke_Adapter.php', 'if ( \'ok\' === $status[\'state\'] && ! $status[\'confirmed\'] ) {', 'if ( false ) {' ],
		],
	],
	[
		'missing tables are not an error',
		[
			[ 'includes/Adapters/Cra_Spoke_Adapter.php', 'if ( ! $this->tables_exist() ) {', 'if ( false ) {' ],
		],
	],
	[
		'the hub settings link opens a page that does not exist',
		[
			[ 'includes/Adapters/Cra_Spoke_Adapter.php', 'admin.php?page=wm-cra-beacon', 'admin.php?page=wm-cra-dashboard' ],
		],
	],
	[
		'every licence becomes Proprietary again',
		[
			[ 'includes/SBOM/CycloneDxGenerator.php', '[ [ \'license\' => [ \'name\' => $license ] ] ]', '[ [ \'license\' => [ \'id\' => \'Proprietary\' ] ] ]' ],
		],
	],
	[
		'an unknown version leaves a purl ending in @',
		[
			[ 'includes/SBOM/CycloneDxGenerator.php', '( \'\' !== $version ? \'@\' . rawurlencode( $version ) : \'\' )', '\'@\' . rawurlencode( $version )' ],
		],
	],
	[
		'a failed snapshot insert counts as saved',
		[
			[ 'includes/SBOM/CycloneDxGenerator.php', '$saved = false !== $inserted && (int) $inserted > 0;', '$saved = true;' ],
		],
	],
	[
		'sbom-generate prints a status line after the JSON',
		[
			[ 'includes/CLI/CraCommand.php', "\t\t\tWP_CLI::line( \$json );\n\t\t\treturn;\n\t\t}\n\n\t\t// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- CLI export to a path the operator names.\n\t\t\$written = @file_put_contents(", "\t\t\tWP_CLI::line( \$json ); WP_CLI::success( 'SBOM generated' );\n\t\t\treturn;\n\t\t}\n\n\t\t// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- CLI export to a path the operator names.\n\t\t\$written = @file_put_contents(" ],
		],
	],
	[
		'an unwritable --output prints Success',
		[
			[ 'includes/CLI/CraCommand.php', 'if ( false === $written ) {', 'if ( false ) {' ],
		],
	],
	[
		'csaf-publish stamps a CVE nobody assigned',
		[
			[ 'includes/CLI/CraCommand.php', '(string) ( $assoc_args[\'cve\'] ?? \'\' ),', '\'CVE-2026-CRA-LOCAL\',' ],
		],
	],
	[
		'any severity is accepted',
		[
			[ 'includes/CSAF/CsafPublisher.php', 'if ( ! in_array( $severity, self::SEVERITIES, true ) ) {', 'if ( false ) {' ],
		],
	],
	[
		'a re-publication resets the initial release date',
		[
			[ 'includes/CSAF/CsafPublisher.php', '? $previous[\'document\'][\'tracking\'][\'initial_release_date\'] : $now;', '? $now : $now;' ],
		],
	],
	[
		'documents claim the Security Advisory profile again',
		[
			[ 'includes/CSAF/CsafPublisher.php', '=> \'csaf_base\',', '=> \'csaf_security_advisory\',' ],
		],
	],
	[
		'the index names a BSI liaison as issuing authority again',
		[
			[ 'includes/CSAF/CsafPublisher.php', '\'namespace\' => home_url( \'/\' ),', '\'namespace\' => home_url( \'/\' ), \'issuing_authority\' => \'WM Suite PSIRT / BSI CSIRT Liaison\',' ],
		],
	],
	[
		'the portal states a patch level again',
		[
			[ 'includes/Frontend/PsirtPortal.php', '\'Derzeit sind keine Sicherheitshinweise veröffentlicht.\'', '\'Derzeit liegen keine ungelösten Sicherheitswarnungen vor. Alle Systeme entsprechen dem aktuellen Patch-Stand.\'' ],
		],
	],
	[
		'the portal shows a placeholder CVE',
		[
			[ 'includes/Frontend/PsirtPortal.php', '$adv[\'vulnerabilities\'][0][\'cve\'] ?? \'\'', '$adv[\'vulnerabilities\'][0][\'cve\'] ?? \'CVE-2026\'' ],
		],
	],
	[
		'the widget shows a fixed 18 without snapshot',
		[
			[ 'includes/Admin/AdminDashboard.php', 'echo null === $snapshot ? \'–\' :', 'echo null === $snapshot ? \'18\' :' ],
		],
	],
	[
		'the preview shows a fixed Expires instead of the served file',
		[
			[ 'includes/Admin/AdminDashboard.php', 'echo esc_html( $this->security_txt->generate_security_txt_content() );', 'echo \'Expires: 2027-08-27T00:00:00Z\';' ],
		],
	],
	[
		'the widget renders unstyled on the WordPress dashboard',
		[
			[ 'includes/Admin/AdminDashboard.php', '\'index.php\' !== $hook && ', '' ],
		],
	],
	[
		'uninstall leaves wm_cra_settings behind',
		[
			[ 'uninstall.php', '\'wm_cra_settings\',', '' ],
		],
	],
	[
		'a lock file inside vendor/ or node_modules is walked into, so the inventory claims another project',
		[
			[ 'includes/SBOM/DependencyScanner.php', "public const SKIP_DIRECTORIES = [ 'vendor', 'node_modules', '.git', '.github', 'tests', 'test', 'node-gyp' ];", "public const SKIP_DIRECTORIES = [ '.github' ];" ],
		],
	],
	[
		'Composer development dependencies are listed as code the site runs',
		[
			[ 'includes/SBOM/DependencyScanner.php', 'foreach ( $data[\'packages\'] as $package ) {', 'foreach ( array_merge( (array) $data[\'packages\'], (array) ( $data[\'packages-dev\'] ?? [] ) ) as $package ) {' ],
		],
	],
	[
		'npm development dependencies are listed as code the site runs',
		[
			[ 'includes/SBOM/DependencyScanner.php', "if ( ! is_array( \$package ) || '' === (string) \$path || ! empty( \$package['dev'] ) ) {", "if ( ! is_array( \$package ) || '' === (string) \$path ) {" ],
		],
	],
	[
		'a Composer package without a version is given one',
		[
			[ 'includes/SBOM/DependencyScanner.php', "\$name    = self::clean( (string) ( \$package['name'] ?? '' ) );\n\t\t\t\$version = self::clean( (string) ( \$package['version'] ?? '' ) );", "\$name    = self::clean( (string) ( \$package['name'] ?? '' ) );\n\t\t\t\$version = self::clean( (string) ( \$package['version'] ?? '0.0.0' ) ) ?: '0.0.0';" ],
		],
	],
	[
		'an npm scope stops being a purl namespace, so the database cannot match the package',
		[
			[ 'includes/SBOM/DependencyScanner.php', "return 'pkg:npm/%40' . rawurlencode( \$scope )", "return 'pkg:npm/' . rawurlencode( \$scope )" ],
		],
	],
	[
		'a library two plugins bundle forgets the second owner',
		[
			[ 'includes/SBOM/DependencyScanner.php', '$components[ $seen[ $key ] ][\'properties\'] = self::merge_owners(', '$components[ $seen[ $key ] ][\'properties\'] = ( static fn( array $p, string $o ): array => $p )(' ],
		],
	],
	[
		'the web server banner reaches the SBOM with its markup and control characters',
		[
			[ 'includes/SBOM/RuntimeInventory.php', "return trim( (string) preg_replace( '/[\\x00-\\x1F\\x7F]/', '', wp_strip_all_tags( \$software ) ) );", "return trim( \$software );" ],
		],
	],
	[
		'MariaDB is reported as MySQL, which has different advisories',
		[
			[ 'includes/SBOM/RuntimeInventory.php', "return false !== stripos( \$server_info, 'mariadb' ) ? 'mariadb' : 'mysql';", "return 'mysql';" ],
		],
	],
	[
		'an extension that only reports PHP own version is listed with it anyway',
		[
			[ 'includes/SBOM/RuntimeInventory.php', "return ( '' === \$reported || \$reported === trim( \$php_version ) ) ? '' : \$reported;", "return \$reported;" ],
		],
	],
	[
		'the openssl and curl extensions stop reporting the library they wrap',
		[
			[ 'includes/SBOM/RuntimeInventory.php', "\$library = self::library_version( \$name );", "\$library = '';" ],
		],
	],
	[
		'a server string without a version number gets one invented',
		[
			[ 'includes/SBOM/RuntimeInventory.php', "return 1 === preg_match( '/(\\d+\\.\\d+(?:\\.\\d+)?)/', \$server_info, \$match ) ? \$match[1] : '';", "return 1 === preg_match( '/(\\d+\\.\\d+(?:\\.\\d+)?)/', \$server_info, \$match ) ? \$match[1] : '0.0';" ],
		],
	],
	[
		'the CBOM is on by default and triples every document',
		[
			[ 'includes/SBOM/CryptoInventory.php', 'return (bool) \\apply_filters( self::OPT_INCLUDE, (bool) \\get_option( self::OPT_INCLUDE, 0 ) );', 'return true;' ],
		],
	],
	[
		'an extendable-output function is called a hash',
		[
			[ 'includes/SBOM/CryptoInventory.php', "\t\t\t\treturn 'xof';", "\t\t\t\treturn 'hash';" ],
		],
	],
	[
		'an authenticating cipher mode is reported as a plain block cipher',
		[
			[ 'includes/SBOM/CryptoInventory.php', "\t\t\treturn 'ae';", "\t\t\treturn 'block-cipher';" ],
		],
	],
	[
		'a key length is invented for a cipher whose name states none',
		[
			[ 'includes/SBOM/CryptoInventory.php', "'parameterSetIdentifier' => self::bit_length( \$method ),", "'parameterSetIdentifier' => '128'," ],
		],
	],
	[
		'the bundled libraries drop out of the served document',
		[
			[ 'includes/SBOM/CycloneDxGenerator.php', 'foreach ( DependencyScanner::components( $this->bundle_roots() ) as $component ) {', 'foreach ( [] as $component ) {' ],
		],
	],
	[
		'the runtime drops out of the served document',
		[
			[ 'includes/SBOM/CycloneDxGenerator.php', 'foreach ( RuntimeInventory::components() as $component ) {', 'foreach ( [] as $component ) {' ],
		],
	],
	[
		'the command flag no longer reaches the decision the screen uses',
		[
			[ 'includes/SBOM/CryptoInventory.php', "return (bool) \\apply_filters( self::OPT_INCLUDE, (bool) \\get_option( self::OPT_INCLUDE, 0 ) );", "return (bool) \\get_option( self::OPT_INCLUDE, 0 );" ],
		],
	],
	[
		'a command parameter gets a second description line, which the synopsis parser rejects',
		[
			[ 'includes/CLI/CraCommand.php', "\t * : Include the cryptographic bill of materials for this run (around 186 further components on a stock PHP 8.3 with OpenSSL 3.5).", "\t * : Include the cryptographic bill of materials for this run, whatever the setting says. On a\n\t * : stock PHP 8.3 with OpenSSL 3.5 that is around 186 further components." ],
		],
	],
	[
		'uninstall leaves the SBOM option behind',
		[
			[ 'uninstall.php', "\t\t'wm_cra_sbom_include_crypto',\n", '' ],
		],
	],
	[
		'a non-vulnerable platform entry counts as a hit, so the operating system is reported as vulnerable',
		[
			[ 'includes/Vuln/CpeMatcher.php', 'if ( empty( $cpe_match[\'vulnerable\'] ) || \'\' === $criteria ) {', 'if ( \'\' === $criteria ) {' ],
		],
	],
	[
		'target_sw stops being checked, so a name collision with unrelated software is a finding',
		[
			[ 'includes/Vuln/CpeMatcher.php', 'if ( ! self::targets_wordpress( $criteria ) || self::product( $criteria ) !== strtolower( $product ) ) {', 'if ( false ) {' ],
		],
	],
	[
		'a component without a version is declared unaffected instead of unknown',
		[
			[ 'includes/Vuln/CpeMatcher.php', '			// Nothing to compare against. A component whose version is unknown is not declared
			// unaffected; the audit records it as "version unknown" instead, which is not a pass.
			return false;', '			return true;' ],
		],
	],
	[
		'the upper bound stops excluding the version that fixed the vulnerability',
		[
			[ 'includes/Vuln/CpeMatcher.php', 'if ( \'\' !== $end_excluding && version_compare( $version, $end_excluding, \'>=\' ) ) {', 'if ( \'\' !== $end_excluding && version_compare( $version, $end_excluding, \'>\' ) ) {' ],
		],
	],
	[
		'the lower bound of a window stops applying, so older versions are reported too',
		[
			[ 'includes/Vuln/CpeMatcher.php', 'if ( \'\' !== $start_including && version_compare( $version, $start_including, \'<\' ) ) {', 'if ( false ) {' ],
		],
	],
	[
		'the older CVSS metric wins, understating the severity',
		[
			[ 'includes/Vuln/CpeMatcher.php', 'foreach ( [ \'cvssMetricV40\', \'cvssMetricV31\', \'cvssMetricV30\', \'cvssMetricV2\' ] as $metric ) {', 'foreach ( [ \'cvssMetricV2\', \'cvssMetricV30\', \'cvssMetricV31\', \'cvssMetricV40\' ] as $metric ) {' ],
		],
	],
	[
		'WordPress components are sent to OSV, where every answer is an empty one',
		[
			[ 'includes/Vuln/OsvClient.php', 'public const SUPPORTED_PURL_PREFIXES = [ \'pkg:composer/\', \'pkg:npm/\' ];', 'public const SUPPORTED_PURL_PREFIXES = [ \'pkg:\' ];' ],
		],
	],
	[
		'the OSV batch answer is read by a fixed index instead of by position',
		[
			[ 'includes/Vuln/OsvClient.php', 'foreach ( (array) ( $results[ $index ][\'vulns\'] ?? [] ) as $vuln ) {', 'foreach ( (array) ( $results[0][\'vulns\'] ?? [] ) as $vuln ) {' ],
		],
	],
	[
		'an unreachable OSV leaves its components looking checked',
		[
			[ 'includes/Vuln/OsvClient.php', 'return [ \'findings\' => $findings, \'checked\' => $checked, \'error\' => $response[\'error\'] ];', 'return [ \'findings\' => $findings, \'checked\' => array_merge( $checked, $chunk ), \'error\' => null ];' ],
		],
	],
	[
		'a component without a version gets an empty clean NVD result instead of an error',
		[
			[ 'includes/Vuln/NvdClient.php', 'if ( \'\' === CpeMatcher::normalise( $version ) ) {', 'if ( false ) {' ],
		],
	],
	[
		'the NVD query guesses a vendor instead of leaving it a wildcard',
		[
			[ 'includes/Vuln/NvdClient.php', '\'virtualMatchString\' => \'cpe:2.3:a:*:\' . $product,', '\'virtualMatchString\' => \'cpe:2.3:a:wordpress:\' . $product,' ],
		],
	],
	[
		'the runtime and the cryptographic assets are sent to a database that cannot answer for them',
		[
			[ 'includes/Vuln/VulnerabilityAudit.php', 'if ( str_starts_with( $purl, \'pkg:generic/wordpress-plugin/\' )
				|| str_starts_with( $purl, \'pkg:generic/wordpress-theme/\' )
				|| str_starts_with( $purl, \'pkg:generic/wordpress-mu-plugin/\' )
				|| str_starts_with( $purl, \'pkg:generic/wordpress\' ) ) {', 'if ( true ) {' ],
		],
	],
	[
		'an unreachable source is recorded as checked',
		[
			[ 'includes/Vuln/VulnerabilityAudit.php', '$state[ $purl ] = self::component_state( self::STATE_SOURCE_ERROR, \'osv\', $now, 0, $package, $osv_result[\'error\'] );', '$state[ $purl ] = self::component_state( self::STATE_CHECKED, \'osv\', $now, 0, $package, null );' ],
		],
	],
	[
		'a run that reached only part of the inventory reports itself complete',
		[
			[ 'includes/Vuln/VulnerabilityAudit.php', '\'complete\'         => 0 === $counts[ self::STATE_NEVER_CHECKED ] && 0 === $counts[ self::STATE_SOURCE_ERROR ],', '\'complete\'         => true,' ],
		],
	],
	[
		'the cursor stops moving, so the same components are checked for ever',
		[
			[ 'includes/Vuln/VulnerabilityAudit.php', 'return [ \'items\' => $items, \'next\' => ( $cursor + count( $items ) ) % $count ];', 'return [ \'items\' => $items, \'next\' => $cursor ];' ],
		],
	],
	[
		'uninstall leaves the audit state behind',
		[
			[ 'uninstall.php', '		\'wm_cra_vuln_state\',
', '' ],
		],
	],
	[
		'the vulnerability tab disappears from the screen, leaving the audit reachable only from the CLI',
		[
			[ 'includes/Admin/AdminDashboard.php', '			\'vuln\'     => [ \'label\' => __( \'Schwachstellen\', \'wm-cra-sbom-beacon\' ), \'icon\' => \'dashicons-shield\' ],
', '' ],
		],
	],
	[
		'a malformed NVD key is stored and sent as a header the API rejects',
		[
			[ 'includes/Admin/AdminDashboard.php', 'update_option( NvdClient::OPT_API_KEY, 1 === preg_match( \'/^[A-Za-z0-9-]{8,64}$/\', $key ) ? $key : \'\' );', 'update_option( NvdClient::OPT_API_KEY, $key );' ],
		],
	],
	[
		'the audit switch no longer moves the schedule',
		[
			[ 'includes/Admin/AdminDashboard.php', '			VulnerabilityAudit::sync_schedule();
', '' ],
		],
	],
	[
		'a key no longer raises the budget, so a site with one still crawls',
		[
			[ 'includes/Vuln/NvdClient.php', 'return self::has_key() ? self::BUDGET_WITH_KEY : self::BUDGET_WITHOUT_KEY;', 'return self::BUDGET_WITHOUT_KEY;' ],
		],
	],
	[
		'the SPDX 2 class name comes back, so the document validates against nothing',
		[
			[ 'includes/SPDX/Spdx3Generator.php', '\'type\'                   => \'software_Package\',
			\'spdxId\'                 => $root_id,', '\'type\'                   => \'Package\',
			\'spdxId\'                 => $root_id,' ],
		],
	],
	[
		'the version uses the SPDX 2 property name, which 3.0.1 does not define',
		[
			[ 'includes/SPDX/Spdx3Generator.php', '$package[\'software_packageVersion\'] = $version;', '$package[\'packageVersion\'] = $version;' ],
		],
	],
	[
		'a component without a version is given one in SPDX, so the two documents disagree',
		[
			[ 'includes/SPDX/Spdx3Generator.php', '$version = trim( (string) ( $component[\'version\'] ?? \'\' ) );
		if ( \'\' !== $version ) {', '$version = trim( (string) ( $component[\'version\'] ?? \'NOASSERTION\' ) ) ?: \'NOASSERTION\';
		if ( \'\' !== $version ) {' ],
		],
	],
	[
		'an unmapped component type gets an invented purpose instead of the defined other',
		[
			[ 'includes/SPDX/Spdx3Generator.php', 'self::PURPOSE[ (string) ( $component[\'type\'] ?? \'\' ) ] ?? \'other\',', 'self::PURPOSE[ (string) ( $component[\'type\'] ?? \'\' ) ] ?? \'cryptographicAsset\',' ],
		],
	],
	[
		'the relationship uses a value the vocabulary does not define',
		[
			[ 'includes/SPDX/Spdx3Generator.php', '\'relationshipType\' => \'contains\',', '\'relationshipType\' => \'includes\',' ],
		],
	],
	[
		'the SBOM claims to describe a build rather than what is deployed',
		[
			[ 'includes/SPDX/Spdx3Generator.php', '\'software_sbomType\' => [ \'deployed\' ],', '\'software_sbomType\' => [ \'buildTime\' ],' ],
		],
	],
	[
		'a free-text header licence is asserted as a declared SPDX licence',
		[
			[ 'includes/SPDX/Spdx3Generator.php', '$package[\'comment\'] = \'Licence as stated in the component header: \' . trim( $licence );', '$package[\'hasDeclaredLicense\'] = trim( $licence );' ],
		],
	],
	[
		'a finding nobody assessed is published as not_affected',
		[
			[ 'includes/Vuln/OpenVexEngine.php', '\'status\'        => \'under_investigation\',', '\'status\'        => \'not_affected\',' ],
		],
	],
	[
		'not_affected is accepted without a justification or an impact statement',
		[
			[ 'includes/Vuln/OpenVexEngine.php', 'if ( \'\' === $justification && \'\' === $impact_statement ) {', 'if ( false ) {' ],
		],
	],
	[
		'a justification outside the VEX catalogue is accepted',
		[
			[ 'includes/Vuln/OpenVexEngine.php', 'if ( \'\' !== $justification && ! in_array( $justification, self::JUSTIFICATIONS, true ) ) {', 'if ( false ) {' ],
		],
	],
	[
		'affected is accepted without saying what to do about it',
		[
			[ 'includes/Vuln/OpenVexEngine.php', 'if ( \'affected\' === $status && \'\' === $action_statement ) {', 'if ( false ) {' ],
		],
	],
	[
		'an unknown VEX status is accepted',
		[
			[ 'includes/Vuln/OpenVexEngine.php', 'if ( ! in_array( $status, self::STATUSES, true ) ) {', 'if ( false ) {' ],
		],
	],
	[
		'the document version stops changing when its content does',
		[
			[ 'includes/Vuln/OpenVexEngine.php', '		self::bump_version();
', '' ],
		],
	],
	[
		'a restatement resets the date the position was first taken',
		[
			[ 'includes/Vuln/OpenVexEngine.php', '\'first_issued\'  => (string) ( $previous[\'first_issued\'] ?? $now ),', '\'first_issued\'  => $now,' ],
		],
	],
	[
		'a statement about a finding the scan no longer reports is dropped',
		[
			[ 'includes/Vuln/OpenVexEngine.php', '		foreach ( $stored as $key => $statement ) {
			if ( ! isset( $covered[ $key ] ) ) {
				$statements[] = self::statement( $statement, \'\' );
			}
		}', '		foreach ( [] as $key => $statement ) {
			if ( ! isset( $covered[ $key ] ) ) {
				$statements[] = self::statement( $statement, \'\' );
			}
		}' ],
		],
	],
	[
		'an unconfirmed contact is published as the document author',
		[
			[ 'includes/Vuln/OpenVexEngine.php', 'if ( $confirmed && \'\' !== $contact ) {', 'if ( \'\' !== $contact ) {' ],
		],
	],
	[
		'uninstall leaves the VEX statements behind',
		[
			[ 'uninstall.php', '		\'wm_cra_vex_statements\',
', '' ],
		],
	],
	[
		'the document version reads the change counter directly, so the first statement changes nothing',
		[
			[ 'includes/Vuln/OpenVexEngine.php', 'return 1 + max( 0, (int) get_option( self::OPT_VERSION, 0 ) );', 'return max( 1, (int) get_option( self::OPT_VERSION, 1 ) );' ],
		],
	],
	[
		'the /sbom route regresses to __return_true and leaks the inventory anonymously',
		[
			[ 'includes/API/RestController.php', "'callback'            => [ \$this, 'get_sbom' ],\n\t\t\t\t'permission_callback' => [ \$this, 'check_read_permission' ],", "'callback'            => [ \$this, 'get_sbom' ],\n\t\t\t\t'permission_callback' => '__return_true'," ],
		],
	],
	[
		'verify_bearer_token accepts any non-empty Bearer token',
		[
			[ 'includes/API/RestController.php', 'return hash_equals( $stored_hash, hash( \'sha256\', $candidate ) );', 'return true;' ],
		],
	],
	[
		'opt-in public REST access stops enforcing the per-IP rate limit',
		[
			[ 'includes/API/RestController.php', 'if ( ! self::consume_rate_limit() ) {', 'if ( false ) {' ],
		],
	],
	[
		'flush_caches stops bumping the cache-bust counter',
		[
			[ 'includes/API/RestController.php', 'update_option( self::OPT_CACHE_BUST, $bust + 1, false );', '// cache bust disabled' ],
		],
	],
	[
		'default uninstall wipes statutory SBOM snapshots, advisories and VEX records without opt-in',
		[
			[ 'uninstall.php', "\$delete_all = '1' === (string) get_option( 'wm_cra_beacon_delete_data_on_uninstall', '0' );", "\$delete_all = true;" ],
		],
	],
	[
		'the Gutenberg block wm/cra-psirt loses its editor_script registration and disappears from the inserter',
		[
			[ 'includes/Frontend/PsirtPortal.php', "'editor_script'   => self::EDITOR_SCRIPT_HANDLE,", "'editor_script'   => ''," ],
		],
	],
	[
		'render_security_txt bypasses the wm_cra_security_txt_output filter',
		[
			[ 'includes/Beacon/SecurityTxtHandler.php', "echo (string) apply_filters( 'wm_cra_security_txt_output', \$txt );", 'echo $txt;' ],
		],
	],
	[
		'Plugin::boot() stops firing the wm_cra_beacon_ready action',
		[
			[ 'includes/Core/Plugin.php', "do_action( 'wm_cra_beacon_ready', \$this );", '// ready hook omitted' ],
		],
	],
	[
		'WP 6.5+ Block Bindings source wm-cra-beacon/status stops being registered',
		[
			[ 'includes/Frontend/PsirtPortal.php', "'wm-cra-beacon/status',", "'wm-cra-beacon/disabled'," ],
		],
	],
	[
		'GenerateBlocks 2.x dynamic tag wm_cra_beacon_status stops being registered',
		[
			[ 'includes/Frontend/PsirtPortal.php', "if ( class_exists( 'GenerateBlocks_Register_Dynamic_Tag' ) ) {", 'if ( false ) {' ],
		],
	],
	[
		'AdminDashboard::register_settings stops registering wm_cra_beacon_delete_data_on_uninstall',
		[
			[ 'includes/Admin/AdminDashboard.php', "if ( function_exists( 'register_setting' ) ) {", 'if ( false ) {' ],
		],
	],
	[
		'wp_initialize_site stops provisioning new multisite subsites',
		[
			[ 'wm-cra-sbom-beacon.php', "add_action( 'wp_initialize_site',", "add_action( 'wp_initialize_site_disabled'," ],
		],
	],
	[
		'wp_initialize_site provisions subsites even when plugin is not network-activated',
		[
			[ 'wm-cra-sbom-beacon.php', '! is_plugin_active_for_network( plugin_basename( __FILE__ ) )', 'false' ],
		],
	],
	[
		'wp_initialize_site omits switch_to_blog and activates on the main site instead of the subsite',
		[
			[ 'wm-cra-sbom-beacon.php', "\tswitch_to_blog( \$blog_id );\n\ttry {\n\t\tDatabase\\Schema::activate();", "\t// switch_to_blog omitted\n\ttry {\n\t\tDatabase\\Schema::activate();" ],
		],
	],
	[
		'wp_initialize_site omits restore_current_blog inside finally',
		[
			[ 'wm-cra-sbom-beacon.php', "\t} finally {\n\t\trestore_current_blog();\n\t}", "\t} finally {\n\t\t// restore_current_blog omitted\n\t}" ],
		],
	],
	[
		'Schema::activate_site writes OPT_CONTACT without autoload = false',
		[
			[ 'includes/Database/Schema.php', 'update_option( SecurityTxtHandler::OPT_CONTACT, SecurityTxtHandler::default_contact(), false );', 'update_option( SecurityTxtHandler::OPT_CONTACT, SecurityTxtHandler::default_contact() );' ],
		],
	],
	[
		'Schema::activate_site writes OPT_EXPIRES without autoload = false',
		[
			[ 'includes/Database/Schema.php', "update_option( SecurityTxtHandler::OPT_EXPIRES, gmdate( 'Y-m-d\\TH:i:s\\Z', strtotime( '+11 months' ) ), false );", "update_option( SecurityTxtHandler::OPT_EXPIRES, gmdate( 'Y-m-d\\TH:i:s\\Z', strtotime( '+11 months' ) ) );" ],
		],
	],
	[
		'Schema::activate_site writes OPT_LANGUAGES without autoload = false',
		[
			[ 'includes/Database/Schema.php', "update_option( SecurityTxtHandler::OPT_LANGUAGES, 'de, en', false );", "update_option( SecurityTxtHandler::OPT_LANGUAGES, 'de, en' );" ],
		],
	],
	[
		'AdminDashboard writes VulnerabilityAudit::OPT_ENABLED without autoload = false',
		[
			[ 'includes/Admin/AdminDashboard.php', "update_option( VulnerabilityAudit::OPT_ENABLED, isset( \$_POST['vuln_enabled'] ) ? 1 : 0, false );", "update_option( VulnerabilityAudit::OPT_ENABLED, isset( \$_POST['vuln_enabled'] ) ? 1 : 0 );" ],
		],
	],
	[
		'AdminDashboard writes CryptoInventory::OPT_INCLUDE without autoload = false',
		[
			[ 'includes/Admin/AdminDashboard.php', "update_option( CryptoInventory::OPT_INCLUDE, isset( \$_POST['include_crypto'] ) ? 1 : 0, false );", "update_option( CryptoInventory::OPT_INCLUDE, isset( \$_POST['include_crypto'] ) ? 1 : 0 );" ],
		],
	],
	[
		'AdminDashboard writes RestController::OPT_PUBLIC_ENDPOINTS without autoload = false',
		[
			[ 'includes/Admin/AdminDashboard.php', "update_option( RestController::OPT_PUBLIC_ENDPOINTS, isset( \$_POST['public_endpoints'] ) ? 1 : 0, false );", "update_option( RestController::OPT_PUBLIC_ENDPOINTS, isset( \$_POST['public_endpoints'] ) ? 1 : 0 );" ],
		],
	],
	[
		'AdminDashboard writes wm_cra_beacon_delete_data_on_uninstall without autoload = false',
		[
			[ 'includes/Admin/AdminDashboard.php', "update_option( 'wm_cra_beacon_delete_data_on_uninstall', isset( \$_POST['delete_data_on_uninstall'] ) ? 1 : 0, false );", "update_option( 'wm_cra_beacon_delete_data_on_uninstall', isset( \$_POST['delete_data_on_uninstall'] ) ? 1 : 0 );" ],
		],
	],
	[
		'AdminDashboard writes SecurityTxtHandler::OPT_CONFIRMED without autoload = false',
		[
			[ 'includes/Admin/AdminDashboard.php', "update_option( SecurityTxtHandler::OPT_CONFIRMED, gmdate( 'Y-m-d\\TH:i:s\\Z' ), false );", "update_option( SecurityTxtHandler::OPT_CONFIRMED, gmdate( 'Y-m-d\\TH:i:s\\Z' ) );" ],
		],
	],
	[
		'Schema::maybe_upgrade calls add_rewrite_rule on plugins_loaded before $wp_rewrite exists',
		[
			[ 'includes/Database/Schema.php', 'self::activate_site( false );', 'self::activate_site( true );' ],
		],
	],
];
