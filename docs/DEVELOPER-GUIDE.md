# Developer Guide — WM CRA SBOM & Vulnerability Beacon

Measured from the code on 2026-09-15.

## WP-CLI

```bash
wp cra sbom-generate                            # CycloneDX JSON on STDOUT, nothing else (pipe-safe)
wp cra sbom-generate --output=/tmp/sbom.json    # write to a file; an unwritable path is an error
wp cra sbom-generate --snapshot                 # also store it in wm_cra_sbom_snapshots; a failed insert is an error
wp cra sbom-generate --crypto                   # add the CBOM for this run (~186 components on a stock PHP 8.3 / OpenSSL 3.5)
wp cra vuln-scan                                # one pass: OSV for Composer/npm, NVD for WordPress components (budgeted)
wp cra vuln-scan --all                           # keep going until every component has been checked once (minutes, rate limited)
wp cra spdx-generate                             # the same inventory as SPDX 3.0.1 JSON-LD
wp cra vex                                       # print the OpenVEX document
wp cra vex <purl> <cve> --status=not_affected --justification=vulnerable_code_not_in_execute_path
wp cra security-txt                             # the served file; a warning when its state is not ok
wp cra csaf-publish WM-2026-001 --title="Stored XSS in the contact form" --severity=high --cve=CVE-2026-12345 --description="Fixed in 2.1."
```

`csaf-publish`: severity is one of `low`, `medium`, `high`, `critical`; `--cve` must look like `CVE-2026-12345`; the tracking id is 1 to 64 printable characters. Publishing an existing id updates the document, raises `tracking.version` and appends to `revision_history`. Until 2026-09-15 the command stamped `CVE-2026-CRA-LOCAL` and a CVSS score of 7.5 or 9.8 on every advisory, accepted any severity, and printed JSON plus a "Success:" line on STDOUT for `sbom-generate`, storing a snapshot on every call.

## REST

| Route | Method | Auth | Response |
| --- | --- | --- | --- |
| `/wp-json/wm-cra/v1/sbom` | GET | `manage_options` or `Authorization: Bearer <token>` (opt-in public, 60/min) | CycloneDX 1.6 JSON (1h transient cache) |
| `/wp-json/wm-cra/v1/spdx` | GET | `manage_options` or `Authorization: Bearer <token>` (opt-in public, 60/min) | SPDX 3.0.1 JSON-LD (1h transient cache) |
| `/wp-json/wm-cra/v1/vex` | GET | `manage_options` or `Authorization: Bearer <token>` (opt-in public, 60/min) | OpenVEX v0.2.0 JSON (1h transient cache) |
| `/wp-json/wm-cra/v1/csaf` | GET | `manage_options` or `Authorization: Bearer <token>` (opt-in public, 60/min) | `{ index, publisher, generated_at, advisories[] }`, newest 50 CSAF documents (1h transient cache) |
| `/.well-known/security.txt`, `/security.txt` | GET | public | text/plain (rewrite rule, not REST) |

Bearer tokens can be rotated/revoked on the *SBOM* admin tab (only the 64-hex SHA-256 digest is stored in `wm_cra_api_token_hash`) or pinned statically via `define( 'WM_CRA_API_TOKEN', '...' );` in `wp-config.php`.

## Hooks & Editor Integrations

- **Actions:** `wm_cra_beacon_ready` (fired at the end of `Plugin::boot()`, passing the `Plugin` singleton).
- **Filters:** `wm_cra_security_txt_output` (filters the served `/.well-known/security.txt` plain-text body), `wm_cra_sbom_include_crypto` (enables the CBOM for a run), `wm_cra_nvd_pause` (seconds between NVD requests).
- **Gutenberg Block:** `wm/cra-psirt` (`blocks/cra-psirt/block.json`, editor script handle `wm-cra-beacon-blocks-editor` from `build/index.js` + `build/index.asset.php`, attributes `showJsonLinks` and `showAdvisories`).
- **WP 6.5+ Block Bindings:** source `wm-cra-beacon/status` (`key`: `summary`, `state`, `expires`, `contact`, `advisories_count`).
- **GenerateBlocks 2.x Dynamic Tag:** `{{wm_cra_beacon_status}}` (registered via `GenerateBlocks_Register_Dynamic_Tag` and `generateblocks_dynamic_tag_replacement`).
- **WordPress hooks wired:** `init` (rewrite rules, text domain, block, block bindings, dynamic tag), `wp_loaded` (stored-rule repair), `query_vars`, `template_redirect` (priority 0), `rest_api_init`, `wp_initialize_site` (priority 20, network-activated multisite subsite provisioning), `activated_plugin` / `deactivated_plugin` / `switch_theme` / `upgrader_process_complete` (`RestController::flush_caches`), `admin_menu`, `admin_enqueue_scripts` (plugin page and `index.php`), `admin_init` (`register_settings` for `wm_cra_beacon_delete_data_on_uninstall` and form actions), `wp_dashboard_setup`, and the hub filter `wm_register_suite_module`.

## WM Suite Hub

`Cra_Spoke_Adapter`: health from the security.txt state and the tables (see ARCHITECTURE.md); telemetry `sbom_snapshots`, `latest_sbom_hash`, `advisories`, `security_txt_state`, `security_txt_expires`, `security_txt_confirmed`, `security_txt_url`; actions `self_test` (success only when the file is ok, confirmed and the tables exist) and `generate_sbom` (success only when the snapshot is stored); settings URL `admin.php?page=wm-cra-beacon`.

## Tests

| Command | Needs | Covers |
| --- | --- | --- |
| `php tests/test-suite.php` | PHP | security.txt fields and states, activation and route repair, settings save, SBOM content, CLI output and errors, CSAF documents, hub health, admin and widget, public box, uninstall. Mock `$wpdb` throws on unknown SQL; warnings fail the run. |
| `bash tests/run-mutations.sh` | PHP, git, tar | 114 mutations in `tests/mutations.php`, each must turn the suite red. |
| `php tests/test-ui-family.php` | PHP | Family sheets identical to the hub. |
| `vendor/bin/phpunit` (in `tests/`) | Composer dev dependencies | Generator and security.txt basics. |
| `wp eval-file tests/wp-runtime-cra.php --user=1` | WordPress | Stored route, served content, REST, admin, settings save (restores the options), hub. |

CI (`.github/workflows/ci.yml`) runs PHPUnit and both standalone suites on PHP 8.2 and 8.3, and the mutation check on 8.3.
