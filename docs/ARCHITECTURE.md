# Architecture — WM CRA SBOM & Vulnerability Beacon

Measured from the code on 2026-09-15. The previous edition announced a "C4 model", an "XML SBOM feed", "automated SHA-256 integrity validation per component" and a CSAF engine fed by the SBOM and security.txt; the code has none of these.

## Flow

```text
Request /.well-known/security.txt
   │  rewrite rule (registered on init, stored on activation; repaired once on wp_loaded when missing)
   ▼
SecurityTxtHandler::render_security_txt()      template_redirect, priority 0 (before redirect_canonical)
   └─ generate_security_txt_content()           five options → text/plain

GET /wp-json/wm-cra/v1/sbom  ──► RestController::check_read_permission() ──► cached CycloneDxGenerator::generate_sbom() (1h transient)
GET /wp-json/wm-cra/v1/spdx  ──► RestController::check_read_permission() ──► cached Spdx3Generator::generate() (1h transient)
GET /wp-json/wm-cra/v1/vex   ──► RestController::check_read_permission() ──► cached OpenVexEngine::document() (1h transient)
GET /wp-json/wm-cra/v1/csaf  ──► RestController::check_read_permission() ──► cached CsafPublisher::get_feed() (1h transient)

wp cra sbom-generate [--output] [--snapshot]   ──► generate_sbom() / save_snapshot()
wp cra csaf-publish <id> --title --severity    ──► CsafPublisher::publish_advisory()
wp cra security-txt                            ──► generate_security_txt_content() + status()
```

## Classes

| File | Responsibility |
| --- | --- |
| `wm-cra-sbom-beacon.php` | Header, constants, autoloader, activation/deactivation (`Schema`), multisite `wp_initialize_site` provisioning, hub registration via `wm_register_suite_module`, boot on `plugins_loaded` |
| `includes/Core/Plugin.php` | Singleton holding generator, publisher and security.txt handler; text domain; wires security.txt, REST, admin (admin only), public box/block/bindings, WP-CLI, and fires `wm_cra_beacon_ready` |
| `includes/Database/Schema.php` | Creates the three tables (per site on network activation and new multisite subsites), writes non-autoloaded security.txt defaults, registers the rewrite rules before the flush; deactivation deletes the stored rules |
| `includes/Beacon/SecurityTxtHandler.php` | Rewrite rules and query var, the served file (filtered via `wm_cra_security_txt_output`), `status()`, field validation (`sanitize_contact`, `sanitize_expires`, `sanitize_languages`, `sanitize_https_url`) |
| `includes/SBOM/CycloneDxGenerator.php` | The CycloneDX document, `serialize()` (the one serialisation every path hashes), `save_snapshot()` |
| `includes/CSAF/CsafPublisher.php` | CSAF 2.0 base documents with revision history, the JSON index, table checks |
| `includes/API/RestController.php` | The four GET routes (`/sbom`, `/spdx`, `/vex`, `/csaf`), protected by default (`manage_options` or SHA-256 Bearer token), with opt-in public rate limiting (60/min) and 1h transient caching |
| `includes/CLI/CraCommand.php` | `wp cra sbom-generate` (`--output`, `--snapshot`, `--crypto`), `security-txt`, `csaf-publish` |
| `includes/SBOM/DependencyScanner.php` | Composer and npm libraries from the lock files plugins and themes bundle; prunes `vendor/`, `node_modules` and `.git`, skips dev dependencies, merges an owner list for a shared library |
| `includes/SBOM/RuntimeInventory.php` | PHP, versioned extensions, database server, web server banner; `usable_version()` drops a reported version equal to PHP's, `library_version()` reads the real one for `openssl` and `curl` |
| `includes/Vuln/CpeMatcher.php` | CPE 2.3 parsing, `target_sw` check and the four NVD version bounds; picks the newest CVSS metric |
| `includes/Vuln/OsvClient.php` | Batched purl queries to osv.dev for Composer and npm only; reads the positional batch answer |
| `includes/Vuln/NvdClient.php` | `virtualMatchString` with a wildcard vendor, rate-limit budget and pause, pure `findings_from()` |
| `includes/SPDX/Spdx3Generator.php` | The inventory as SPDX 3.0.1 JSON-LD; profile-prefixed term names and vocabulary entries read from the published specification |
| `includes/Vuln/OpenVexEngine.php` | OpenVEX v0.2.0 statements; `under_investigation` for anything unassessed, catalogue justifications enforced, document and statement versions |
| `includes/Vuln/VulnerabilityAudit.php` | Splits the inventory by source, walks NVD with a cursor, stores findings in `wm_cra_vulnerabilities` and a per-component state in `wm_cra_vuln_state` |
| `includes/SBOM/CryptoInventory.php` | CBOM: hash algorithms, cipher methods and TLS versions as `cryptographic-asset` components, behind `wm_cra_sbom_include_crypto` (option or filter) |
| `includes/Admin/AdminDashboard.php` | Menu `wm-cra-beacon`, tabs overview / SBOM / vuln / security.txt / glossary, `register_setting` for `wm_cra_beacon_delete_data_on_uninstall`, settings save, snapshot button, dashboard widget |
| `includes/Frontend/PsirtPortal.php` | Shortcodes `[wm_cra_psirt]` & `[wm_security_disclosure]`, compiled block `wm/cra-psirt` (`blocks/cra-psirt/block.json` + `build/index.js`), Block Bindings `wm-cra-beacon/status`, GenerateBlocks Dynamic Tag `{{wm_cra_beacon_status}}` |
| `includes/Adapters/Cra_Spoke_Adapter.php` | WM Suite Hub module (defined only when the hub interface exists) |
| `uninstall.php` | Preserves all options and the 3 CRA Beacon tables by default; deletes options, drops tables and removes guard-only `uploads/wm-cra/sbom` only when `wm_cra_beacon_delete_data_on_uninstall` is enabled |

Until 2026-09-15 `includes/Security/` held RequestShield (ran on every request, logged "BLOCK" with the client IP and blocked nothing), DirectoryProtector (created `uploads/wm-cra/sbom` on every request), and UploadShield, RateLimiter and ErrorSanitizer, which nothing called. All five were removed.

## Data

| Table | Columns |
| --- | --- |
| `wm_cra_sbom_snapshots` | `id`, `cyclonedx_version`, `components_count`, `sbom_sha256` (of `CycloneDxGenerator::serialize()`), `sbom_json`, `created_at` (UTC) |
| `wm_cra_advisories` | `id`, `tracking_id` (unique), `title`, `severity`, `csaf_json`, `published_at`, `updated_at` (UTC) |

Older installs also have `wm_cra_audit_log`, created and never written; new activations do not create it, uninstall drops it.

Options: `wm_cra_security_txt_contact`, `_expires`, `_languages`, `_policy`, `_encryption`, `_confirmed` (UTC time of the last save through the form). `wm_cra_settings` is what the settings form wrote until 2026-09-15; nothing reads it.

## States of security.txt

`SecurityTxtHandler::status()` returns the first that applies: `not_configured` (no contact), `invalid` (contact not an e-mail or https URL), `no_route` (the rule is not in the stored rewrite rules, e.g. plain permalinks), `invalid` (Expires missing or not RFC 3339), `expired`, `expiring` (≤ 30 days), `ok`; plus `confirmed`. Hub health: `ok` and confirmed → HEALTHY, `ok` unconfirmed or `not_configured` → NEEDS_CONFIG, `expiring` → DEGRADED, everything else or missing tables → ERROR.

---

<!-- wm-measured-inventory -->

## Measured inventory

Regenerated from the code, never hand-edited. Everything above this line is written by hand and stays.

```bash
python3 the fleet's architecture inventory tool wm-cra-sbom-beacon --append-to docs/ARCHITECTURE.md
```

## Inventory by layer

**22 PHP files, 5322 lines** (excluding `tests/`, `vendor/`, `node_modules/`, `languages/`).

| Layer | Files | Lines |
|---|---:|---:|
| `(raíz)` | 2 | 200 |
| `build` | 1 | 18 |
| `includes/API` | 1 | 270 |
| `includes/Adapters` | 1 | 198 |
| `includes/Admin` | 1 | 868 |
| `includes/Beacon` | 1 | 252 |
| `includes/CLI` | 1 | 333 |
| `includes/CSAF` | 1 | 184 |
| `includes/Core` | 1 | 87 |
| `includes/Database` | 1 | 123 |
| `includes/Frontend` | 1 | 250 |
| `includes/SBOM` | 4 | 1056 |
| `includes/SPDX` | 1 | 224 |
| `includes/Vuln` | 5 | 1259 |

---

## Classes

| Class | File |
|---|---|
| `AdminDashboard` | [`includes/Admin/AdminDashboard.php`](../includes/Admin/AdminDashboard.php) |
| `CpeMatcher` | [`includes/Vuln/CpeMatcher.php`](../includes/Vuln/CpeMatcher.php) |
| `CraCommand` | [`includes/CLI/CraCommand.php`](../includes/CLI/CraCommand.php) |
| `Cra_Spoke_Adapter` | [`includes/Adapters/Cra_Spoke_Adapter.php`](../includes/Adapters/Cra_Spoke_Adapter.php) |
| `CryptoInventory` | [`includes/SBOM/CryptoInventory.php`](../includes/SBOM/CryptoInventory.php) |
| `CsafPublisher` | [`includes/CSAF/CsafPublisher.php`](../includes/CSAF/CsafPublisher.php) |
| `CycloneDxGenerator` | [`includes/SBOM/CycloneDxGenerator.php`](../includes/SBOM/CycloneDxGenerator.php) |
| `DependencyScanner` | [`includes/SBOM/DependencyScanner.php`](../includes/SBOM/DependencyScanner.php) |
| `NvdClient` | [`includes/Vuln/NvdClient.php`](../includes/Vuln/NvdClient.php) |
| `OpenVexEngine` | [`includes/Vuln/OpenVexEngine.php`](../includes/Vuln/OpenVexEngine.php) |
| `OsvClient` | [`includes/Vuln/OsvClient.php`](../includes/Vuln/OsvClient.php) |
| `Plugin` | [`includes/Core/Plugin.php`](../includes/Core/Plugin.php) |
| `PsirtPortal` | [`includes/Frontend/PsirtPortal.php`](../includes/Frontend/PsirtPortal.php) |
| `RestController` | [`includes/API/RestController.php`](../includes/API/RestController.php) |
| `RuntimeInventory` | [`includes/SBOM/RuntimeInventory.php`](../includes/SBOM/RuntimeInventory.php) |
| `Schema` | [`includes/Database/Schema.php`](../includes/Database/Schema.php) |
| `SecurityTxtHandler` | [`includes/Beacon/SecurityTxtHandler.php`](../includes/Beacon/SecurityTxtHandler.php) |
| `Spdx3Generator` | [`includes/SPDX/Spdx3Generator.php`](../includes/SPDX/Spdx3Generator.php) |
| `VulnerabilityAudit` | [`includes/Vuln/VulnerabilityAudit.php`](../includes/Vuln/VulnerabilityAudit.php) |

---

## Entry points

**REST routes:** `/csaf`, `/sbom`, `/spdx`, `/vex`

**WP-CLI:** `cra`

**Shortcodes:** `wm_cra_psirt`, `wm_security_disclosure`

**Gutenberg blocks:** `wm/cra-psirt`

---

## Persistence — who writes each key and who reads it

| Key | Written by | Read by |
|---|---|---|
| `wm_cra_beacon_delete_data_on_uninstall` | `includes/Admin/AdminDashboard.php` | `includes/Admin/AdminDashboard.php`, `uninstall.php` |
| `wm_cra_db_version` | `includes/Database/Schema.php` | `includes/Database/Schema.php` |
| `wm_cra_flash_token_` (transient) | — | — |

Every key has exactly one writing layer and at least one reader.


**Tables** (prefixed with `$wpdb->prefix`): `wm_cra_advisories`, `wm_cra_sbom_snapshots`

---

## Gates

- `tests/bootstrap.php`
- `tests/mutations.php`
- `tests/run-mutations.sh`
- `tests/test-pot-freshness.php`
- `tests/test-suite.php`
- `tests/test-ui-family.php`
- `tests/wp-runtime-cra.php`
- `.github/workflows/ci.yml`

What CI actually runs is in the workflow files above — a test file that no workflow invokes is not a gate.

---

## Drift detected against the documentation

Nothing measurable: versions agree and every class named in the documents exists.

