# Changelog — WM CRA SBOM & Vulnerability Beacon

All notable changes to this project are documented in this file. Before 2026-09-15 changes were recorded only in `readme.txt`.

## [Unreleased]

### Fixed
- Relaxed `PsirtPortal` GenerateBlocks `generateblocks_dynamic_tag_replacement` filter parameter to `mixed`.
- Renamed `RestController::NAMESPACE` to `REST_NAMESPACE` for PHP 8.5/8.6 compatibility.
- Added `Schema::maybe_upgrade()` to `Plugin::boot()` (`plugins_loaded`) so schema upgrades and scheduled vulnerability scans stay healthy on already-active installs (`wm_cra_db_version` stored with `autoload = false`, removed on opt-in uninstall), deferring rewrite rule registration/flush to `init`/`wp_loaded` (`SecurityTxtHandler`) because `$wp_rewrite` is not initialized during `plugins_loaded`.

## [1.2.2] - 2026-11-21

### Fixed

- Screenshot 1 showed the WM Suite menu from before WM Suite Hub 1.2.3, with entries the hub no longer has («Marketplace (Lösungspakete)», «Merkle-Audit-Protokoll», «CRA- & SBOM-Zentrale»). It is retaken with the current menu; the plugin's code is unchanged.

## [1.2.1] - 2026-11-21

### Changed

- The bundled family stylesheet is identical to WM Suite Hub 1.2.5 again: it starts the admin header below WordPress's help toggle instead of shortening it. This plugin's own screens register no help tab, so they change only where another plugin adds one.
- The translation catalogs are regenerated from the code: the `.pot` header names the current version, strings the code no longer uses are gone, and the block-editor files carry the block's title, description and keywords with the context WordPress looks them up by.

## [1.2.0] - 2026-11-20

### Changed
- The WM Suite Hub contract now lives in the `ArnoldWender\SuiteHub\Contracts` namespace. The spoke adapter registers only with WM Suite Hub 1.2.0 or later, so update the hub together with this plugin; used on its own, the plugin works as before.
- The `.wordpress-org/` banners show the current version.
- The description of the first screenshot (`readme.txt` and the three READMEs) names what it shows, the admin overview; it described CycloneDX 1.5 / SPDX 2.3 export controls and an advisory generator the screen does not have. `README.es.md` stated version 1.1.3 since release 1.1.4.

### Removed
- The archived pre-2026-11-19 marketing visuals in `versionen/`: they claimed features and conformity the plugin does not have. They were never part of the installable package.

## [1.1.4] - 2026-11-19

- Removed the agency name, links to unrelated projects and the personal mailbox from code, catalogs and documentation; the admin family badge and the hub menu read "WM Suite". The READMEs say the plugin was built with an agentic workflow (AI coding agents) and should be reviewed like any third-party code.

- Added root `SUPPORT.md`, `.github/ISSUE_TEMPLATE/{config.yml,bug_report.yml}`, and explicit zero-support / "AS IS" liability notices across `README.md`, `README.de.md`, `README.es.md`, `readme.txt`, `SECURITY.md`, and `llms.txt`.
- Migrated plugin author/catalog/repository metadata to personal open-source distribution (`Arnold Wender`, `https://arnoldwender.com/wordpress-plugins/wm-cra-sbom-beacon/`, `https://github.com/arnoldwender/wm-wp-cra-sbom-beacon`), normalized FSF GPL-2.0 `LICENSE` metadata where applicable, and updated `.wordpress-org/` banner branding to `ARNOLD WENDER · OPEN SOURCE`.

## [Unreleased]

## [1.1.3] - 2026-11-19

### Added
- Official `.wordpress-org/` directory visual kit (`icon.svg`, `icon-128x128.png`, `icon-256x256.png`, `banner-772x250.png`, `banner-1544x500.png`) and live Playwright screenshots (`screenshot-1.png` through `screenshot-3.png`) with `== Screenshots ==` in `readme.txt`.
- Added German (`README.de.md`) and Spanish (`README.es.md`) documentation with language switcher badges, root `llms.txt`, visual previews, and direct links to `https://arnoldwender.com/wordpress-plugins/wm-cra-sbom-beacon/`.

### Changed
- Archived superseded pre-2026-11-19 banners and mockups non-destructively in `versionen/visuals-pre-2026-11-19/` and excluded `versionen/` from distribution packages via `.distignore`.
- Updated release metadata, block/asset manifests, test fixtures, and SBOM (`bom.json`) to `1.1.3`.

## [1.1.2] - 2026-11-19

### Changed
- Point `Plugin URI` to `https://arnoldwender.com/wordpress-plugins/wm-cra-sbom-beacon/` and align release metadata at `v1.1.2`. Added `.github/scripts/security-audit.py` CI gate.

## [1.1.1] - 2026-11-18

### Fixed — Multisite new-site provisioning and non-frontend option autoload (`R2-B8`)

- **Multisite new-subsite provisioning (`wp_initialize_site`).** `wm-cra-sbom-beacon.php` now hooks `wp_initialize_site` (priority 20) when `is_multisite()` and `is_plugin_active_for_network( plugin_basename( __FILE__ ) )`, switching into the new site via `switch_to_blog()`, running `Database\Schema::activate()`, and always calling `restore_current_blog()` inside `try/finally`. `Schema::activate()` also wraps per-site switching in `try/finally` during network-wide activation, and `Schema::activate_site()` guards `wp-admin/includes/upgrade.php` behind `! function_exists( 'dbDelta' )`.
- **Non-frontend `update_option()` autoload disabled.** Passed explicit `$autoload = false` to non-frontend option writes in `includes/Admin/AdminDashboard.php` (`wm_cra_vuln_enabled`, `wm_cra_sbom_include_crypto`, `wm_cra_public_endpoints`, `wm_cra_beacon_delete_data_on_uninstall`, `wm_cra_security_txt_confirmed`) and `includes/Database/Schema.php` (`wm_cra_security_txt_contact`, `wm_cra_security_txt_expires`, `wm_cra_security_txt_languages`).
- **Tests and mutations.** Added Group 15 in `tests/test-suite.php` and 12 mutation cases in `tests/mutations.php` covering `wp_initialize_site` guards, `try/finally` blog restoration, and `$autoload = false`.

## [1.1.0] - 2026-11-16

### Added — Gutenberg block, Block Bindings, GenerateBlocks dynamic tag, hooks & 28-locale i18n (2026-11-16)

- **Compiled Gutenberg block `wm/cra-psirt` (`blocks/cra-psirt/block.json`, `blocks-src/index.js`, `build/index.js`, `build/index.asset.php`).** Registered with editor script handle `wm-cra-beacon-blocks-editor`, `wp_set_script_translations()`, `InspectorControls` (`showJsonLinks` and `showAdvisories` toggles) and `ServerSideRender` so the block is visible and configurable in the Block Inserter.
- **WordPress 6.5+ Block Bindings (`wm-cra-beacon/status`) & GenerateBlocks 2.x Dynamic Tag (`{{wm_cra_beacon_status}}`).** Exposes computed `security.txt` status (`summary`, `state`, `expires`, `contact`, `advisories_count`) without hardcoded badges or conformity claims.
- **Developer extensibility & output escaping (`SEC-08`).** Fires `do_action( 'wm_cra_beacon_ready', $this )` after boot, passes served `/.well-known/security.txt` plain-text content through `apply_filters( 'wm_cra_security_txt_output', $txt )`, and wraps the header badge class expression in `esc_attr()`.
- **Opt-in uninstall (`D-UNINSTALL`).** `uninstall.php` now preserves all plugin options and the 3 CRA Beacon database tables (`wm_cra_sbom_snapshots`, `wm_cra_advisories`, `wm_cra_vulnerabilities`) by default unless `wm_cra_beacon_delete_data_on_uninstall` (registered via `register_setting` and exposed on the *security.txt* settings tab) is explicitly enabled.
- **Translation catalogs (`D-LOCALES`), CycloneDX `bom.json` & Playground blueprint.** Regenerated `languages/wm-cra-sbom-beacon.pot` (163 unique strings) and compiled complete `.po`, `.mo` and JED `.json` catalogs across all 28 shipped locales, alongside `bom.json` (CycloneDX 1.6, `GPL-2.0-or-later`) and `.wordpress-org/blueprints/blueprint.json`.

### Security — REST access control and transient caching (2026-11-16)

- **Closed `/wp-json/wm-cra/v1/sbom`, `/spdx`, `/vex` and `/csaf` by default (`D-CRA-SBOM`).** Anonymous callers previously received the complete plugin/theme/library version map and filesystem lockfile walks on every request without authentication or caching. `RestController::check_read_permission()` now requires `manage_options` or a timing-safe `Authorization: Bearer <token>` header (`WM_CRA_API_TOKEN` in `wp-config.php` or a rotated token whose SHA-256 digest is stored in `wm_cra_api_token_hash`; the raw token is shown once via a 60-second user-scoped flash transient and never stored in cleartext).
- **Opt-in public mode + GDPR-safe rate limit + 1-hour transient cache.** Operators who deliberately publish the endpoints can enable `wm_cra_public_endpoints` on the SBOM tab, throttled to 60 requests/min per salted SHA-256 IP digest (HTTP 429 on exhaustion, zero raw IP persistence). All four JSON endpoints cache serialized payloads in 1-hour transients invalidated automatically via `RestController::flush_caches()` on `activated_plugin`, `deactivated_plugin`, `switch_theme`, `upgrader_process_complete` and `CsafPublisher::publish_advisory()`.

### Translation catalog (2026-09-20)

- **127 of the 131 translatable strings had no entry in the `.pot`** — all but four. A string the code wraps in `__()` but that the catalog does not carry cannot be translated by anyone, to any language, ever, and nothing reports it: the admin screens simply stayed German. The template is now generated from the code with `wp i18n make-pot`, every `.po` merged with `msgmerge --no-fuzzy-matching` and every `.mo` rebuilt.
- **Of the 164 entries the catalogs translated, 156 were strings this code no longer has.** They became obsolete `#~` entries rather than being deleted, verified against the strings the code extracts **before** the merge rather than after it. Honest coverage is now 8 of 3,808 across the 28 catalogs.
- The Known issues note reporting mis-encoded text in `bg_BG`, `cs_CZ`, `da_DK` and `el` was stale: all 29 catalogs measure **0 double-encoded** since the repair pass of 2026-09-17.
- `tests/test-pot-freshness.php` and a CI step keep the catalog matching the code.

### Plugin Check errors in the distribution view (2026-09-17)
- **The `SERVER_SOFTWARE` banner is cleaned with `wp_strip_all_tags()`** instead of `strip_tags()` (Plugin Check, `strip_tags_strip_tags`, 1 error → 0). Nothing tested that markup and control characters were removed from that banner before it goes into the SBOM; a suite assertion now does, and a mutation that drops the cleaning turns it red.

### Added — SPDX 3.0.1 and OpenVEX (2026-09-16)
- **`includes/SPDX/Spdx3Generator.php`** and `GET /wp-json/wm-cra/v1/spdx`, `wp cra spdx-generate`. One measurement, two wire formats: procurement asks for SPDX, security tooling for CycloneDX, and a second document that disagreed with the first would be worse than not shipping one — an assertion compares the component names and versions of both.
- **Every SPDX term was read from the published 3.0.1 context and vocabularies, not recalled.** SPDX 3 renamed what SPDX 2 users know: the class is `software_Package` (`Package` is not in the context at all), the version is `software_packageVersion`, and `relationshipType`, `externalIdentifierType`, `software_sbomType` and `software_primaryPurpose` take vocabulary entries. The suite re-checks every emitted entry against the lists read from the specification, because an invented one makes the document validate against nothing and nothing in the plugin would notice.
- A licence taken from a free-text file header goes into `comment`, not into `hasDeclaredLicense`: it is not an SPDX identifier and the plugin cannot verify it.
- **`includes/Vuln/OpenVexEngine.php`** and `GET /wp-json/wm-cra/v1/vex`, `wp cra vex`. **A finding nobody has assessed is published as `under_investigation`** — the one VEX label that is true without anyone having assessed anything. `not_affected` requires one of the five justification labels from the VEX Working Group catalogue or a free-text impact statement; `affected` requires an action statement; both are refused without one. The document version changes whenever its content does, a restatement raises the statement's own version and keeps `first_issued`, and a statement about a finding the scan no longer reports stays in the document.
- The author is the security contact **only once an administrator has confirmed it**; the address the plugin guessed on activation is never published as an identity.

### Fixed — four checks of my own that measured nothing (2026-09-16)
- The vocabulary check had no component with an unmapped type, so the `other` fallback never ran and its mutation **SURVIVED**. The fixture component had been added to the wrong test group: the same two lines appear in two fixtures and the replacement hit the first.
- The `first_issued` check compared two timestamps generated in the same second, so keeping the date and resetting it produced the same string. The stored date is pushed into the past first.
- The author check ran with no contact stored at all, so both branches returned the site URL.
- An assertion counted packages as `count(...) - 1 + 1`.

- **The first statement did not change the document version.** Measured on a local WordPress install: an empty document and a one-statement document both reported `version: 1`, because the field read the stored counter directly. The content had changed and the version had not, which is the one thing the field exists for. The counter now counts changes and the version is that count plus one.

**Gate:** `php tests/test-suite.php` → **187 PASSED | 0 FAILED**. `bash tests/run-mutations.sh` → control green, **90/90 RED**, 0 SURVIVED, 0 NOT APPLIED. PHPUnit 2 tests / 13 assertions. `php tests/test-ui-family.php` → 6 passed.

**Measured on a local WordPress install:** the SPDX document holds 47 `software_Package` elements against the published context, 11 of them without a version (omitted, not invented), one `contains` relationship and a `software_Sbom` of type `deployed`. The four REST routes (`/sbom`, `/spdx`, `/vex`, `/csaf`) answer 200 with JSON. `wp cra vex` refuses `not_affected` without a justification, refuses a justification outside the catalogue and refuses `affected` without an action statement.


### Added — the unattended vulnerability audit (2026-09-16)
- **`includes/Vuln/`**: `OsvClient`, `NvdClient`, `CpeMatcher` and `VulnerabilityAudit`, plus the table `wm_cra_vulnerabilities`, a daily cron, `wp cra vuln-scan [--all]` and the *Schwachstellen* tab. This is the spec's *«Conector Automático con Bases de Datos OSV / NVD: auditoría desatendida diaria»*.
- **Each source is asked only about what it holds.** Measured 2026-09-16: OSV accepts `WordPress`, `WordPress:Core`, `WordPress:Plugin` and `WordPress:Theme` as ecosystems (an unknown one is rejected with `invalid ecosystem`) and answers `{}` for `contact-form-7 5.7.1`, `elementor 3.5.0`, `wordpress 6.4` and `twentytwentyone`; `CVE-2023-6553` is not in the database at all. Sending WordPress components there would have produced "no vulnerabilities" on every site for ever — a check with no variance. Composer and npm go to OSV, which does hold them (`symfony/http-kernel 4.4.0` returns two advisories, with or without the `v` prefix a lock file writes); WordPress components go to NVD.
- **A finding is matched against the installed version.** `CpeMatcher` reads the CVE's own CPE ranges — `versionStartIncluding`, `versionStartExcluding`, `versionEndIncluding`, `versionEndExcluding` — so a CVE fixed before the version in use is not reported. Without that, every CVE ever filed against a plugin would show on every install: a permanently red screen the operator learns to ignore.
- **`target_sw` decides whether a name match means anything.** The query uses a wildcard vendor (`cpe:2.3:a:*:contact_form_7`) because a plugin header states no CPE vendor and guessing one would be inventing part of someone else's identifier. Only matches whose eleventh CPE field is `wordpress` are kept, and `vulnerable: false` platform entries are not findings.
- **A component is never clean by default.** NVD allows five requests per 30 seconds without a key, so a run takes a budget and a cursor remembers where it stopped. Every component carries `checked` (with a timestamp), `never_checked`, `unknown_version` or `source_error`, and the screen leads with that state. An unreachable database leaves its components in `source_error`; a run that reached part of the inventory does not report itself complete.
- **No score is computed.** The newest CVSS metric NVD states wins (a CVE scored under both v2 and v3.1 is a v3.1 score); OSV states a vector rather than a number and the vector is kept as it stands.
- The optional NVD API key raises the limit from 5 to 50 requests per 30 seconds and the budget from 8 to 40 components; a value that cannot be a key is not stored, so the client falls back to the slower budget instead of sending a header the API rejects.

### Fixed — an assertion that was true whatever happened (2026-09-16)
- One of the new assertions ended in `|| $counts['never_checked'] >= 0`, which is true in every case. Replaced with a check that the four states add up to the component count and that no component falls out of the map.

**Gate:** `php tests/test-suite.php` → **159 PASSED | 0 FAILED**. `bash tests/run-mutations.sh` → control green, **72/72 RED**, 0 SURVIVED, 0 NOT APPLIED. PHPUnit 2 tests / 13 assertions. `php tests/test-ui-family.php` → 6 passed.


### Added — the inventory reaches past the plugin boundary (2026-09-16)
- **`includes/SBOM/DependencyScanner.php`.** The spec asks the inventory to map the Composer packages and npm dependencies, not only the units an administrator installs. A plugin carrying a `vendor/` directory runs every library in it, and that is where published vulnerabilities live. Read from `composer.lock` and `package-lock.json` (v1, v2 and v3 layouts), with `pkg:composer/` and `pkg:npm/` purls a vulnerability database can match, and an npm scope kept as a purl namespace.
- **Only lock files, never manifests.** `composer.json` states a range, `composer.lock` states the installed version, and this document writes versions. Development dependencies are skipped — a distribution build runs `composer install --no-dev` — and a lock file inside `vendor/` or `node_modules` describes another project's tree and is not read. A library two plugins bundle is one component whose properties name both.
- **`includes/SBOM/RuntimeInventory.php`.** PHP, the loaded extensions that wrap a library with its own release cycle, the database server and the web server banner. A site on an unsupported PHP or an end-of-life database is vulnerable through software no list of plugins mentions.
- **A reported version that is wrong is not written.** Measured 2026-09-16: `phpversion( 'openssl' )` returns **the PHP version** (8.5.10) on a stock build, not OpenSSL's. `php-ext-openssl@8.5.10` would send a scanner after a release that does not exist, which is worse than omitting the field. For `openssl` and `curl` the real library version is read from `OPENSSL_VERSION_TEXT` and `curl_version()` instead.
- **MariaDB is not reported as MySQL.** They announce themselves in one string and have different advisories.
- **`includes/SBOM/CryptoInventory.php`, off by default.** Hash algorithms, cipher methods and TLS versions as CycloneDX 1.6 `cryptographic-asset` components — including the weak ones still available, which is what a crypto inventory is for. Every enum value (`primitive`, `mode`, `assetType`, `protocolProperties.type`) comes from the published CycloneDX 1.6 schema, read on 2026-09-16 rather than recalled, and an assertion re-checks them. Off by default because on a stock PHP 8.3 with OpenSSL 3.5 it adds 186 components; on through the SBOM tab or `wp cra sbom-generate --crypto`, both going through the same filter so the screen and the command cannot produce different documents.

### Fixed — checks that measured half of what they claimed (2026-09-16)
- **`!isset( $a, $b )` is true when *either* is missing.** Two assertions covered two behaviours each, so a mutation only had to keep one side alive; both SURVIVED. One assertion per name now.
- `RuntimeInventory::web_server()` called `wp_unslash()` on `$_SERVER`, which WordPress does not slash (only `$_GET`, `$_POST`, `$_COOKIE` and `$_REQUEST`). Removed, and with it a dependency that stopped the PHPUnit run at "undefined function" while the standalone suite stayed green.
- `tests/bootstrap.php` lacked `apply_filters`, `get_site_option` and `WP_PLUGIN_DIR`, so the PHPUnit run could not reach the new code at all.
- `uninstall.php` did not delete `wm_cra_sbom_include_crypto`.

- **A command parameter may have only one description line.** Measured on a local WordPress install: `[--crypto]` with its description over two `: ` lines made WP-CLI print one warning per word of the first line **on STDOUT**, which destroys the JSON pipe `sbom-generate` promises. A new assertion reads the docblocks and fails on two consecutive `: ` lines — only that rule, since reimplementing WP-CLI's whole token grammar would trade a real check for an invented one.

**Gate:** `php tests/test-suite.php` → **120 PASSED | 0 FAILED**. `bash tests/run-mutations.sh` → control green, **52/52 RED**, 0 SURVIVED, 0 NOT APPLIED. PHPUnit 2 tests / 13 assertions. `php tests/test-ui-family.php` → 6 passed.

**Measured on a local WordPress install:** 46 components without the CBOM and 235 with it (188 cryptographic assets, among them `md4`, `md5`, `sha1` and `des-ede3-cbc` — the point of the list). `php-ext-openssl` carries **3.5.6**, OpenSSL's version, not PHP's 8.3.33, and the extensions compiled into PHP carry none. Against real third-party lock files (`wp-rocket`, `perfmatters`): 13 libraries with their purls, 0 development dependencies leaked, 0 lock files read out of `vendor/`. The WM Suite plugins themselves report 0 bundled libraries, which is correct — their `composer.lock` files hold 27 development packages and no runtime ones.


### Family sheets (2026-09-16)
- Re-synced from the hub: the badge variants carry the state tokens on body surfaces, where the command-banner inks measured 1.49:1 to 2.21:1 against the composed background (hub PR #19), and the canonical sheet dropped five classes that belonged to a single plugin (hub PR #21). `tests/test-ui-family.php` re-pins both md5s.

### Fixed (2026-09-15)
- **`/.well-known/security.txt` answered 404 after activation.** WordPress includes the plugin file during activation after `init` has run, so the rules `SecurityTxtHandler::init()` adds were not registered when `Schema::activate()` flushed; the stored rules lacked the route (measured on a local WordPress install: 404, rule absent from `rewrite_rules`). Activation registers the rules before the flush; sites activated earlier get one soft flush on the next request. Deactivation deletes the stored rules instead of flushing them back in.
- **Then it answered 301.** `redirect_canonical()` ran first on `template_redirect` and redirected to `/.well-known/security.txt/`. The file is printed at priority 0. Measured on a local WordPress install after the fix: 200 `text/plain`.
- **The settings form changed nothing that was served.** It wrote `wm_cra_settings`, which no code read, set `pgp_key_url` to empty on every save (the form had no such field) and reported success for an invalid e-mail. It now writes the five security.txt options, validates Contact (e-mail or https URL), Expires (future, at most one year), language tags and https URLs, and saves nothing when a field is invalid. Expires and the encryption key are new fields. `esc_url_raw( 'not-an-email', [ 'https' ] )` returns `https://not-an-email` on WordPress 7.1, so the URL check reads scheme and host from the input.
- **Health, self test and telemetry reported success for any stored contact**, which activation always writes; an expired file was HEALTHY. They follow `SecurityTxtHandler::status()` now; the guessed activation contact is NEEDS_CONFIG until the form is saved; missing tables are ERROR. The hub settings link pointed to `page=wm-cra-dashboard`, which does not exist.
- **Fixed values in the admin.** Widget: "18 Komponenten" (read from an option nothing wrote), "CycloneDX v1.6 SBOM Signatur gültig" (no signing exists), "PSIRT Feed Aktiv". Header: "CIBERRESILIENCIA OK", "SECURITY.TXT ACTIVO". Overview: "RFC 9116 verificado", a preview with a fixed `Expires: 2027-08-27T00:00:00Z`, an advisory count capped at 10. SBOM tab: a "Licencia" column that printed the description with a `GPL-2.0+` fallback. All values are computed now; the preview is the served file.
- **SBOM content.** The only hash was SHA-256 of the WordPress version string; every plugin was licensed `Proprietary`; missing versions became `1.0.0` or `6.8` and an empty version produced a purl ending in `@`; purl types `wordpress-plugin`/`wordpress-theme` are not registered. Licences come from the file headers as names, unknown values are left out, purls use the registered `generic` type, network-active and must-use plugins and the parent theme are included, `authors` replaces the deprecated `author`. Three code paths serialised and timestamped snapshots differently; there is one serialisation and UTC.
- **`wp cra sbom-generate`** printed "Success:" lines into the JSON on STDOUT, stored a snapshot on every call, and reported a failed file write as success. JSON only on STDOUT; `--snapshot` stores; failures are errors.
- **`wp cra csaf-publish`** wrote `CVE-2026-CRA-LOCAL` and a CVSS score of 7.5 or 9.8 into every advisory, accepted any severity (`banana` gave `BANANA`) and reset the initial release date on re-publication. CVE only with `--cve`, no scores, severity validated, revision history kept.
- **CSAF documents** claimed the Security Advisory profile without product tree or product status and lacked `revision_history`; the index named "WM Suite PSIRT / BSI CSIRT Liaison" as issuing authority on every site, and security.txt pointed its `CSAF:` field at that index. Documents use the base profile with every required field; the index says it is not a provider feed; security.txt lists both JSON links as comments.
- **Public box:** "Offizielle Koordinierungsstelle für Schwachstellenmeldungen", a "EU CRA & BSI TR-03183" badge, and with no advisories "Alle Systeme entsprechen dem aktuellen Patch-Stand" (nothing checked it); a missing score showed "CVSS 0.0". Neutral German texts, severity as stated.
- **Uninstall** deleted five options nothing wrote and left `wm_cra_settings` and the uploads directory; it removes what the plugin writes, on every site of a network.

### Removed (2026-09-15)
- `RequestShield` ran on every request, logged "[WM-SECURITY-BLOCK]" with the client IP for any GET, POST or cookie value containing a stream wrapper (a comment mentioning `file:///etc/hosts` included) and blocked nothing. The plugin's routes take no parameters.
- `DirectoryProtector` created `uploads/wm-cra/sbom` with four guard files on every request; nothing writes there.
- `UploadShield`, `RateLimiter`, `ErrorSanitizer`: no caller. The `wm_cra_audit_log` table is no longer created (it was never written).
- The admin `publish_csaf` handler: no form posted it, and a crafted POST stored a document without the CSAF required fields.

### Changed (2026-09-15)
- Admin screen and widget in German (they were Spanish, the public box German, the CLI English), dashicons instead of emoji, labelled form fields; the family sheets also load on the WordPress dashboard for the widget.
- Network activation creates tables and defaults on every site.

### Documented (2026-09-15)
- README, readme.txt, `docs/ARCHITECTURE.md`, `docs/DEVELOPER-GUIDE.md`, `public/humans.txt` rewritten from the code; `docs/LEGAL-COMPLIANCE.md` with sources (Regulation (EU) 2024/2847, RFC 9116, CSAF 2.0, CycloneDX 1.6, BSI TR-03183, purl registry). Removed: "Compliance Suite", "PSIRT Incident Timeline Engine", "PGP key references", "C4 model", "XML feed", "BSI TR-03183 (Parts 1–4)", "CRA 2026/2027", "Founder & CEO". The banner and the "UI showcase" are no longer referenced or packaged.
- Tests: `tests/test-suite.php` rewritten (89 assertions, mock `$wpdb` that throws on unknown SQL), `tests/run-mutations.sh` with 33 mutations, `tests/wp-runtime-cra.php`; CI runs the standalone suites and the mutation check, not only the two PHPUnit tests.

## [1.0.0]
- Initial release.
