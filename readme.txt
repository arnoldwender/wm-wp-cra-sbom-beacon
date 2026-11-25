=== WM CRA SBOM & Vulnerability Beacon ===
Contributors: arnoldwender
Tags: sbom, cyclonedx, security-txt, csaf, vulnerability-disclosure
Requires at least: 6.4
Tested up to: 7.1
Requires PHP: 8.2
Stable tag: 1.2.2
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

CycloneDX 1.6 inventory of the active code, security.txt (RFC 9116) from admin settings, advisories as CSAF 2.0 base documents.

== Description ==

* **Software inventory:** `GET /wp-json/wm-cra/v1/sbom`, `wp cra sbom-generate` and an admin tab list WordPress core, active and must-use plugins, the active theme with its parent, bundled Composer/npm lockfile packages and runtime libraries. All four REST JSON routes (`/sbom`, `/spdx`, `/vex`, `/csaf`) require `manage_options` or `Authorization: Bearer <token>` by default, cache responses for 1 hour, and offer an explicit opt-in public mode rate-limited to 60 requests/min.
* **security.txt:** `/.well-known/security.txt` from five validated settings, filtered through `wm_cra_security_txt_output`. Admin, widget, Block Bindings (`wm-cra-beacon/status`), GenerateBlocks 2.x Dynamic Tag (`{{wm_cra_beacon_status}}`) and hub show whether the file is usable, expiring, expired or unreachable; the contact written on activation stays unconfirmed until the form is saved.
* **Advisories:** `wp cra csaf-publish` stores CSAF 2.0 documents (base profile) with revision history; `GET /wp-json/wm-cra/v1/csaf` lists them. No CVE or score is filled in.
* **Public box & Gutenberg block:** `[wm_cra_psirt]`, `[wm_security_disclosure]` and the Gutenberg block `wm/cra-psirt` (with `InspectorControls` and `ServerSideRender`) display the security contact, optional JSON links and published advisories.
* **Uninstall:** Preserves all options and the 3 CRA Beacon database tables by default across reinstalls unless the administrator explicitly enables `wm_cra_beacon_delete_data_on_uninstall` on the *security.txt* settings tab.
* **Translations:** Complete `.po`, `.mo` and JED `.json` catalogs across 28 locales.

**What it does not do.** No assessment of whether the Cyber Resilience Act applies, no Article 14 reporting, no CSAF provider metadata.

== Frequently Asked Questions ==

= Is technical or private support provided? =

No. This plugin comes with zero support (`0` support). Private inquiries sent via email, `arnoldwender.com`, or social/chat channels are not answered. Reproducible bugs belong solely on GitHub Issues (`https://github.com/arnoldwender/wm-wp-cra-sbom-beacon/issues`) with no guarantee of reply or resolution. The software is provided **"AS IS"** at your sole risk with zero warranty or liability (see `SUPPORT.md` in the repository).

== Screenshots ==

1. Admin overview: component count, security.txt state, stored snapshots and published advisories
2. Block editor showing the wm/cra-psirt disclosure block
3. Public security disclosure portal rendered on a page via [wm_cra_psirt]

== Changelog ==


= 1.2.2 =
* Fixed: Screenshot 1 showed the WM Suite menu from before WM Suite Hub 1.2.3, with entries the hub no longer has («Marketplace (Lösungspakete)», «Merkle-Audit-Protokoll», «CRA- & SBOM-Zentrale»). It is retaken with the current menu; the plugin's code is unchanged.

= 1.2.1 =
* The bundled family stylesheet is identical to WM Suite Hub 1.2.5 again: it starts the admin header below WordPress's help toggle instead of shortening it. This plugin's own screens register no help tab, so they change only where another plugin adds one.

= 1.2.0 =
* The WM Suite Hub contract now lives in the `ArnoldWender\SuiteHub\Contracts` namespace. The spoke adapter registers only with WM Suite Hub 1.2.0 or later, so update the hub together with this plugin; used on its own, the plugin works as before.
* The `.wordpress-org/` banners show the current version.
* The description of the first screenshot names what it shows, the admin overview; it described CycloneDX 1.5 / SPDX 2.3 export controls and an advisory generator the screen does not have.
* Removed: The archived pre-2026-11-19 marketing visuals in `versionen/`: they claimed features and conformity the plugin does not have. They were never part of the installable package.

= 1.1.4 =
* Removed the agency name, links to unrelated projects and the personal mailbox from code, catalogs and documentation; the admin family badge and the hub menu read "WM Suite". The READMEs say the plugin was built with an agentic workflow (AI coding agents) and should be reviewed like any third-party code.
* Added root `SUPPORT.md`, GitHub Issue templates, explicit zero-support & "AS IS" liability notices in READMEs and `readme.txt`, and normalized canonical GPLv2+ `arnoldwender.com` / `arnoldwender/wm-wp-cra-sbom-beacon` links.
* Updated `.wordpress-org/` visual banners to personal `ARNOLD WENDER · OPEN SOURCE` branding.

= 1.1.3 =
* Add `.wordpress-org/` vector icons, banners (`772x250`, `1544x500`), live WordPress screenshots (`screenshot-1..3.png`) and `== Screenshots ==` descriptions.
* Add `README.de.md`, `README.es.md`, root `llms.txt`, live previews, and direct plugin catalog link (`https://arnoldwender.com/wordpress-plugins/wm-cra-sbom-beacon/`).

= 1.1.2 =
* Point Plugin URI to the official plugin page and enabled lexer-based security-audit CI step.

= 1.1.1 =
* Fixed: multisite network activation now provisions database tables, default options and rewrite rules automatically when a new subsite is initialized via `wp_initialize_site` (inside `try/finally` with `switch_to_blog()` / `restore_current_blog()`).
* Changed: added explicit `$autoload = false` on non-frontend `update_option()` calls in `AdminDashboard` and `Schema::activate_site()`.

= 1.1.0 =
* Added: compiled `wm/cra-psirt` Gutenberg block (`blocks/cra-psirt/block.json`, `blocks-src/index.js`, `build/index.js`, `build/index.asset.php`) with `InspectorControls` toggles and `ServerSideRender` preview in the Block Inserter.
* Added: WordPress 6.5+ Block Bindings source `wm-cra-beacon/status` and GenerateBlocks 2.x Dynamic Tag `{{wm_cra_beacon_status}}` exposing computed `security.txt` state fields.
* Added: `wm_cra_beacon_ready` action on boot and `wm_cra_security_txt_output` filter on `/.well-known/security.txt` output.
* Added: CycloneDX 1.6 `bom.json` and WordPress Playground blueprint (`.wordpress-org/blueprints/blueprint.json`).
* Added: complete translations across all 28 locales (`.po`, `.mo` and JED `.json` editor catalogs).
* Security: closed `/wp-json/wm-cra/v1/sbom`, `/spdx`, `/vex` and `/csaf` by default behind `manage_options` or `Authorization: Bearer <token>` (storing only a SHA-256 token hash in `wp_options` or reading `WM_CRA_API_TOKEN` from `wp-config.php`), added 1-hour transient caching with automatic invalidation on plugin/theme/upgrader/advisory changes, added an opt-in public toggle with GDPR-safe salted-IP rate limiting (60 req/min), and escaped header badge attributes (`esc_attr`).
* Changed: `uninstall.php` now preserves all options and the 3 CRA Beacon tables by default unless `wm_cra_beacon_delete_data_on_uninstall` (registered via `register_setting` and exposed on the *security.txt* tab) is explicitly enabled.
* Fixed: `/.well-known/security.txt` answered 404 after activation and then a 301 to a trailing slash; existing sites are repaired on the next request.
* Fixed: settings form validation for Contact, Expires, language tags and https URLs; health, self test and telemetry computed from `SecurityTxtHandler::status()`.

= 1.0.0 =
* Initial release.

== Upgrade Notice ==

= 1.2.2 =
Screenshot 1 retaken with the current WM Suite menu. No code, data or settings change.

= 1.2.1 =
Stylesheet update only (the family sheet of WM Suite Hub 1.2.5). No data or settings change.

= 1.2.0 =
Hub users: update WM Suite Hub to 1.2.0 together with this plugin. The hub contract moved to a new PHP namespace; next to an older hub the plugin keeps working, but it is not listed in the cockpit and its admin page has no menu entry until the hub is updated.
