# Regulations and specifications — WM CRA SBOM & Vulnerability Beacon

What the plugin does for each rule it names, checked against the source on 2026-09-15. The plugin makes no legal assessment: it does not decide whether a rule applies to a site or its operator.

The previous edition of this file stated that "Annex I" requires "24h early warning, 72h detailed notification to ENISA/CSIRTs", that BSI TR-03183 Part 1 is a "risk-based control catalog in OSCAL format" and that Part 2 requires CycloneDX 1.6, and the architecture file cited "BSI TR-03183 (Parts 1–4)". None of these match the sources below.

## Sources

| Source | Where | Retrieved |
| --- | --- | --- |
| Regulation (EU) 2024/2847 (Cyber Resilience Act) | EU Publications Office, CELEX 32024R2847, English XHTML (`http://publications.europa.eu/resource/celex/32024R2847`); EUR-Lex answered automated requests with an empty 202 | 2026-09-15 |
| Commission page "Cyber Resilience Act – Reporting obligations" | digital-strategy.ec.europa.eu/en/policies/cra-reporting | 2026-09-15 |
| RFC 9116 (security.txt) | rfc-editor.org/rfc/rfc9116.txt | 2026-09-15 |
| CSAF 2.0 JSON schema and specification (OASIS) | github.com/oasis-tcs/csaf `csaf_2.0/json_schema/csaf_json_schema.json`; docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html | 2026-09-15 |
| CycloneDX 1.6 JSON schema | github.com/CycloneDX/specification `schema/bom-1.6.schema.json` | 2026-09-15 |
| BSI TR-03183 overview | bsi.bund.de, Technische Richtlinie TR-03183 | 2026-09-15 |
| purl type registry | github.com/package-url/purl-spec `purl-types-index.json` (42 types) | 2026-09-15 |

## Cyber Resilience Act

| Provision (quoted or summarised from the source) | What the plugin does |
| --- | --- |
| Art. 3 (39): "'software bill of materials' means a formal record containing details and supply chain relationships of components included in the software elements of a product with digital elements" | Lists the WordPress components a site loads (core, active and must-use plugins, themes) with the details their headers state. No supply chain relationships between them, no libraries inside plugins. |
| Annex I Part II (1): manufacturers shall "identify and document vulnerabilities and components contained in products with digital elements, including by drawing up a software bill of materials in a commonly used and machine-readable format covering at the very least the top-level dependencies of the products" | Produces a machine-readable CycloneDX document of the site's components. It does not identify or document vulnerabilities. |
| Annex II (9): "If the manufacturer decides to make available the software bill of materials to the user, information on where the software bill of materials can be accessed." | The inventory is public by default at `/wp-json/wm-cra/v1/sbom` (README, Known issues: open decision). |
| Annex VII (8): the technical documentation contains, "where applicable, the software bill of materials, further to a reasoned request from a market surveillance authority" | No technical documentation is produced. |
| Annex VII (2)(b): the technical documentation describes the vulnerability handling processes, "including the software bill of materials, the coordinated vulnerability disclosure policy, evidence of the provision of a contact address for the reporting of the vulnerabilities …" | security.txt publishes a contact address and, when set, a policy URL. |
| Art. 14 (2): early warning of an actively exploited vulnerability "within 24 hours", vulnerability notification "within 72 hours", final report "no later than 14 days after a corrective or mitigating measure is available" | Not covered. |
| Art. 71 (2): "This Regulation shall apply from 11 December 2027. However, Article 14 shall apply from 11 September 2026 and Chapter IV (Articles 35 to 51) shall apply from 11 June 2026." | Stated in the admin glossary. |

The plugin header said "CRA 2026/2027"; the regulation is 2024/2847.

## RFC 9116 (security.txt)

| Requirement | What the plugin does |
| --- | --- |
| 2.5.3 Contact: required; a URI, `mailto:` for e-mail addresses | Required in the form; an e-mail address is stored as `mailto:`; an https URL is kept. The activation default `security@<host>` is marked unconfirmed, and invalid on hosts without a dot. |
| 2.5.5 Expires: required, exactly once, RFC 3339; "RECOMMENDED that the value of this field be less than a year into the future" | Required in the form; past dates and dates more than 365 days ahead are refused; activation writes 11 months ahead; admin and hub report `expiring` 30 days before and `expired` after. |
| 2.5.2 Canonical, 2.5.4 Encryption, 2.5.7 Policy: optional; web URIs begin with `https://` | Canonical from the site URL; Encryption and Policy only as https URLs. |
| 2.5.8 Preferred-Languages: optional, comma-separated | Language tags validated and normalised. |
| 2.4: researchers "MUST ignore any fields they do not explicitly support"; new fields through an IANA registry | The links to the SBOM and the advisory index are comment lines, not fields. |

## CSAF 2.0

| Requirement | What the plugin does |
| --- | --- |
| `/document` requires `category`, `csaf_version`, `publisher` (`category`, `name`, `namespace`), `title`, `tracking` | All present. |
| `/document/tracking` requires `current_release_date`, `id`, `initial_release_date`, `revision_history` (items: `date`, `number`, `summary`), `status`, `version` | All present; integer versioning, the initial release date is kept on re-publication. |
| Profile 1 (CSAF Base) uses category `csaf_base`; Profile 4 (Security Advisory) additionally requires `product_tree` and `product_status` | Documents use `csaf_base`. Until 2026-09-15 they claimed `csaf_security_advisory` without either. |
| `/vulnerabilities[]/scores[]` requires `products`; `cvss_v3` follows the FIRST CVSS schema | No scores are written. Until 2026-09-15 the CLI wrote 7.5 or 9.8 and a CVSS object with only `baseScore` and `baseSeverity`. |
| Provider requirement 8: security.txt points to the `provider-metadata.json` | The plugin publishes no provider metadata, so security.txt carries no `CSAF:` field (until 2026-09-15 it pointed to the plugin's own index). |

## CycloneDX 1.6

| Schema rule | What the plugin does |
| --- | --- |
| A component requires only `type` and `name`; `version` is optional | Unknown versions are left out (until 2026-09-15: "1.0.0", "6.8"). |
| `license.id` must be an SPDX identifier; `id` and `name` are mutually exclusive | Licences are written as `name` from the file header, or omitted. Until 2026-09-15 every plugin was `id: "Proprietary"` and the hub adapter sent `id` and `name` together. |
| `author` (string) is deprecated in favour of `authors` / `manufacturer` | `authors` with one name. |
| `hash.alg` values include `SHA-256` | No component hashes. Until 2026-09-15 core carried the SHA-256 of its version string. |

purl: the registry lists 42 types and none for WordPress; components use the registered `generic` type (`pkg:generic/wordpress-plugin/<slug>@<version>`). Until 2026-09-15 they used the unregistered types `wordpress-plugin` and `wordpress-theme`.

## BSI TR-03183

The BSI lists Part 1 "General Requirements" (1.0.0), Part 2 "Software Bill of Materials (SBOM)" (2.1.0), Part 3 "Vulnerability Reports and Notifications" (1.0.0) and Part H "Conformity based on full quality assurance (Module H)" (1.1.0). Part 2 recommends a mapping of its data fields to SPDX and CycloneDX. The BSI states: "This document is meant to be a guide and is not binding or mandatory. It cannot be used as presumption of conformity."

The plugin was not checked against the field list of Part 2; it makes no TR-03183 claim. Until 2026-09-15 the served security.txt, the admin screen, the REST comments and the hub SBOM properties claimed TR-03183-2 conformance, and the public feed named a "BSI CSIRT Liaison".
