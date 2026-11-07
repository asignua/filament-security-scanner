# Changelog

All notable changes to `asignua/filament-security-scanner` are documented here.

## Unreleased

First public release, `v1.0.0` when tagged. It continues the private `asign/eegnith-security-scanner` (last tag `v1.x`): the
scanning behaviour, tables, config key (`security-scanner`), `SECURITY_SCANNER_*` environment variables, translation namespace
(`security-scanner::`), view names, gate names (`security-scanner.*`), commands (`security:*`) and finding fingerprints are
unchanged, so stored findings, quarantine copies and settings keep working. The two packages cannot be installed together
(`conflict`).

### Breaking (relative to the predecessor)

- **Gates deny by default.** `security-scanner.view`, `.quarantine`, `.triage` and `.restore` used to allow every panel user
  when undefined; now an undefined gate denies everybody. `triage` still inherits `quarantine`. Define the gates before updating.
- Namespace `Asignua\FilamentSecurityScanner`; the plugin class is `Asignua\FilamentSecurityScanner\SecurityScannerPlugin`.
  There are no class aliases: let queued scanner jobs finish before switching.
- The vendor path changed, so run `security:baseline --zone=vendor` once in the deploy that switches packages.
- Messages produced by the scanner (zone, git, rule-validation and command output) are now in English. The fingerprint of an
  open "heuristics registry rejected a rule" finding depends on that text, so such a finding may reappear as new once.
- Russian translations were dropped.

### Changed

- PHP `^8.3` and Laravel 12 or 13 (the predecessor required PHP 8.4 and Laravel 13).
- Code comments are in English.
- The empty upstream rules layer (`heuristics.upstream.php`) and the sync with an external rules repository are gone; rules
  merge package -> host.
- Locales: en, uk, pl, de, es, fr, it, nl, pt_BR, tr (the new ones are machine translations).
- Allowlist path for the plugin's own sample files is `vendor/asignua/filament-security-scanner/tests/fixtures/**`.

### Added

- Feature tests on testbench (deny by default, registration, a scan/quarantine/restore flow, self-scan from `vendor/`), a
  fingerprint compatibility pin, a workbench with demo findings, Laravel Boost guidelines.
