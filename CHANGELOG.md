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

### Fixed (behaviour changes)

- **PostgreSQL:** `content_hash` is `varchar(64)` instead of `char(64)` (PostgreSQL pads `char(n)`, so a 32-char xxh128 never
  equalled the fresh hash and every vendor file was reported as `code.baseline-modified`). Tables that already exist keep
  `char`; the comparison trims the padding, so no migration is needed. The other `char` columns (`fingerprint`,
  `path_hash`, `snapshot_id`) always hold full-length values and are unaffected.
- **Restore reopens the finding.** Restoring a quarantined file now sets the finding back to `New`, clears `quarantined_at`,
  `quarantine_path` and the notification stamps, so every channel alerts again and a re-scan does not stay silent about a
  live web shell. It used to become `Acknowledged`. An admin who restored a false positive closes it with **Ignore**.
- **Non-UTF-8 file names** cannot be quarantined: the action is refused with a clear message and the finding stays open.
- **Unreadable directories** (for example `chmod 0311`, which still executes files by name) are no longer skipped silently.
  The scanner that walked them is marked incomplete (it closes no findings), the run lists the directory in its issues and
  a `hygiene.scanner-degraded` finding is raised.
- **Quarantine and restore stay inside the zone.** A backslash is no longer a path separator on POSIX (a file named
  `..\..\public\index.php` used to be normalised into a real traversal), stored paths with `..` segments are refused, and
  the file and its parent directory must resolve inside the ZONE root, checked again right before the move (manual,
  automatic and restore).
- Notification bodies (panel alerts, quarantine/restore errors, scan errors) are HTML-escaped; a file name could inject a link.
- The evidence entry on the finding page shows the rule and excerpt (it rendered just `:`); its hidden label is translated.
- `git status` runs with `core.fsmonitor=false` and `core.hooksPath=/dev/null`; commands configured in `.git/config`
  (fsmonitor, non-LFS filters, diff/merge drivers, ssh command) are reported as scan issues.
- The Telegram bot token is redacted (`/bot<redacted>/`) from logged exception messages.
- `webroot.unexpected-php` matches `.php .phtml .phar .pht .php3-8` in any case (`.PHP`); `public/index.php` stays the only
  exemption (case-sensitive).
- The findings list has an empty state that tells the admin to run `php artisan security:scan`.

### Added

- New rules `code.ignored-php-file` (PHP hidden from git by a nested `.gitignore`, directories in
  `security-scanner.git.ignored_php_paths`) and `code.git-index-flag` (`assume-unchanged` / `skip-worktree`). Sites with
  legitimately ignored PHP files in those directories should allowlist them. New translation keys exist in all 10 locales.

- Feature tests on testbench (deny by default, registration, a scan/quarantine/restore flow, self-scan from `vendor/`), a
  fingerprint compatibility pin, a workbench with demo findings, Laravel Boost guidelines.
