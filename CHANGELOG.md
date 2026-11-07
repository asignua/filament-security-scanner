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

### Fixed

- A negative file mtime/size (`touch -d 1960-01-01`) overflowed the unsigned columns on MariaDB (error 1264) and lost the
  finding; values are clamped (findings and baseline). A baseline batch that fails is retried row by row, a failed
  re-verification update is reported instead of aborting the run.
- A zone outside `base_path()` is refused with a visible issue (it used to be scanned under pseudo-relative paths, and its
  findings were closed by re-verification). Documented under README Limits.
- `obf.oversized-unreadable` (no content hash) is re-checked by size and stays open while the file is still too large.
- Quarantine (manual, automatic and restore) is contained by the zone instead of the project root, so a symlinked `storage`
  (Deployer) works; symlinks inside the zone are still refused. Auto-quarantine failures and refusals are listed in the run's issues.
- The legacy `ee.` title migration runs in PHP in chunks (no SQL `CONCAT`, which needs SQLite 3.44+) and is a no-op without rows.

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
- **A file that cannot be stat-ed or opened no longer crashes a scanner.** `getSize()/getMTime()/getPerms()` throw despite `@`:
  a directory with mode `0444` lists but does not stat, which crashed the uploads, obfuscation and hygiene scanners (hygiene
  died before reporting any degradation and later zones went unscanned). The file is skipped, the scanner is marked
  incomplete and the run continues. An existing file that cannot be opened (`chmod 000`) keeps its content finding open
  instead of closing it as gone. The baseline snapshot tolerates the same.
- **`git status` no longer runs clean/smudge filters.** The config is read first (all scopes, `include.path` followed),
  every flagged filter is emptied and made non-required for the run, and the value check is anchored (`clean = true && cmd`
  used to pass). Exact git-lfs filters are left intact. New rule `code.git-executable-config` reports each such key.
- **Nested repositories are expanded.** A nested repository (or one that ignores itself) shows up in `git status` as one
  `dir/` entry; its PHP files are now reported individually as untracked executables. `resources` joined the default
  `git.ignored_php_paths`.
- **Staged additions (`A`), copies (`C`) and unmerged paths (`U`)** map to rules. `security:baseline` records the git `HEAD`
  and a scan raises `code.git-head-moved` while `HEAD` differs from it (a commit used to make everything clean). The deploy
  must run `security:baseline`.
- **`public/storage` is allowlisted only as the storage symlink.** A link to anything else (for example `..`, which exposes
  `.env`) is scanned and reported as `hygiene.foreign-storage-link`.
- **Quarantine and restore decide by the zone the path really lies in**, not by the row's `zone_kind` column: a tampered row
  could move `public/index.php` and restore a file into the webroot. Moves never overwrite an existing target (`link()` +
  `unlink()`), and the placement is verified afterwards.
- **Database notifications are written in the recipient's locale** (`HasLocalePreference`, otherwise the app locale)
  instead of the CLI locale the scan runs in.
- The empty state distinguishes "no scan has run yet" from "scans ran and found nothing" (new translation keys, 10 locales).
- **Quarantine and restore decide by the zone the path really lies in**, not by the row's `zone_kind` column: a tampered row
  could move `public/index.php` and restore a file into the webroot. Moves never overwrite an existing target (`link()` +
  `unlink()`), and the placement is verified afterwards.
- **Database notifications are written in the recipient's locale** (`HasLocalePreference`, otherwise the app locale)
  instead of the CLI locale the scan runs in.
- The empty state distinguishes "no scan has run yet" from "scans ran and found nothing" (new translation keys, 10 locales).
- A file named `.php` (or `.php.jpg`) now counts as PHP-executable.

### Added

- **Git invocation hardened.** Config overrides travel through `GIT_CONFIG_COUNT/KEY_n/VALUE_n` (a filter name containing
  `=` used to survive `-c`); `--no-lazy-fetch` (when git supports it), `--no-replace-objects`, `--ignore-submodules=all`
  (gitlinks are reported once as a scan issue), `core.trustctime=true`, `core.checkStat=default`,
  `diff.ignoreSubmodules=none`; every inherited `GIT_*` variable (environment, `$_ENV`, `$_SERVER`) is dropped. git-lfs
  filters run with `GIT_LFS_SKIP_SMUDGE=1` and non-required (a read-only `.git` no longer makes git "unavailable") and are
  emptied when `alias.lfs` or another trick is present. `alias.lfs`, `remote.*.uploadpack`, `remote.*.promisor` and
  `extensions.partialClone` are reported by `code.git-executable-config`.
- **A hygiene stage that throws no longer ends the run silently** (for example `chmod 0311 public` made the world-writable
  walk throw): the stage is recorded as an issue, the scanner is marked incomplete and `hygiene.scanner-degraded` is
  always evaluated.
- New rule `code.head-unrecorded` (medium): git is available but no baseline ever recorded a `HEAD`. The `HEAD` SHA is now
  part of the path of `code.git-head-moved` too, so an ignored finding does not mask a later move.
- **Restore / move fallback no longer uses `rename()`**: across filesystems it copied through a symlink planted at the
  target and overwrote what it pointed at. It copies with `fopen($target, 'xb')` and then removes the source.
- New translation key (all 10 locales) for `code.head-unrecorded`.
- **Setting `security-scanner.git.enabled`** (`SECURITY_SCANNER_GIT`, default on) for sites deployed without a `.git`: with it
  off, `code.git-unavailable` and the matching `hygiene.scanner-degraded` are not raised; with no baseline at all one
  `code.baseline-missing` hint (path `git-off`) remains.
- A symlinked `storage/` (Deployer layout) no longer produces `code.deleted-file` for the tracked files below it.
- New rule `code.git-dir-writable` (medium): the PHP user can write to `.git`, so git results cannot be trusted. Not raised
  when `app.env` is `local` or `testing`. README "Limits" explains the trust model.
- New translation key (all 10 locales) for `code.git-dir-writable`.
- New translation keys (all 10 locales) for `code.git-executable-config`, `code.git-head-moved` and
  `hygiene.foreign-storage-link`.
- New rules `code.ignored-php-file` (PHP hidden from git by a nested `.gitignore`, directories in
  `security-scanner.git.ignored_php_paths`) and `code.git-index-flag` (`assume-unchanged` / `skip-worktree`). Sites with
  legitimately ignored PHP files in those directories should allowlist them. New translation keys exist in all 10 locales.

- Feature tests on testbench (deny by default, registration, a scan/quarantine/restore flow, self-scan from `vendor/`), a
  fingerprint compatibility pin, a workbench with demo findings, Laravel Boost guidelines.
