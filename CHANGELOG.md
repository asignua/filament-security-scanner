# Changelog

All notable changes to `asignua/filament-security-scanner` are documented here.

## v1.1.0 - 2026-11-10

- Requires Filament ^5.11.2; replaced deprecated Filament API calls: Requires Filament ^5.11.2; replaced deprecated Filament API calls (BaseFilter::schema() → form() in the findings table).

## v1.0.0 - 2026-11-09

First public release. It continues the private `asign/eegnith-security-scanner` (last tag `v1.x`): scanning behaviour,
tables, config key (`security-scanner`), `SECURITY_SCANNER_*` environment variables, translation namespace
(`security-scanner::`), view names, gate names (`security-scanner.*`), commands (`security:*`) and finding fingerprints are
unchanged, so stored findings, quarantine copies and settings keep working. The two packages cannot be installed together
(`conflict`).

Requires PHP 8.3+, Laravel 12 or 13 and Filament 5. Detection, not protection: it reports traces of intrusion, it does not
block anything.

### Features

- Four scanners: `code` (drift from git and from a hash snapshot of `vendor/`), `uploads` (executable code and polyglots
  in upload folders), `obfuscation` and `hygiene` (risky runtime settings, world-writable files, foreign storage links).
- Rules are data (`resources/heuristics/*.php`), overridable from the host app.
- A read-only findings resource with evidence, acknowledge / ignore, quarantine and restore.
- Alerts in the panel, by e-mail and Telegram, each channel with its own threshold and throttling; synchronous check of a
  file the moment it is added to the media library (optional `spatie/laravel-medialibrary`).
- Commands `security:scan`, `security:baseline`, `security:rules`, `security:prune`, `security:notify`, scheduled by the plugin.
- Hardened git invocation (no hooks, fsmonitor or clean/smudge filters run; inherited `GIT_*` variables dropped), setting
  `security-scanner.git.enabled` for sites deployed without `.git`.
- English, Ukrainian, Polish, German, Spanish, French, Italian, Dutch, Brazilian Portuguese and Turkish (all but English and
  Ukrainian are machine translations).

### Upgrading from `asign/eegnith-security-scanner`

- **Gates deny by default.** `security-scanner.view`, `.quarantine`, `.triage` and `.restore` used to allow every panel user
  when undefined; now an undefined gate denies everybody (`triage` still inherits `quarantine`). Define the gates before updating.
- Namespace is `Asignua\FilamentSecurityScanner`, the plugin class `Asignua\FilamentSecurityScanner\SecurityScannerPlugin`.
  There are no class aliases: let queued scanner jobs finish before switching.
- **Deploy step:** the vendor path changed, so run `php artisan security:baseline --zone=vendor` once in the deploy that
  switches packages (and keep it a deploy step afterwards). Run `php artisan migrate` (idempotent; it also rewrites legacy
  `ee.` finding titles).
- Scanner messages (zone, git, rule validation, command output) are now English, so an open "heuristics registry rejected a
  rule" finding may reappear as new once. Russian translations were dropped.
- The empty upstream rules layer and the sync with an external rules repository are gone; rules merge package -> host.
- The allowlist path for the plugin's own sample files is `vendor/asignua/filament-security-scanner/tests/fixtures/**`.

### Notable behaviour

- **Restore reopens the finding** (status `New`, notification stamps cleared) so every channel alerts again; close a false
  positive with **Ignore**.
- **Quarantine and restore stay inside the zone** the path really lies in (not the row's `zone_kind`), never follow or create
  symlinks, never overwrite an existing target, and refuse `..` segments and non-UTF-8 names.
- **A scanner that cannot do its job says so:** unreadable directories, files that cannot be stat-ed or opened, a zone outside
  `base_path()` and failing stages mark the scanner incomplete (it closes no findings) and raise `hygiene.scanner-degraded`.
- `code.git-head-moved` / `code.head-unrecorded` compare git `HEAD` with the one recorded by `security:baseline`;
  `code.git-dir-writable`, `code.git-executable-config`, `code.ignored-php-file` and `code.git-index-flag` report ways git
  results could be bent.
- `public/storage` is allowlisted only as the storage symlink; any other target is `hygiene.foreign-storage-link`.
- PostgreSQL: `content_hash` is `varchar(64)` (existing `char` tables keep working). Negative mtime/size values are clamped
  (MariaDB error 1264). Notification bodies are HTML-escaped, the Telegram bot token is redacted from logged errors, and
  database notifications are written in the recipient's locale.
