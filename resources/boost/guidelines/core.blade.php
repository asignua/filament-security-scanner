## Filament Security Scanner (asignua/filament-security-scanner)

- It DETECTS traces of intrusion (executable files in uploads, polyglot images, drift from git or the `vendor/` hash snapshot, obfuscated PHP, risky runtime settings). It does not protect; never describe it as protection.
- Register it on the panel: `->plugin(Asignua\FilamentSecurityScanner\SecurityScannerPlugin::make()->navigationGroup(fn () => __('System')))`, then `php artisan migrate`.
- Access is DENY BY DEFAULT. Define the gates in `AppServiceProvider::boot()` or nobody sees anything: `Gate::define('security-scanner.view' | '.quarantine' | '.triage' | '.restore', fn ($user) => ...)`. `triage` falls back to `quarantine` when undefined; `restore` should be tighter than `quarantine`.
- Recipients of in-panel alerts: `SecurityScanner::notifyUsersUsing(fn () => User::...->get())` (the panel needs `->databaseNotifications()`). Mail: `SECURITY_SCANNER_NOTIFY_MAIL`; Telegram: `SECURITY_SCANNER_TELEGRAM_BOT_TOKEN` / `_CHAT_ID`.
- Add `php artisan security:baseline --zone=vendor` to the deploy script right after `composer install` (not to the scheduler). The package registers its own schedule (`security:scan` 04:40, `security:prune` 05:00, `security:notify` hourly); do not duplicate it.
- Config is `config/security-scanner.php`; a published `zones` or `allowlist` replaces the whole list (top-level merge only). After adding a zone run `security:scan --reread` once. Host rules go in `config/security-scanner-heuristics.php`; check them with `security:rules --against=<dir with clean/ and malicious/>`.
- Quarantine only works for upload zones and never deletes. Add `location ^~ /storage/ { try_files $uri =404; }` to nginx for the `public/storage` symlink: the scanner cannot replace that.
