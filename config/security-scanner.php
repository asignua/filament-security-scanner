<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| File-system intrusion scanner
|--------------------------------------------------------------------------
|
| Looks for traces of files that were already added, changed or swapped:
| executable code in upload zones, drift from the baseline, obfuscation,
| environment hygiene. This is DETECTION, not protection.
|
| WARNING: mergeConfigFrom() merges only the TOP level. A published
| config/security-scanner.php that overrides `zones` replaces the WHOLE zone
| list - a site that only wanted to add one zone has to list them all.
| The same goes for `allowlist`.
*/
return [
    'enabled' => (bool) env('SECURITY_SCANNER_ENABLED', true),

    // Table prefix for security_findings / security_scans / security_baseline.
    'tables' => [
        'prefix' => (string) env('SECURITY_SCANNER_TABLE_PREFIX', ''),
    ],

    // 0 = never prune. Prunes runs and ONLY closed findings (resolved/ignored).
    'retention_days' => (int) env('SECURITY_SCANNER_RETENTION_DAYS', 180),

    // Zones: what to look at and WHERE on THIS site. Rules declare the zone
    // KIND (`applies_to`), not a path, which keeps them portable between sites.
    // `root` is relative to base_path(); `disk` is a disk name from
    // config/filesystems.php.
    // Zones may NEST: the directory of the more specific zone is cut out of the
    // walk of the broader one (Zones::resolve), so `storage_app` does not walk
    // into `storage/app/public` or a media disk, and they stay themselves.
    'zones' => [
        'webroot' => ['root' => 'public', 'kind' => 'webroot'],
        // storage/app/public is reachable from outside through the public/storage
        // symlink - the classic place for a web shell disguised as an image.
        'storage_public' => ['disk' => 'public', 'kind' => 'upload:web'],
        // The rest of storage/app: private directories the application writes to
        // and git does not see (they are in .gitignore). They are not served
        // directly, but a file dropped here is still read by PHP - certificates,
        // generated documents, temporary exports. The zone is deliberately BROAD:
        // listing directories by name means going blind on every next one the
        // site creates.
        'storage_app' => ['root' => 'storage/app', 'kind' => 'upload:private'],
        // vendor/ is in .gitignore: its integrity is held by the hash snapshot,
        // taken by a deploy step (`security:baseline --zone=vendor` after
        // composer install).
        'vendor' => ['root' => 'vendor', 'kind' => 'vendor'],
    ],

    // TWO DIFFERENT lists. `scan` excludes from scanning; `baseline` only from
    // hashing. A mutable upload disk belongs in the second and NOT in the first.
    'allowlist' => [
        'scan' => [
            'storage/framework/**',
            'storage/logs/**',
            'storage/media-library/temp/**',
            'storage/app/livewire-tmp/**',
            'bootstrap/cache/*.php',
            'public/robots.txt',
            'public/sitemap.xml',
            'public/storage',
            'public/hot',
            // The contents of .env are NEVER read or hashed.
            '.env',
            '.env.*',
            // CRITICAL: real web shells sit in quarantine.
            'storage/app/private/quarantine/**',
            // The scanner's own samples (present when the package is symlinked
            // from a path repository; export-ignore keeps them out of dist installs).
            'vendor/asignua/filament-security-scanner/tests/fixtures/**',
        ],
        'baseline' => [
            'storage/**',
            'bootstrap/cache/**',
            'node_modules/**',
            '.git/**',
        ],
    ],

    'max_file_size' => (int) env('SECURITY_SCANNER_MAX_FILE_SIZE', 33554432),
    'git_timeout' => (int) env('SECURITY_SCANNER_GIT_TIMEOUT', 60),

    'git' => [
        // Code directories searched for PHP files that .gitignore hides from
        // `git status` (a nested config/.gitignore listing a shell). Relative to the
        // project root; bootstrap/cache is always skipped. Empty = off.
        'ignored_php_paths' => ['app', 'bootstrap', 'config', 'database', 'resources', 'routes'],
    ],

    // Host file that adds to / overrides the rules (see RuleRegistry).
    'heuristics_override' => 'security-scanner-heuristics.php',

    'quarantine' => [
        'enabled' => (bool) env('SECURITY_SCANNER_QUARANTINE', true),
        'auto' => (bool) env('SECURITY_SCANNER_QUARANTINE_AUTO', false),
        'auto_zones' => ['upload:web'],
        'max_bytes' => (int) env('SECURITY_SCANNER_QUARANTINE_MAX_BYTES', 67108864),
    ],

    'upload' => [
        'enabled' => (bool) env('SECURITY_SCANNER_UPLOAD_SCAN', true),
        'sync_budget_ms' => (int) env('SECURITY_SCANNER_UPLOAD_BUDGET_MS', 150),
        'sniff_bytes' => 4096,
    ],

    'notify' => [
        // Empty = the mail channel is off.
        'mail' => (string) env('SECURITY_SCANNER_NOTIFY_MAIL', ''),
        'throttle_minutes' => (int) env('SECURITY_SCANNER_NOTIFY_THROTTLE', 60),
        'min_severity' => [
            'database' => env('SECURITY_SCANNER_NOTIFY_MIN_PANEL', 'low'),
            'mail' => env('SECURITY_SCANNER_NOTIFY_MIN_MAIL', 'high'),
            'telegram' => env('SECURITY_SCANNER_NOTIFY_MIN_TELEGRAM', 'high'),
        ],
    ],

    'mail' => [
        // A host may substitute its own view (same variables as
        // security-scanner::mail.findings).
        'view' => 'security-scanner::mail.findings',
        // null = app.locale.
        'locale' => env('SECURITY_SCANNER_MAIL_LOCALE'),
    ],

    // Token and chat_id come from ENV: they are credentials.
    'telegram' => [
        'enabled' => (bool) env('SECURITY_SCANNER_TELEGRAM_ENABLED', true),
        'token' => (string) env('SECURITY_SCANNER_TELEGRAM_BOT_TOKEN', ''),
        'chat_id' => (string) env('SECURITY_SCANNER_TELEGRAM_CHAT_ID', ''),
        'timeout' => (int) env('SECURITY_SCANNER_TELEGRAM_TIMEOUT', 5),
    ],

    // The package registers the schedule itself. Times are fragments for dailyAt()/hourlyAt().
    'schedule' => [
        'enabled' => (bool) env('SECURITY_SCANNER_SCHEDULE', true),
        'scan' => '04:40',
        'prune' => '05:00',
        'notify_minute' => 15,
    ],
];
