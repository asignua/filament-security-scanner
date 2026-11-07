<?php

declare(strict_types=1);

use Asignua\FilamentSecurityScanner\Enums\SecuritySeverity;
use Asignua\FilamentSecurityScanner\Enums\SecurityZoneKind;

/*
|--------------------------------------------------------------------------
| Scanner heuristics - the package's own rules
|--------------------------------------------------------------------------
|
| A host adds to or overrides these in its own file
| (config/security-scanner-heuristics.php): an entry with the same `id`
| replaces the package rule, and `enabled => false` switches it off. The later
| file wins per `id` (package -> host).
|
| Every regex below was run BEFORE the code was written: both web shells from
| a real incident are caught by two or three independent rules, while a corpus
| of 1250 real project files (app/, config/, routes/, database/, bootstrap/,
| resources/, public/) gives ZERO false positives. A new rule must not be added
| without such a check - a findings page that cries wolf gets ignored by the
| third day.
|
*/

$uploadZones = [SecurityZoneKind::UploadWeb->value, SecurityZoneKind::UploadPrivate->value];
// Everything a web server hands to the PHP engine. Matched CASE-INSENSITIVELY:
// `shell.PHP` runs exactly like `shell.php`.
$phpExtensions = ['php', 'phtml', 'phar', 'pht', 'php3', 'php4', 'php5', 'php6', 'php7', 'php8'];
$webrootPhpPatterns = array_merge(...array_map(
    static fn (string $ext): array => ['public/*.'.$ext, 'public/**/*.'.$ext],
    $phpExtensions,
));
$codeZones = [SecurityZoneKind::Code->value, SecurityZoneKind::Webroot->value];

return [
    'format' => 1,
    'version' => '2026-10-05.1',
    'source' => 'package',
    'origin' => 'asignua/filament-security-scanner',
    'generated_at' => '2026-09-20',

    'rules' => [

        /*
         * STRUCTURAL — deterministic, allow auto-quarantine.
         *
         * This is a statement of fact, not a guess: "an executable extension on a disk
         * where user uploads are stored". A prod check of 69,344
         * media disk files gave zero false positives (the extensions there are exactly
         * png/webp/jpg/jpeg/avif/mp4/svg/pdf/docx + one uppercase PNG).
         */
        [
            'id' => 'uploads.executable-extension',
            'scanner' => 'uploads',
            'severity' => SecuritySeverity::Critical->value,
            'deterministic' => true,
            'applies_to' => $uploadZones,
            'weight' => 10,
            'message' => 'security-scanner::rules.Executable file in an upload directory',
            'matcher' => [
                'type' => 'extension',
                // chain: also catches `shell.php.jpg` — it is served as an image
                // but executed as PHP everywhere the handler hooks onto a
                // partial extension match.
                'chain' => true,
                'extensions' => [
                    'php', 'php3', 'php4', 'php5', 'php6', 'php7', 'php8',
                    'phtml', 'pht', 'phar', 'phps', 'inc', 'shtml',
                    'cgi', 'pl', 'py', 'sh', 'bash', 'jsp', 'asp', 'aspx',
                ],
            ],
        ],

        [
            'id' => 'uploads.server-config-file',
            'scanner' => 'uploads',
            'severity' => SecuritySeverity::High->value,
            // NOT deterministic: a web server config in the tree can be legitimate,
            // and a mistaken move of .htaccess can take file serving down.
            'deterministic' => false,
            'applies_to' => $uploadZones,
            'weight' => 8,
            'message' => 'security-scanner::rules.Server config file in an upload directory',
            'matcher' => [
                'type' => 'extension',
                'names' => ['.htaccess', '.user.ini', 'web.config', '.htpasswd'],
            ],
        ],

        [
            'id' => 'uploads.symlink-in-upload-zone',
            'scanner' => 'uploads',
            'severity' => SecuritySeverity::High->value,
            'deterministic' => false,
            'applies_to' => $uploadZones,
            'weight' => 6,
            'message' => 'security-scanner::rules.Symlink inside an upload directory',
            'matcher' => ['type' => 'flag', 'flag' => 'symlink'],
        ],

        /*
         * Exactly one .php is allowed in the webroot — `public/index.php`.
         * That is exactly how many there are in prod (verified: 155 files in public/, one of them
         * a .php). There is no auto-quarantine here and there cannot be: a false
         * positive in the webroot takes the site down.
         */
        [
            'id' => 'webroot.unexpected-php',
            'scanner' => 'uploads',
            'severity' => SecuritySeverity::Critical->value,
            'deterministic' => false,
            'applies_to' => [SecurityZoneKind::Webroot->value],
            'weight' => 10,
            'message' => 'security-scanner::rules.Unexpected PHP file in the web root',
            'matcher' => [
                'type' => 'path',
                'patterns' => $webrootPhpPatterns,
                // The patterns ignore case; the exception does NOT: `public/INDEX.php`
                // is a different file on Linux, and not the front controller.
                'ignore_case' => true,
                'except' => ['public/index.php'],
            ],
        ],

        /*
         * CODE INTEGRITY. Detection is done by the scanner itself (git and the hash snapshot), so
         * matcher.type = none: the registry entry is needed so that severity, label and
         * allowlist for these findings live in the same place as for the rest, rather than
         * half in data and half in the package release.
         *
         * None of them is deterministic: auto-quarantining a hotfix that a
         * developer placed by hand would destroy trust in the subsystem faster than
         * any intrusion.
         */
        [
            'id' => 'code.untracked-executable',
            'scanner' => 'code',
            'severity' => SecuritySeverity::High->value,
            'applies_to' => $codeZones,
            'weight' => 8,
            'message' => 'security-scanner::rules.Untracked executable file in the repository',
            'matcher' => ['type' => 'none'],
        ],
        [
            // Separate from the previous one and DELIBERATELY of a lower level: an untracked
            // README or a drafts folder is the everyday state of a working tree, and if
            // it showed up as high, nobody would read the findings list any more.
            'id' => 'code.untracked-file',
            'scanner' => 'code',
            'severity' => SecuritySeverity::Low->value,
            'applies_to' => $codeZones,
            'weight' => 2,
            'message' => 'security-scanner::rules.Untracked file in the repository',
            'matcher' => ['type' => 'none'],
        ],
        [
            'id' => 'code.modified-file',
            'scanner' => 'code',
            'severity' => SecuritySeverity::High->value,
            'applies_to' => $codeZones,
            'weight' => 8,
            'message' => 'security-scanner::rules.Tracked file differs from the commit',
            'matcher' => ['type' => 'none'],
        ],
        [
            // A nested .gitignore (`config/.gitignore` listing `aaa.php`) hides a PHP
            // file from `git status`: invisible to the git half of the scanner.
            'id' => 'code.ignored-php-file',
            'scanner' => 'code',
            'severity' => SecuritySeverity::High->value,
            'applies_to' => $codeZones,
            'weight' => 8,
            'message' => 'security-scanner::rules.PHP file hidden from git by .gitignore',
            'matcher' => ['type' => 'none'],
        ],
        [
            // assume-unchanged / skip-worktree: the file may be modified and still
            // look clean to `git status`.
            'id' => 'code.git-index-flag',
            'scanner' => 'code',
            'severity' => SecuritySeverity::High->value,
            'applies_to' => $codeZones,
            'weight' => 7,
            'message' => 'security-scanner::rules.Tracked file hidden from git status',
            'matcher' => ['type' => 'none'],
        ],
        [
            // A config key that makes git run a command (a clean filter, fsmonitor,
            // hooksPath…): code execution as the web user on every `git status`.
            // The scanner switches the command off before running git and reports it.
            'id' => 'code.git-executable-config',
            'scanner' => 'code',
            'severity' => SecuritySeverity::High->value,
            'applies_to' => $codeZones,
            'weight' => 8,
            'message' => 'security-scanner::rules.Git config makes git run a command',
            'matcher' => ['type' => 'none'],
        ],
        [
            // A commit makes `git status` clean. HEAD differs from the one recorded
            // with the last baseline: commits happened without a new baseline.
            'id' => 'code.git-head-moved',
            'scanner' => 'code',
            'severity' => SecuritySeverity::Medium->value,
            'applies_to' => $codeZones,
            'weight' => 5,
            'message' => 'security-scanner::rules.Git HEAD moved since the last baseline',
            'matcher' => ['type' => 'none'],
        ],
        [
            // Whoever can write .git can make git report anything, so a clean
            // `git status` proves nothing. Not raised in local/testing environments.
            'id' => 'code.git-dir-writable',
            'scanner' => 'code',
            'severity' => SecuritySeverity::Medium->value,
            'applies_to' => $codeZones,
            'weight' => 5,
            'message' => 'security-scanner::rules.Git directory is writable by the web user',
            'matcher' => ['type' => 'none'],
        ],
        [
            'id' => 'code.deleted-file',
            'scanner' => 'code',
            'severity' => SecuritySeverity::Medium->value,
            'applies_to' => $codeZones,
            'weight' => 5,
            'message' => 'security-scanner::rules.Tracked file is missing',
            'matcher' => ['type' => 'none'],
        ],
        [
            'id' => 'code.renamed-file',
            'scanner' => 'code',
            'severity' => SecuritySeverity::Medium->value,
            'applies_to' => $codeZones,
            'weight' => 5,
            'message' => 'security-scanner::rules.Tracked file was renamed',
            'matcher' => ['type' => 'none'],
        ],
        [
            // The absence of a check is not "clean". Without this finding a site without
            // git would look like a site with flawless code integrity.
            'id' => 'code.git-unavailable',
            'scanner' => 'code',
            'severity' => SecuritySeverity::Medium->value,
            'applies_to' => $codeZones,
            'weight' => 4,
            'message' => 'security-scanner::rules.Git baseline is unavailable',
            'matcher' => ['type' => 'none'],
        ],
        [
            'id' => 'code.baseline-added',
            'scanner' => 'code',
            'severity' => SecuritySeverity::High->value,
            'applies_to' => [SecurityZoneKind::Vendor->value],
            'weight' => 7,
            'message' => 'security-scanner::rules.File appeared since the baseline',
            'matcher' => ['type' => 'none'],
        ],
        [
            'id' => 'code.baseline-modified',
            'scanner' => 'code',
            'severity' => SecuritySeverity::High->value,
            'applies_to' => [SecurityZoneKind::Vendor->value],
            'weight' => 8,
            'message' => 'security-scanner::rules.File changed since the baseline',
            'matcher' => ['type' => 'none'],
        ],
        [
            // composer legitimately removes files — hence low, not high.
            'id' => 'code.baseline-removed',
            'scanner' => 'code',
            'severity' => SecuritySeverity::Low->value,
            'applies_to' => [SecurityZoneKind::Vendor->value],
            'weight' => 2,
            'message' => 'security-scanner::rules.File disappeared since the baseline',
            'matcher' => ['type' => 'none'],
        ],
        [
            'id' => 'code.baseline-missing',
            'scanner' => 'code',
            'severity' => SecuritySeverity::Medium->value,
            'applies_to' => [SecurityZoneKind::Vendor->value],
            'weight' => 4,
            'message' => 'security-scanner::rules.No baseline snapshot for this zone',
            'matcher' => ['type' => 'none'],
        ],

        /*
         * ENVIRONMENT HYGIENE. Runtime posture, not file contents; detected by the scanner
         * itself, hence matcher.type = none. Some of the rules are invariants of precisely
         * the reference production stack (proc_open, pcntl, MAGICK_TIME_LIMIT):
         * each of them has already cost a production site once.
         */
        [
            'id' => 'hygiene.debug-enabled',
            'scanner' => 'hygiene',
            'severity' => SecuritySeverity::Critical->value,
            'applies_to' => $codeZones,
            'weight' => 10,
            'message' => 'security-scanner::rules.Debug mode is on in production',
            'matcher' => ['type' => 'none'],
        ],
        [
            'id' => 'hygiene.app-key-missing',
            'scanner' => 'hygiene',
            'severity' => SecuritySeverity::Critical->value,
            'applies_to' => $codeZones,
            'weight' => 10,
            'message' => 'security-scanner::rules.Application key is missing',
            'matcher' => ['type' => 'none'],
        ],
        [
            'id' => 'hygiene.env-in-webroot',
            'scanner' => 'hygiene',
            'severity' => SecuritySeverity::Critical->value,
            'applies_to' => $codeZones,
            'weight' => 10,
            'message' => 'security-scanner::rules.Environment file inside the web root',
            'matcher' => ['type' => 'none'],
        ],
        [
            'id' => 'hygiene.dangerous-ini',
            'scanner' => 'hygiene',
            'severity' => SecuritySeverity::High->value,
            'applies_to' => $codeZones,
            'weight' => 7,
            'message' => 'security-scanner::rules.Dangerous PHP setting',
            'matcher' => ['type' => 'none'],
        ],
        [
            'id' => 'hygiene.pcntl-missing',
            'scanner' => 'hygiene',
            'severity' => SecuritySeverity::Medium->value,
            'applies_to' => $codeZones,
            'weight' => 4,
            'message' => 'security-scanner::rules.The pcntl extension is missing',
            'matcher' => ['type' => 'none'],
        ],
        [
            'id' => 'hygiene.magick-time-limit',
            'scanner' => 'hygiene',
            'severity' => SecuritySeverity::High->value,
            'applies_to' => $codeZones,
            'weight' => 7,
            'message' => 'security-scanner::rules.MAGICK_TIME_LIMIT is set',
            'matcher' => ['type' => 'none'],
        ],
        [
            // `public/storage` is allowlisted as the storage symlink; one that points
            // anywhere else (`..` exposes .env) is not.
            'id' => 'hygiene.foreign-storage-link',
            'scanner' => 'hygiene',
            'severity' => SecuritySeverity::Critical->value,
            'applies_to' => [SecurityZoneKind::Webroot->value],
            'weight' => 10,
            'message' => 'security-scanner::rules.Storage link in the web root points elsewhere',
            'matcher' => ['type' => 'none'],
        ],
        [
            'id' => 'hygiene.prepend-in-webroot',
            'scanner' => 'hygiene',
            'severity' => SecuritySeverity::Critical->value,
            'applies_to' => [SecurityZoneKind::Webroot->value],
            'weight' => 10,
            'message' => 'security-scanner::rules.Web server config injects code before every request',
            'matcher' => ['type' => 'none'],
        ],
        [
            'id' => 'hygiene.world-writable',
            'scanner' => 'hygiene',
            'severity' => SecuritySeverity::High->value,
            'applies_to' => [SecurityZoneKind::Webroot->value],
            'weight' => 7,
            'message' => 'security-scanner::rules.World-writable file in the web root',
            'matcher' => ['type' => 'none'],
        ],
        [
            'id' => 'hygiene.registry-rule-invalid',
            'scanner' => 'hygiene',
            'severity' => SecuritySeverity::Medium->value,
            'applies_to' => $codeZones,
            'weight' => 4,
            'message' => 'security-scanner::rules.A heuristics rule was rejected',
            'matcher' => ['type' => 'none'],
        ],
        [
            // A scanner problem is a FINDING, not a console line. Otherwise "did not
            // look into the zone" would look like "looked and found nothing".
            'id' => 'hygiene.scanner-degraded',
            'scanner' => 'hygiene',
            'severity' => SecuritySeverity::Medium->value,
            'applies_to' => $codeZones,
            'weight' => 5,
            'message' => 'security-scanner::rules.A scanner did not complete its pass',
            'matcher' => ['type' => 'none'],
        ],
        [
            // Silence is not the same as clean: a file larger than the ceiling was not
            // read — and there must be a record of that.
            'id' => 'obf.oversized-unreadable',
            'scanner' => 'obfuscation',
            'severity' => SecuritySeverity::Info->value,
            'applies_to' => array_merge($codeZones, $uploadZones),
            'weight' => 1,
            'message' => 'security-scanner::rules.File too large to inspect',
            'matcher' => ['type' => 'none'],
        ],

        /*
         * OBFUSCATION — never deterministic (the registry validator rejects
         * `deterministic: true` on matcher.type = regex).
         */
        [
            'id' => 'obf.halt-compiler-inflate',
            'scanner' => 'obfuscation',
            'severity' => SecuritySeverity::High->value,
            'applies_to' => array_merge($codeZones, $uploadZones),
            'weight' => 6,
            'message' => 'security-scanner::rules.Code hidden past __halt_compiler',
            'matcher' => [
                'type' => 'regex',
                'pattern' => '~__halt_compiler\s*(?:/\*.*?\*/)?\s*\(\s*\)\s*;~s',
            ],
            'references' => ['https://www.php.net/manual/function.halt-compiler.php'],
        ],

        [
            'id' => 'obf.eval-base64',
            'scanner' => 'obfuscation',
            'severity' => SecuritySeverity::Critical->value,
            'applies_to' => array_merge($codeZones, $uploadZones),
            'weight' => 10,
            'message' => 'security-scanner::rules.Decoded payload passed to eval',
            'matcher' => [
                'type' => 'regex',
                'pattern' => '~\b(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(~i',
            ],
        ],

        [
            'id' => 'obf.nested-inflate',
            'scanner' => 'obfuscation',
            'severity' => SecuritySeverity::High->value,
            'applies_to' => array_merge($codeZones, $uploadZones),
            'weight' => 7,
            'message' => 'security-scanner::rules.Compressed payload unpacked at runtime',
            'matcher' => [
                'type' => 'regex',
                'pattern' => '~\bgz(?:inflate|uncompress)\s*\(\s*(?:base64_decode|stream_get_contents)\s*\(~i',
            ],
        ],

        [
            'id' => 'obf.var-var-globals',
            'scanner' => 'obfuscation',
            'severity' => SecuritySeverity::High->value,
            'applies_to' => array_merge($codeZones, $uploadZones),
            'weight' => 7,
            'message' => 'security-scanner::rules.Variable variables with escaped names',
            'matcher' => [
                'type' => 'regex',
                'pattern' => '~\$\{\s*"(?:[A-Za-z]|\\\\x[0-9A-Fa-f]{2}){2,}"\s*\}\s*\[~',
            ],
        ],

        [
            'id' => 'obf.concat-fn-name',
            'scanner' => 'obfuscation',
            'severity' => SecuritySeverity::Medium->value,
            'applies_to' => array_merge($codeZones, $uploadZones),
            'weight' => 5,
            'message' => 'security-scanner::rules.Function name assembled from concatenation',
            'matcher' => [
                'type' => 'regex',
                'pattern' => "~=\\s*'[a-z]'(?:\\s*\\.\\s*'[a-z]{1,3}'){3,}~",
            ],
        ],

        /*
         * Polyglot: a valid image with PHP hidden in it. The `\A` anchor and the 8 KB bound
         * are not an optimization but protection against catastrophic backtracking:
         * without them the rule hangs the pass on the first large file, and the scanner's
         * silence cannot be told from "clean".
         *
         * The `i` flag: the PHP opening tag is case-insensitive (`<?PHP`
         * executes just the same). `<?=` always works, regardless of
         * short_open_tag, — but those are three bytes that occur by themselves in compressed
         * image data (measured: 11 matches over 81 thousand media disk
         * files, and a lone backtick or `$_` in the following 128 bytes of noise
         * is not rare either). So `<?=` counts only with an UNBROKEN printable
         * tail up to a PHP marker: a superglobal, an expression in backticks or an
         * execution call with a parenthesis. That gives zero false positives on the same 81 thousand files.
         * The magic covers both webp (`RIFF….WEBP`) and avif/heic (`….ftyp…`): those are
         * what the media disk is mostly filled with.
         */
        [
            'id' => 'obf.php-after-binary',
            'scanner' => 'obfuscation',
            'severity' => SecuritySeverity::Critical->value,
            'applies_to' => array_merge($codeZones, $uploadZones),
            'weight' => 10,
            'max_read_bytes' => 65536,
            'message' => 'security-scanner::rules.PHP code inside a binary file',
            'matcher' => [
                'type' => 'regex',
                // `[\s\S]{0,8192}?`, NOT `(?s:.){0,8192}?`: a bounded repeat of a
                // GROUP unrolls it 8192 times and hits the PCRE2 compilation limit
                // ("Internal error"), while a repeat of a character CLASS is not
                // unrolled. Python accepts this pattern — which is why the compilation check
                // must run in PHP, not in the tool where the draft was written.
                'pattern' => '~\A(?:\xff\xd8\xff|\x89PNG|GIF8|%PDF|RIFF[\s\S]{4}WEBP|[\s\S]{4}ftyp(?:avif|avis|heic|heix|mif1))'
                    .'[\s\S]{0,8192}?<\?(?:php|=[\x20-\x7e\t]{0,128}?(?:\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)|`[\x20-\x7e]{1,128}`'
                    .'|\b(?:system|exec|passthru|shell_exec|popen|proc_open|eval|assert|include|require)\s*\())~i',
            ],
        ],

        [
            'id' => 'obf.include-tmpfile',
            'scanner' => 'obfuscation',
            'severity' => SecuritySeverity::Critical->value,
            'applies_to' => array_merge($codeZones, $uploadZones),
            'weight' => 10,
            'message' => 'security-scanner::rules.Code included from a temporary stream',
            'matcher' => [
                'type' => 'regex',
                'pattern' => '~\binclude\s*\(?\s*(?:socket_get_status|stream_get_meta_data)\s*\(~i',
            ],
        ],

    ],
];
