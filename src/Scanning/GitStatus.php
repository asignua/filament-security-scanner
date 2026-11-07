<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;
use Symfony\Component\Process\Exception\ProcessFailedException;
use Symfony\Component\Process\Process;
use Throwable;

/**
 * A thin wrapper over `git status` for the code integrity scanner.
 *
 * Why git at all: in production the application is a real git checkout
 * (`git reset --hard` + `git clean -fd` on every deploy), so git already knows
 * the truth about every tracked file, and taking our own "reference" for them is
 * not needed. Moreover, an OWN reference gets poisoned: if tampering happened before
 * the snapshot was taken, the snapshot records it as the norm. Git compares with the remote
 * commit, which the attacker does not control.
 *
 * What git does NOT see is ignored paths. That is where web shells were found on 2026-09-20.
 * This is covered by the structural scanner and the hash baseline, not by this class.
 *
 * RUN VIA Symfony\Process, never via exec(): `exec` is in our
 * `disable_functions`, while `proc_open` is deliberately left for the image optimizer.
 */
final class GitStatus
{
    /** Extensions the PHP engine executes. */
    private const array PHP_EXTENSIONS = ['php', 'php3', 'php4', 'php5', 'php6', 'php7', 'php8', 'phtml', 'pht', 'phar', 'inc'];

    private const int EXPAND_LIMIT = 2000;

    /** @var list<string> */
    private array $issues = [];

    /** @var false|list<array{key: string, filter: string|null}>|null false = detection failed */
    private array|false|null $commandConfig = null;

    /** @var list<string> names of the exact git-lfs filters (benign on their own) */
    private array $lfsFilters = [];

    private bool $gitlinksReported = false;

    private static ?bool $lazyFetchOption = null;

    public function __construct(private readonly string $base) {}

    /**
     * @return list<string>
     */
    public function issues(): array
    {
        return $this->issues;
    }

    public function available(): bool
    {
        if (!is_dir($this->base.'/.git')) {
            $this->issues[] = 'git baseline unavailable: no .git in the root';

            return false;
        }

        $out = $this->run(['rev-parse', '--is-inside-work-tree']);

        return is_string($out) && trim($out) === 'true';
    }

    /**
     * Whether the PHP user can write to `.git` (the directory, its config or HEAD).
     * Whoever can write there can make git say anything, so the comparison with
     * git is only as trustworthy as that directory.
     */
    public function gitDirWritable(): bool
    {
        $git = rtrim($this->base, '/').'/.git';

        if (!is_dir($git)) {
            return false;
        }

        foreach ([$git, $git.'/config', $git.'/HEAD'] as $path) {
            if (file_exists($path) && is_writable($path)) {
                return true;
            }
        }

        return false;
    }

    public function head(bool $full = false): ?string
    {
        $out = $this->run($full ? ['rev-parse', 'HEAD'] : ['rev-parse', '--short', 'HEAD']);

        return is_string($out) ? trim($out) : null;
    }

    /**
     * `null` means git did not answer (timeout, failure). NOT an empty list: an empty one
     * would mean "no changes", and the run would close all code integrity findings
     * as gone, and the next successful one would reopen them with fresh alerts.
     *
     * @return list<array{status: string, path: string, from: string|null}>|null
     */
    public function entries(): ?array
    {
        // Submodules are not compared (a submodule's own git would be a second,
        // separately trusted repository); gitlinks are reported once instead.
        $out = $this->run(['status', '--porcelain=v1', '-z', '--untracked-files=all', '--ignore-submodules=all']);

        if (!is_string($out)) {
            return null;
        }

        $this->reportGitlinks();

        $entries = [];

        foreach (self::parsePorcelainZ($out) as $entry) {
            $entries[] = $entry;

            // `--untracked-files=all` still reports a NESTED REPOSITORY (or any directory
            // git refuses to descend into) as ONE `dir/` entry, so a shell inside it
            // would show up as a single low `untracked-file`. Expand it: every
            // PHP-executable file becomes an entry of its own.
            if ($entry['status'] === '??' && $this->isRealDirectory($entry['path'])) {
                foreach ($this->expandDirectory($entry['path']) as $file) {
                    $entries[] = ['status' => '??', 'path' => $file, 'from' => null];
                }
            }
        }

        return $entries;
    }

    private function reportGitlinks(): void
    {
        if ($this->gitlinksReported) {
            return;
        }

        $this->gitlinksReported = true;
        $out = $this->run(['ls-files', '-s', '-z']);

        if (!is_string($out)) {
            return;
        }

        $links = [];

        foreach (explode("\0", $out) as $field) {
            if (str_starts_with($field, '160000 ')) {
                $links[] = PathNormalizer::relative(substr($field, (int) strpos($field, "\t") + 1));
            }
        }

        if ($links !== []) {
            $this->issues[] = sprintf(
                '%d gitlink(s) (submodules) are not compared with git: %s',
                count($links),
                implode(', ', array_slice($links, 0, 5)),
            );
        }
    }

    private function isRealDirectory(string $relative): bool
    {
        $absolute = rtrim($this->base, '/').'/'.$relative;

        return !is_link($absolute) && is_dir($absolute);
    }

    /**
     * PHP-executable files under a directory git reports as a single entry.
     * Symlinks are not followed; an unreadable subdirectory is recorded as an issue.
     *
     * @return list<string> paths relative to the root
     */
    private function expandDirectory(string $relative): array
    {
        $absolute = rtrim($this->base, '/').'/'.$relative;
        $files = [];

        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($absolute, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::LEAVES_ONLY,
                RecursiveIteratorIterator::CATCH_GET_CHILD,
            );

            foreach ($iterator as $file) {
                /** @var SplFileInfo $file */
                if ($file->isLink() || !$file->isFile()) {
                    continue;
                }

                $path = PathNormalizer::relative($file->getPathname(), $this->base);

                if (array_intersect(PathNormalizer::extensionChain($path), self::PHP_EXTENSIONS) !== []) {
                    $files[] = $path;
                }

                if (count($files) >= self::EXPAND_LIMIT) {
                    $this->issues[] = sprintf('directory "%s": more than %d PHP files, the rest not listed', $relative, self::EXPAND_LIMIT);

                    break;
                }
            }
        } catch (Throwable $e) {
            $this->issues[] = sprintf('directory "%s" cannot be expanded: %s', $relative, $e->getMessage());
        }

        return $files;
    }

    /**
     * Ignored files with a PHP-executable extension inside the given code
     * directories. `git status` never lists them, which is exactly how a nested
     * `.gitignore` (`config/.gitignore` with `aaa.php`) hides a shell inside
     * tracked code. `null` = git did not answer.
     *
     * @param list<string> $paths directories relative to the root
     *
     * @return list<string>|null
     */
    public function ignoredPhpFiles(array $paths): ?array
    {
        if ($paths === []) {
            return [];
        }

        $out = $this->run(array_merge(['ls-files', '--others', '--ignored', '--exclude-standard', '-z', '--'], $paths));

        if (!is_string($out)) {
            return null;
        }

        $files = [];

        foreach (explode("\0", $out) as $path) {
            if ($path === '') {
                continue;
            }

            $relative = PathNormalizer::relative($path);

            if ($this->isRealDirectory($relative)) {
                array_push($files, ...$this->expandDirectory($relative));

                continue;
            }

            if (array_intersect(PathNormalizer::extensionChain($relative), self::PHP_EXTENSIONS) !== []) {
                $files[] = $relative;
            }
        }

        return $files;
    }

    /**
     * Tracked files whose index entry hides changes from `git status`:
     * `assume-unchanged` (lowercase tag in `ls-files -v`) and `skip-worktree`
     * (`S`). Either way a modified file looks clean.
     *
     * @return list<array{path: string, flag: string}>|null
     */
    public function hiddenIndexEntries(): ?array
    {
        $out = $this->run(['ls-files', '-v', '-z']);

        if (!is_string($out)) {
            return null;
        }

        $entries = [];

        foreach (explode("\0", $out) as $field) {
            if (strlen($field) < 3) {
                continue;
            }

            $tag = $field[0];

            if ($tag === 'S' || ctype_lower($tag)) {
                $entries[] = [
                    'path' => PathNormalizer::relative(substr($field, 2)),
                    'flag' => $tag === 'S' ? 'skip-worktree' : 'assume-unchanged',
                ];
            }
        }

        return $entries;
    }

    /**
     * Config keys (from ALL scopes, with `include.path`/`includeIf` followed) that
     * make git run a command, other than the git-lfs filter. `git config` executes
     * nothing, so this is safe to read.
     *
     * The value is matched ANCHORED: `clean = true && cmd` starts with `true` and
     * used to pass an unanchored `^true` check. A boolean is accepted only for the
     * keys that take one; a filter only when it is exactly a git-lfs command.
     * Detection runs BEFORE any other git command (see {@see run()}), and the
     * flagged filters are switched off for those commands.
     *
     * @return list<string>
     */
    public function executableConfig(): array
    {
        return array_map(
            static fn (array $item): string => $item['key'],
            $this->commandConfig() ?? [],
        );
    }

    /**
     * @return list<array{key: string, filter: string|null}>|null `null` = config could not be read
     */
    private function commandConfig(): ?array
    {
        if ($this->commandConfig !== null) {
            return $this->commandConfig === false ? null : $this->commandConfig;
        }

        $out = $this->run(['config', '--includes', '--list', '-z'], neutralise: false);

        if (!is_string($out)) {
            $this->commandConfig = false;

            return null;
        }

        $found = [];

        foreach (explode("\0", $out) as $entry) {
            if ($entry === '') {
                continue;
            }

            [$key, $value] = array_pad(explode("\n", $entry, 2), 2, '');
            $value = trim($value);
            $filter = null;

            if (preg_match('~^filter\.(.+)\.(?:clean|smudge|process)$~i', $key, $m) === 1) {
                $filter = $m[1];
                $benign = preg_match('~^git[- ]lfs (?:clean -- %f|smudge(?: --skip)? -- %f|filter-process(?: --skip)?)$~', $value) === 1;

                if ($benign) {
                    $this->lfsFilters[] = $filter;
                }
            } elseif (preg_match('~^alias\.lfs$|^remote\..+\.uploadpack$|^extensions\.partialclone$~i', $key) === 1) {
                // `git lfs ...` in a filter runs the ALIAS if one is set; uploadpack and
                // partial clones make git run a command / fetch on demand.
                $benign = $value === '';
            } elseif (preg_match('~^remote\..+\.promisor$~i', $key) === 1) {
                $benign = preg_match('~^(?:false|no|off|0)?$~i', $value) === 1;
            } elseif (preg_match('~^(?:core\.(?:fsmonitor|sshcommand|hookspath|editor|pager)|diff\..+\.(?:textconv|command)|merge\..+\.driver)$~i', $key) === 1) {
                $benign = preg_match('~^(?:false|true)$~i', $value) === 1;
            } else {
                continue;
            }

            if (!$benign) {
                $found[] = ['key' => $key, 'filter' => $filter];
            }
        }

        return $this->commandConfig = $found;
    }

    /**
     * Parsing of `--porcelain=v1 -z`.
     *
     * Format: two status characters, a space, the path, NUL. For renames and copies
     * (`R`/`C`) the OLD path comes as a SEPARATE NUL field right after the new one; this is
     * where home-grown parsers most often break.
     *
     * `-z` is mandatory: without it git quotes "inconvenient" names (spaces,
     * Cyrillic, quotes) in its own escaped format, and parsing that
     * line by line is guaranteed to go wrong sooner or later. File names in upload zones
     * are exactly like that.
     *
     * @return list<array{status: string, path: string, from: string|null}>
     */
    public static function parsePorcelainZ(string $raw): array
    {
        if (trim($raw) === '') {
            return [];
        }

        $fields = explode("\0", $raw);
        $entries = [];
        $count = count($fields);

        for ($i = 0; $i < $count; $i++) {
            $field = $fields[$i];

            if ($field === '') {
                continue;
            }

            // "XY " + path, where XY is exactly two characters (the space is significant).
            if (strlen($field) < 4) {
                continue;
            }

            $status = substr($field, 0, 2);
            $path = substr($field, 3);
            $from = null;

            if (str_contains($status, 'R') || str_contains($status, 'C')) {
                $from = $fields[++$i] ?? null;
                $from = $from === '' ? null : $from;
            }

            $entries[] = [
                'status' => $status,
                'path' => PathNormalizer::relative($path),
                'from' => $from !== null ? PathNormalizer::relative($from) : null,
            ];
        }

        return $entries;
    }

    /**
     * @param list<string> $arguments
     */
    private function run(array $arguments, bool $neutralise = true): ?string
    {
        // Overrides go through the environment (GIT_CONFIG_COUNT/KEY_n/VALUE_n), not
        // `-c key=value`: `-c` splits at the first `=`, so a filter NAME containing
        // `=` left its command untouched.
        $overrides = [
            // The owner of .git in production has a different uid than the container user.
            'safe.directory' => $this->base,
            // WITHOUT this the uid difference gives a "mode change" on EVERY tracked
            // file, and the very first run alarms on the entire repository.
            'core.fileMode' => 'false',
        ];

        if ($neutralise) {
            // Filters are detected FIRST. `git status` runs a clean filter to compare
            // content of stat-dirty files; if the config cannot be read we cannot
            // vouch for what git would execute, so git "did not answer".
            $config = $this->commandConfig();

            if ($config === null) {
                return null;
            }

            // THINGS GIT MAY EXECUTE ON `status`, switched off: `core.fsmonitor` names a
            // COMMAND, `core.hooksPath` redirects hooks. The stat settings are forced to
            // their strict defaults so that a weakened `.git/config` cannot make a
            // same-size change look clean. Not passed to the config READ: our own
            // values would show up in `git config --list` as the repository's.
            $overrides += [
                'core.fsmonitor' => 'false',
                'core.hooksPath' => '/dev/null',
                'core.trustctime' => 'true',
                'core.checkStat' => 'default',
                'diff.ignoreSubmodules' => 'none',
            ];

            // Every flagged filter is emptied (an empty command means "no filter") and
            // made non-required, so git neither runs it nor refuses to continue.
            // Exact git-lfs filters stay intact (emptied, they would make every LFS file
            // look modified) unless something else suspicious is present: then
            // `git lfs` itself may be an alias, and they are emptied too.
            $names = array_column($config, 'filter');

            if ($config !== []) {
                $names = array_merge($names, $this->lfsFilters);
            }

            foreach (array_unique(array_filter($names)) as $name) {
                foreach (['clean', 'smudge', 'process'] as $variable) {
                    $overrides['filter.'.$name.'.'.$variable] = '';
                }
            }

            // Not required: a failing lfs filter (read-only .git) must not fail the status.
            foreach (array_unique(array_merge(array_filter(array_column($config, 'filter')), $this->lfsFilters)) as $name) {
                $overrides['filter.'.$name.'.required'] = 'false';
            }
        }

        $environment = [];

        foreach (array_merge(array_keys(getenv()), array_keys($_ENV), array_keys($_SERVER)) as $name) {
            if (is_string($name) && str_starts_with(strtoupper($name), 'GIT_')) {
                $environment[$name] = false;
            }
        }

        $index = 0;
        $environment['GIT_CONFIG_COUNT'] = (string) count($overrides);

        foreach ($overrides as $key => $value) {
            $environment['GIT_CONFIG_KEY_'.$index] = $key;
            $environment['GIT_CONFIG_VALUE_'.$index] = $value;
            $index++;
        }

        // An LFS filter that survives must not try to download anything.
        $environment['GIT_LFS_SKIP_SMUDGE'] = '1';
        $environment['GIT_TERMINAL_PROMPT'] = '0';

        $command = array_merge(
            ['git', '--no-optional-locks', '--no-replace-objects'],
            self::supportsNoLazyFetch() ? ['--no-lazy-fetch'] : [],
            ['-C', $this->base],
            $arguments,
        );

        try {
            $process = new Process($command, null, $environment);
            $process->setTimeout((float) config('security-scanner.git_timeout', 60));
            $process->run();

            if (!$process->isSuccessful()) {
                throw new ProcessFailedException($process);
            }

            return $process->getOutput();
        } catch (Throwable $e) {
            // A silent "no git, therefore clean" is unacceptable here: it is
            // the absence of a check, not its result.
            $this->issues[] = sprintf('git unavailable (%s): %s', implode(' ', $arguments), trim($e->getMessage()));

            return null;
        }
    }

    /**
     * `--no-lazy-fetch` appeared in git 2.43; an older git refuses the whole command.
     */
    private static function supportsNoLazyFetch(): bool
    {
        if (self::$lazyFetchOption === null) {
            $probe = new Process(['git', '--no-lazy-fetch', '--version']);
            $probe->setTimeout(10);

            try {
                $probe->run();
                self::$lazyFetchOption = $probe->isSuccessful();
            } catch (Throwable) {
                self::$lazyFetchOption = false;
            }
        }

        return self::$lazyFetchOption;
    }
}
