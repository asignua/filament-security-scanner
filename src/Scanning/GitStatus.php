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
        $out = $this->run(['status', '--porcelain=v1', '-z', '--untracked-files=all']);

        if (!is_string($out)) {
            return null;
        }

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
        $overrides = [];

        if ($neutralise) {
            // Filters are detected FIRST. `git status` runs a clean filter to compare
            // content of stat-dirty files; if the config cannot be read we cannot
            // vouch for what git would execute, so git "did not answer".
            $config = $this->commandConfig();

            if ($config === null) {
                return null;
            }

            // Every flagged filter is emptied (an empty command means "no filter") and
            // made non-required, so git neither runs it nor refuses to continue.
            // Exact git-lfs filters are not flagged and stay intact: emptied, they
            // would make every LFS file look modified.
            foreach (array_unique(array_filter(array_column($config, 'filter'))) as $name) {
                foreach (['clean', 'smudge', 'process'] as $variable) {
                    array_push($overrides, '-c', 'filter.'.$name.'.'.$variable.'=');
                }

                array_push($overrides, '-c', 'filter.'.$name.'.required=false');
            }
        }

        $command = array_merge([
            'git',
            '--no-optional-locks',
            // The owner of .git in production has a different uid than the container user.
            '-c', 'safe.directory='.$this->base,
            // WITHOUT this the uid difference gives a "mode change" on EVERY tracked
            // file, and the very first run alarms on the entire repository.
            '-c', 'core.fileMode=false',
            // THINGS GIT MAY EXECUTE ON `status`, switched off: `core.fsmonitor` names a
            // COMMAND that git runs to ask what changed (anyone who can write
            // .git/config gets code execution as the web user on the nightly scan),
            // and `core.hooksPath` redirects hooks to a directory of the attacker's
            // choice. Clean/smudge FILTER drivers (`filter.<name>.clean`) cannot be
            // blanket-disabled (git-lfs needs them), so {@see executableConfig()}
            // reports unexpected ones instead.
            // Not passed to the config READ: our own `-c` would show up in
            // `git config --list` and be reported as the repository's.
            ...($neutralise ? ['-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null'] : []),
            ...$overrides,
            '-C', $this->base,
        ], $arguments);

        try {
            $process = new Process($command);
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
}
