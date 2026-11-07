<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning;

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
    /** @var list<string> */
    private array $issues = [];

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

    public function head(): ?string
    {
        $out = $this->run(['rev-parse', '--short', 'HEAD']);

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

        return is_string($out) ? self::parsePorcelainZ($out) : null;
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
    private function run(array $arguments): ?string
    {
        $command = array_merge([
            'git',
            '--no-optional-locks',
            // The owner of .git in production has a different uid than the container user.
            '-c', 'safe.directory='.$this->base,
            // WITHOUT this the uid difference gives a "mode change" on EVERY tracked
            // file, and the very first run alarms on the entire repository.
            '-c', 'core.fileMode=false',
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
