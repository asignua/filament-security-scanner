<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Console;

use Asignua\FilamentSecurityScanner\Enums\SecurityScanTrigger;
use Asignua\FilamentSecurityScanner\Enums\SecuritySeverity;
use Asignua\FilamentSecurityScanner\Models\SecurityFinding;
use Asignua\FilamentSecurityScanner\Models\SecurityScan;
use Asignua\FilamentSecurityScanner\Scanning\ScanRunner;
use Illuminate\Console\Command;

/**
 * An intrusion-trace scanner pass.
 *
 * The exit code is not decorative: `--fail-on` lets external monitoring hook in
 * without knowing anything about our DB schema. The default threshold is `high` —
 * a `low` finding must not wake the person on call.
 *
 * The command runs SYNCHRONOUSLY, not via the queue: a dead worker must not be able
 * to hide the scanner. This is the same motive as the run row with status
 * `running`.
 */
class SecurityScanCommand extends Command
{
    protected $signature = 'security:scan
        {--path=* : Check only these paths (relative to the project root)}
        {--fail-on=high : Minimum severity at which the command returns a non-zero code (none = never)}
        {--budget= : Pass time ceiling in seconds}
        {--reread : Read the contents of ALL files, not only those changed since the last pass (after adding a zone)}
        {--trigger=manual : Who started it: manual|schedule|upload|deploy}';

    protected $description = 'Looks for intrusion traces in the file system: executable code in upload zones and foreign files in the webroot';

    public function handle(): int
    {
        if (!(bool) config('security-scanner.enabled', false)) {
            $this->components->warn('The scanner is disabled (security-scanner.enabled = false).');

            return self::SUCCESS;
        }

        $trigger = SecurityScanTrigger::tryFrom((string) $this->option('trigger')) ?? SecurityScanTrigger::Manual;
        $budget = $this->option('budget');

        // The scanner list is ONE place, shared with the host's Tools button
        // (SecurityScanJob): ScanRunner::defaultScanners(). The order inside
        // it is not cosmetic: `code` and `uploads` form the set of
        // candidates for `obfuscation`, and `hygiene` goes last and turns
        // the problems of all the previous ones into a finding — so it must run even
        // when the rest failed.
        $runner = new ScanRunner(ScanRunner::defaultScanners());

        /** @var list<string> $paths */
        $paths = array_values(array_filter((array) $this->option('path'), 'is_string'));

        $scan = $runner->run(
            trigger: $trigger,
            restrictToPaths: $paths,
            timeBudgetSeconds: is_numeric($budget) ? (int) $budget : null,
            rereadContent: (bool) $this->option('reread'),
        );

        $this->report($scan);

        return $this->exitCode($scan);
    }

    private function report(SecurityScan $scan): void
    {
        $this->components->info(sprintf(
            'Run %s: status %s, findings %d (new %d), in %d ms.',
            $scan->ulid,
            $scan->status->value,
            $scan->findings_total,
            $scan->findings_new,
            $scan->duration_ms,
        ));

        /** @var array<string, mixed> $meta */
        $meta = (array) ($scan->scanners ?? []);
        /** @var list<string> $issues */
        $issues = array_values(array_filter((array) ($meta['issues'] ?? []), 'is_string'));

        // Scanner problems are ALWAYS printed, even when there are no findings: "found
        // nothing" and "looked nowhere" must look different.
        foreach ($issues as $issue) {
            $this->components->warn($issue);
        }

        $open = SecurityFinding::query()->open()->orderByDesc('severity_weight')->limit(15)->get();

        if ($open->isEmpty()) {
            $this->components->info('No open findings.');

            return;
        }

        $this->table(
            ['Severity', 'Rule', 'Path'],
            $open->map(static fn (SecurityFinding $f): array => [
                $f->severity->value,
                $f->rule_id,
                (string) $f->path,
            ])->all(),
        );
    }

    private function exitCode(SecurityScan $scan): int
    {
        $failOn = strtolower((string) $this->option('fail-on'));

        if ($failOn === 'none') {
            return self::SUCCESS;
        }

        $threshold = SecuritySeverity::tryFromName($failOn) ?? SecuritySeverity::High;

        $blocking = SecurityFinding::query()
            ->open()
            ->where('severity_weight', '>=', $threshold->weight())
            ->exists();

        return $blocking ? self::FAILURE : self::SUCCESS;
    }
}
