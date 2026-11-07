<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Console;

use Asignua\FilamentSecurityScanner\Enums\SecurityFindingStatus;
use Asignua\FilamentSecurityScanner\Models\SecurityFinding;
use Asignua\FilamentSecurityScanner\Models\SecurityScan;
use Asignua\FilamentSecurityScanner\Scanning\BaselineSnapshot;
use Asignua\FilamentSecurityScanner\Scanning\Zones;
use Illuminate\Console\Command;

/**
 * Scanner rotation: runs, CLOSED findings, old snapshots.
 *
 * Only resolved/ignored are cleaned — new/acknowledged/quarantined statuses are
 * NEVER cleaned: an unhandled intrusion has no right to rot beyond the
 * retention horizon. A closed finding that still holds a `quarantine_path` also stays:
 * it is the only reference to the quarantined copy (the file came back and vanished again —
 * `persist()` deliberately keeps the trace), and without the row the copy is orphaned — no
 * "Restore", no forensics. Runs that a live finding still
 * references also stay.
 * Snapshots — the two latest full ones per zone, incomplete ones are dropped right away.
 */
class SecurityPruneCommand extends Command
{
    protected $signature = 'security:prune {--days= : Override the horizon from the config}';

    protected $description = 'Prune scanner runs and closed findings beyond the security-scanner.retention_days horizon';

    public function handle(): int
    {
        $days = (int) ($this->option('days') ?? config('security-scanner.retention_days', 180));

        if ($days <= 0) {
            $this->info('Scanner rotation is disabled (retention_days = 0).');

            return self::SUCCESS;
        }

        $horizon = now()->subDays($days);
        $findings = 0;
        $scans = 0;

        // In chunks of 500: there are few findings, but the rule is the same as in the other
        // rotations — do not hold a transaction over the whole set.
        do {
            $chunk = SecurityFinding::query()
                ->whereIn('status', [SecurityFindingStatus::Resolved->value, SecurityFindingStatus::Ignored->value])
                ->where('status_changed_at', '<', $horizon)
                ->whereNull('quarantine_path')
                ->limit(500)
                ->delete();
            $findings += $chunk;
        } while ($chunk > 0);

        do {
            $chunk = SecurityScan::query()
                ->where('created_at', '<', $horizon)
                ->whereNotExists(function ($q): void {
                    $q->selectRaw('1')
                        ->from((new SecurityFinding)->getTable().' as f')
                        ->whereColumn('f.last_scan_id', (new SecurityScan)->getTable().'.id')
                        ->orWhereColumn('f.first_scan_id', (new SecurityScan)->getTable().'.id');
                })
                ->limit(500)
                ->delete();
            $scans += $chunk;
        } while ($chunk > 0);

        $baseline = 0;
        [$zones] = Zones::resolve();

        foreach ($zones as $zone) {
            $baseline += BaselineSnapshot::prune($zone->name, 2);
        }

        $this->info(sprintf(
            'Deleted: findings %d, runs %d, snapshot rows %d (older than %d days).',
            $findings,
            $scans,
            $baseline,
            $days,
        ));

        return self::SUCCESS;
    }
}
