<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Console;

use Asignua\FilamentSecurityScanner\Enums\SecurityZoneKind;
use Asignua\FilamentSecurityScanner\Scanning\BaselineSnapshot;
use Asignua\FilamentSecurityScanner\Scanning\GitStatus;
use Asignua\FilamentSecurityScanner\Scanning\Zone;
use Asignua\FilamentSecurityScanner\Scanning\Zones;
use Illuminate\Console\Command;

/**
 * Takes a hash snapshot of the zones git cannot see.
 *
 * IT IS CALLED AS A DEPLOY STEP, not as a schedule entry. The reason is not organizational:
 * `vendor/` is rebuilt by `composer install` on every deploy and may
 * legitimately arrive with different versions without any change in the host's git. A snapshot
 * taken right AFTER install gives zero noise until the next deploy — and any
 * discrepancy between deploys means either an intrusion or a manual hotfix, and you
 * need to know about both. A scheduled snapshot, on the contrary, would record an already changed state
 * as the norm.
 *
 * On the server it is a line in `${SITE_DIR}/deploy.post.sh`:
 *
 *     art security:baseline --zone=vendor
 *
 * Deliberately in the post-hook rather than in the shared `site-deploy.sh`: the subsystem is opt-in, and
 * a site that has not enabled it should not get an extra deploy step.
 */
class SecurityBaselineCommand extends Command
{
    protected $signature = 'security:baseline
        {--zone=* : Zone names; empty means all zones of the vendor kind}
        {--keep=2 : How many latest full snapshots to keep}';

    protected $description = 'Takes a hash snapshot of the zones git cannot see (vendor first of all)';

    public function handle(): int
    {
        if (!(bool) config('security-scanner.enabled', false)) {
            $this->components->warn('The scanner is disabled (security-scanner.enabled = false).');

            return self::SUCCESS;
        }

        [$zones, $issues] = Zones::resolve();

        foreach ($issues as $issue) {
            $this->components->warn($issue);
        }

        // The git HEAD of this deploy goes with the snapshot: the scanner flags a HEAD
        // that moved WITHOUT a new baseline (a commit makes `git status` clean).
        $git = new GitStatus(Zones::base());

        if ($git->available()) {
            $head = $git->head(full: true);

            if ($head !== null && $head !== '') {
                BaselineSnapshot::takeHead($head);
                BaselineSnapshot::prune(BaselineSnapshot::HEAD_ZONE, max(1, (int) $this->option('keep')));
                $this->components->info('Git HEAD recorded: '.substr($head, 0, 12));
            }
        }

        /** @var list<string> $wanted */
        $wanted = array_values(array_filter((array) $this->option('zone'), 'is_string'));

        $targets = array_values(array_filter(
            $zones,
            static fn (Zone $z): bool => $wanted === []
                ? $z->kind === SecurityZoneKind::Vendor
                : in_array($z->name, $wanted, true),
        ));

        if ($targets === []) {
            // A silent failure here would be the worst outcome: the deploy "passed",
            // there is no snapshot, and the next night the scanner reports "no baseline".
            $this->components->error('No zones found for the snapshot.');

            return self::FAILURE;
        }

        $allowlist = (array) config('security-scanner.allowlist.baseline', []);
        $keep = max(1, (int) $this->option('keep'));

        foreach ($targets as $zone) {
            $started = microtime(true);

            $snapshot = BaselineSnapshot::take(
                $zone,
                Zones::base(),
                array_values(array_filter($allowlist, 'is_string')),
            );

            $pruned = BaselineSnapshot::prune($zone->name, $keep);

            $this->components->info(sprintf(
                'Zone "%s": snapshot %s (%s), old rows removed %d, in %.1f s.',
                $zone->name,
                $snapshot,
                BaselineSnapshot::algo(),
                $pruned,
                microtime(true) - $started,
            ));
        }

        return self::SUCCESS;
    }
}
