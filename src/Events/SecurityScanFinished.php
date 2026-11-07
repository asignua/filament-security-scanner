<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Events;

use Illuminate\Foundation\Events\Dispatchable;

/**
 * The scanner run has finished.
 *
 * Carries ONLY scalars. The listener is queued, and a serialized run model could by
 * processing time have changed (the next run) or disappeared
 * (rotation). The listener re-reads findings from the DB through the "new and not yet
 * notified" gate — so it needs not a state snapshot but a "take a look" signal.
 *
 * `isFirstRun` is not for logic but for PRESENTATION: the first pass on a site is an
 * inventory of the existing state, not an event of the day, and the mail must say
 * so. There is no leniency for finding status, though: the three incident files had to
 * light up precisely on the first run.
 */
final class SecurityScanFinished
{
    use Dispatchable;

    public function __construct(
        public readonly string $scanUlid,
        public readonly int $newCount,
        public readonly int $totalCount,
        public readonly ?string $topSeverity,
        public readonly bool $isFirstRun,
    ) {}
}
