<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Jobs;

use Asignua\FilamentSecurityScanner\Enums\SecurityScanTrigger;
use Asignua\FilamentSecurityScanner\Scanning\Scanners\ObfuscationScanner;
use Asignua\FilamentSecurityScanner\Scanning\Scanners\UploadZoneScanner;
use Asignua\FilamentSecurityScanner\Scanning\ScanRunner;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;

/**
 * A full pass (structure + obfuscation) over ONE just-uploaded file.
 *
 * The same ScanRunner, the same logic, one target — via restrictToPaths.
 * The run gets trigger=upload and status partial, and by invariant partial does not
 * close any findings: a targeted pass sees one file and has no right to
 * declare everything it did not see as gone.
 *
 * timeout=60 matches the existing worker (queue:work --timeout=60).
 */
final class SecurityScanPathJob implements ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;

    public int $tries = 3;

    public int $timeout = 60;

    public function __construct(public readonly string $relativePath) {}

    public function handle(): void
    {
        if (!(bool) config('security-scanner.enabled', false)) {
            return;
        }

        (new ScanRunner([
            new UploadZoneScanner,
            new ObfuscationScanner,
        ]))->run(SecurityScanTrigger::Upload, [$this->relativePath]);
    }
}
