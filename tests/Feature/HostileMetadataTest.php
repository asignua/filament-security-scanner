<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Feature;

use Asignua\FilamentSecurityScanner\Enums\SecuritySeverity;
use Asignua\FilamentSecurityScanner\Models\SecurityBaselineEntry;
use Asignua\FilamentSecurityScanner\Models\SecurityFinding;
use Asignua\FilamentSecurityScanner\Scanning\BaselineSnapshot;
use Asignua\FilamentSecurityScanner\Scanning\Contracts\Scanner;
use Asignua\FilamentSecurityScanner\Scanning\Finding;
use Asignua\FilamentSecurityScanner\Scanning\ScanContext;
use Asignua\FilamentSecurityScanner\Scanning\ScanRunner;
use Asignua\FilamentSecurityScanner\Scanning\Zone;
use Asignua\FilamentSecurityScanner\Enums\SecurityZoneKind;
use Asignua\FilamentSecurityScanner\Tests\TestCase;
use Illuminate\Support\Facades\File;

/**
 * A file's metadata comes from the file system and is attacker-controllable
 * (`touch -d 1960-01-01` gives a NEGATIVE mtime). The columns are unsigned, so
 * MariaDB rejects such a row (error 1264); it must be clamped, and one bad row
 * must never lose the others.
 */
class HostileMetadataTest extends TestCase
{
    public function test_a_negative_mtime_and_size_are_clamped_and_other_findings_survive(): void
    {
        $scanner = new class implements Scanner
        {
            public function id(): string
            {
                return 'uploads';
            }

            public function enabled(): bool
            {
                return true;
            }

            public function scan(ScanContext $context): iterable
            {
                yield new Finding('uploads.executable-extension', 'uploads', SecuritySeverity::Critical, 'security-scanner::rules.x', 'a/old.php', size: -5, mtime: -315619200);
                yield new Finding('uploads.executable-extension', 'uploads', SecuritySeverity::High, 'security-scanner::rules.x', 'a/new.php', size: 10, mtime: 1000);
            }

            public function issues(): array
            {
                return [];
            }
        };

        (new ScanRunner([$scanner]))->run();

        $old = SecurityFinding::query()->where('path', 'a/old.php')->firstOrFail();
        $this->assertSame(0, (int) $old->file_mtime);
        $this->assertSame(0, (int) $old->size);
        $this->assertSame(2, SecurityFinding::query()->count());
    }

    public function test_one_unwritable_finding_is_reported_and_does_not_lose_the_rest(): void
    {
        $scanner = new class implements Scanner
        {
            public function id(): string
            {
                return 'uploads';
            }

            public function enabled(): bool
            {
                return true;
            }

            public function scan(ScanContext $context): iterable
            {
                // A title that cannot be stored (NOT NULL violated via an exception in the model).
                yield new Finding('uploads.executable-extension', 'uploads', SecuritySeverity::High, 'security-scanner::rules.x', 'a/ok1.php');
                yield new Finding('', 'uploads', SecuritySeverity::High, "bad\xff", str_repeat('é', 5000));
                yield new Finding('uploads.executable-extension', 'uploads', SecuritySeverity::High, 'security-scanner::rules.x', 'a/ok2.php');
            }

            public function issues(): array
            {
                return [];
            }
        };

        $scan = (new ScanRunner([$scanner]))->run();

        $this->assertTrue(SecurityFinding::query()->where('path', 'a/ok1.php')->exists());
        $this->assertTrue(SecurityFinding::query()->where('path', 'a/ok2.php')->exists());
        $this->assertNotNull($scan->finished_at);
    }

    public function test_the_baseline_clamps_a_negative_mtime(): void
    {
        $root = sys_get_temp_dir().'/ss-base-'.bin2hex(random_bytes(4));
        File::ensureDirectoryExists($root.'/vendor');
        file_put_contents($root.'/vendor/a.php', 'x');
        touch($root.'/vendor/a.php', -315619200);

        $zone = new Zone('vendor', SecurityZoneKind::Vendor, $root.'/vendor');
        $id = BaselineSnapshot::take($zone, $root);

        $this->assertGreaterThanOrEqual(0, (int) SecurityBaselineEntry::query()->where('snapshot_id', $id)->value('mtime'));
        File::deleteDirectory($root);
    }
}
