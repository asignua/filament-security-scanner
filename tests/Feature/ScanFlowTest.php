<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Feature;

use Asignua\FilamentSecurityScanner\Enums\SecurityFindingStatus;
use Asignua\FilamentSecurityScanner\Models\SecurityFinding;
use Asignua\FilamentSecurityScanner\Scanning\Quarantine;
use Asignua\FilamentSecurityScanner\Tests\TestCase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\File;
use RuntimeException;

/**
 * A real scan over real (inert) files in a throw-away project root.
 */
class ScanFlowTest extends TestCase
{
    private string $root;

    protected function setUp(): void
    {
        parent::setUp();

        $this->root = sys_get_temp_dir().'/ss-flow-'.bin2hex(random_bytes(4));
        File::ensureDirectoryExists($this->root.'/storage/app/public/uploads');
        $this->app->setBasePath($this->root);
        $this->app->useStoragePath($this->root.'/storage');

        config([
            'filesystems.disks.public.root' => $this->root.'/storage/app/public',
            'security-scanner.zones' => [
                'storage_public' => ['root' => 'storage/app/public', 'kind' => 'upload:web'],
            ],
        ]);

        file_put_contents($this->root.'/storage/app/public/uploads/shell.php', '<?php echo "neutralized"; ?>');
    }

    protected function tearDown(): void
    {
        File::deleteDirectory($this->root);

        parent::tearDown();
    }

    private function shellFinding(): SecurityFinding
    {
        return SecurityFinding::query()->where('path', 'storage/app/public/uploads/shell.php')->firstOrFail();
    }

    private function scan(): void
    {
        Artisan::call('security:scan', ['--trigger' => 'manual', '--fail-on' => 'none']);
    }

    public function test_a_scan_finds_the_executable_in_the_upload_zone(): void
    {
        $this->scan();

        $finding = SecurityFinding::query()->where('path', 'storage/app/public/uploads/shell.php')->first();

        $this->assertNotNull($finding);
        $this->assertSame(SecurityFindingStatus::New, $finding->status);
    }

    public function test_a_rescan_does_not_duplicate_findings_and_keeps_a_closed_one_closed(): void
    {
        $this->scan();
        $finding = $this->shellFinding();
        $finding->status = SecurityFindingStatus::Ignored;
        $finding->save();
        $count = SecurityFinding::query()->count();

        $this->scan();

        $this->assertSame($count, SecurityFinding::query()->count());
        $this->assertSame(SecurityFindingStatus::Ignored, $finding->fresh()?->status);
        $this->assertSame(2, $finding->fresh()?->times_seen);
    }

    public function test_quarantine_moves_the_file_and_restore_puts_it_back(): void
    {
        $this->scan();
        $finding = $this->shellFinding();
        $original = $this->root.'/storage/app/public/uploads/shell.php';

        Quarantine::move($finding, auto: false, byLabel: 'tester');

        $finding->refresh();
        $this->assertFileDoesNotExist($original);
        $this->assertNotNull($finding->quarantine_path);
        $this->assertSame(SecurityFindingStatus::Quarantined, $finding->status);

        Quarantine::restore($finding, byLabel: 'tester');

        $this->assertFileExists($original);
        $this->assertSame('<?php echo "neutralized"; ?>', file_get_contents($original));
    }

    public function test_restore_refuses_to_overwrite_an_occupied_path(): void
    {
        $this->scan();
        $finding = $this->shellFinding();
        Quarantine::move($finding, auto: false);
        file_put_contents($this->root.'/storage/app/public/uploads/shell.php', 'someone else');

        $this->expectException(RuntimeException::class);

        Quarantine::restore($finding->refresh());
    }

    public function test_manual_quarantine_refuses_files_outside_upload_zones(): void
    {
        file_put_contents($this->root.'/.env', 'SECRET=1');
        $finding = new SecurityFinding;
        $finding->forceFill([
            'ulid' => 'x'.bin2hex(random_bytes(8)),
            'fingerprint' => bin2hex(random_bytes(32)),
            'scanner' => 'code',
            'rule_id' => 'code.test',
            'severity' => \Asignua\FilamentSecurityScanner\Enums\SecuritySeverity::High,
            'severity_weight' => 80,
            'zone_kind' => \Asignua\FilamentSecurityScanner\Enums\SecurityZoneKind::Code,
            'path' => '.env',
            'status' => SecurityFindingStatus::New,
            'times_seen' => 1,
            'first_seen_at' => now(),
            'last_seen_at' => now(),
        ])->save();

        try {
            Quarantine::move($finding, auto: false);
            $this->fail('A file outside an upload zone must not be quarantined.');
        } catch (RuntimeException) {
            $this->assertFileExists($this->root.'/.env');
        }
    }

    public function test_restore_refuses_a_target_that_escapes_the_project(): void
    {
        $this->scan();
        $finding = $this->shellFinding();
        Quarantine::move($finding, auto: false);
        $finding->refresh();
        $finding->path = '../../escaped.php';
        $finding->save();

        $this->expectException(RuntimeException::class);

        Quarantine::restore($finding);
    }
}
