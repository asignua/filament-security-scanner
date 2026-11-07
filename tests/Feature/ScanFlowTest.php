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

    public function test_a_restored_file_reopens_the_finding_as_new_and_alerts_again(): void
    {
        $this->scan();
        $finding = $this->shellFinding();
        $finding->notified_channels = ['database' => now()->toIso8601String()];
        $finding->notified_at = now();
        $finding->save();
        Quarantine::move($finding, auto: false, byLabel: 'tester');
        $this->assertNotNull($finding->refresh()->quarantined_at);

        Quarantine::restore($finding, byLabel: 'tester');

        $fresh = $finding->fresh();
        $this->assertSame(SecurityFindingStatus::New, $fresh?->status);
        $this->assertNull($fresh?->quarantined_at);
        $this->assertNull($fresh?->quarantine_path);
        $this->assertNull($fresh?->notified_channels);
        $this->assertNull($fresh?->notified_at);

        // The live shell is on disk again: a re-scan must keep the finding open and unnotified.
        $this->scan();
        $this->assertSame(SecurityFindingStatus::New, $finding->fresh()?->status);
        $this->assertNull($finding->fresh()?->notified_at);
    }

    public function test_quarantine_refuses_a_non_utf8_file_name_and_keeps_the_finding_open(): void
    {
        $name = "bad\xff.php";
        $file = $this->root.'/storage/app/public/uploads/'.$name;
        file_put_contents($file, '<?php echo "neutralized"; ?>');
        $this->scan();

        $finding = SecurityFinding::query()->where('path', 'like', '%bad%')->firstOrFail();

        try {
            Quarantine::move($finding, auto: false);
            $this->fail('A non-UTF-8 name must not be quarantined.');
        } catch (RuntimeException $e) {
            $this->assertSame((string) __('security-scanner::ui.Quarantine refused: the file name is not valid UTF-8. The finding stays open; handle the file by hand.'), $e->getMessage());
        }

        $this->assertFileExists($file);
        $this->assertSame(SecurityFindingStatus::New, $finding->fresh()?->status);
        $this->assertNull($finding->fresh()?->quarantine_path);
    }

    public function test_quarantine_refuses_a_raw_non_utf8_stored_path(): void
    {
        $file = $this->root.'/storage/app/public/uploads/raw'."\xe9".'.php';
        file_put_contents($file, '<?php echo "neutralized"; ?>');
        $this->scan();
        $finding = $this->shellFinding();
        $finding->path = 'storage/app/public/uploads/raw'."\xe9".'.php';
        $finding->save();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage((string) __('security-scanner::ui.Quarantine refused: the file name is not valid UTF-8. The finding stays open; handle the file by hand.'));

        try {
            Quarantine::move($finding, auto: false);
        } finally {
            $this->assertFileExists($file);
        }
    }

    private function planted(string $name): string
    {
        $file = $this->root.'/storage/app/public/uploads/'.$name;
        file_put_contents($file, '<?php echo "neutralized"; ?>');

        return $file;
    }

    public function test_a_file_named_with_backslash_dotdot_is_not_a_traversal(): void
    {
        $name = '..\\..\\..\\..\\public\\index.php';
        $this->planted($name);
        mkdir($this->root.'/public');
        file_put_contents($this->root.'/public/index.php', '<?php // real front controller');
        $this->scan();

        $finding = SecurityFinding::query()->where('path', 'like', '%uploads/%')->get()
            ->first(fn (SecurityFinding $f): bool => str_contains((string) $f->path, '\\'));
        $this->assertNotNull($finding);
        $this->assertSame('storage/app/public/uploads/'.$name, $finding->path);

        Quarantine::move($finding, auto: false);

        $this->assertFileExists($this->root.'/public/index.php', 'The real file outside the zone must be untouched.');
        $this->assertFileDoesNotExist($this->root.'/storage/app/public/uploads/'.$name);
    }

    public function test_quarantine_refuses_a_stored_path_with_dotdot_segments(): void
    {
        mkdir($this->root.'/public');
        file_put_contents($this->root.'/public/index.php', '<?php // real front controller');
        $this->scan();
        $finding = $this->shellFinding();
        $finding->path = 'storage/app/public/uploads/../../../../public/index.php';
        $finding->save();

        try {
            Quarantine::move($finding, auto: false);
            $this->fail('A traversing path must be refused.');
        } catch (RuntimeException) {
            $this->assertFileExists($this->root.'/public/index.php');
        }
    }

    public function test_quarantine_refuses_a_directory_symlink_that_leaves_the_zone(): void
    {
        mkdir($this->root.'/outside');
        file_put_contents($this->root.'/outside/x.php', '<?php // elsewhere in the project');
        symlink($this->root.'/outside', $this->root.'/storage/app/public/uploads/sub');
        $this->scan();
        $finding = $this->shellFinding();
        $finding->path = 'storage/app/public/uploads/sub/x.php';
        $finding->save();

        try {
            Quarantine::move($finding, auto: false);
            $this->fail('A file reached through a symlinked directory outside the zone must be refused.');
        } catch (RuntimeException) {
            $this->assertFileExists($this->root.'/outside/x.php');
        }
    }

    public function test_restore_refuses_a_destination_directory_swapped_for_a_symlink_out_of_the_zone(): void
    {
        $this->scan();
        $finding = $this->shellFinding();
        Quarantine::move($finding, auto: false);
        mkdir($this->root.'/outside');
        File::deleteDirectory($this->root.'/storage/app/public/uploads');
        symlink($this->root.'/outside', $this->root.'/storage/app/public/uploads');

        try {
            Quarantine::restore($finding->refresh());
            $this->fail('A restore through a symlink leaving the zone must be refused.');
        } catch (RuntimeException) {
            $this->assertFileDoesNotExist($this->root.'/outside/shell.php');
        }
    }

    public function test_restore_refuses_a_stored_path_that_climbs_out_of_the_zone(): void
    {
        $this->scan();
        $finding = $this->shellFinding();
        Quarantine::move($finding, auto: false);
        mkdir($this->root.'/public');
        $finding->refresh();
        $finding->path = 'storage/app/public/uploads/../../../../public/shell.php';
        $finding->save();

        try {
            Quarantine::restore($finding);
            $this->fail('A restore target outside the zone must be refused.');
        } catch (RuntimeException) {
            $this->assertFileDoesNotExist($this->root.'/public/shell.php');
        }
    }
}
