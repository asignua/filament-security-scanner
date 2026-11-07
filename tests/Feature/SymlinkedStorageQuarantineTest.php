<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Feature;

use Asignua\FilamentSecurityScanner\Enums\SecurityFindingStatus;
use Asignua\FilamentSecurityScanner\Enums\SecuritySeverity;
use Asignua\FilamentSecurityScanner\Enums\SecurityZoneKind;
use Asignua\FilamentSecurityScanner\Models\SecurityFinding;
use Asignua\FilamentSecurityScanner\Models\SecurityScan;
use Asignua\FilamentSecurityScanner\Scanning\Finding;
use Asignua\FilamentSecurityScanner\Scanning\Quarantine;
use Asignua\FilamentSecurityScanner\Scanning\Rule;
use Asignua\FilamentSecurityScanner\Scanning\RuleRegistry;
use Asignua\FilamentSecurityScanner\Scanning\ScanContext;
use Asignua\FilamentSecurityScanner\Scanning\Zones;
use Asignua\FilamentSecurityScanner\Tests\Concerns\MakesFindings;
use Asignua\FilamentSecurityScanner\Tests\TestCase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\File;
use RuntimeException;

/**
 * Deployer layout: `storage` is a symlink to `shared/storage`. The zone lies under the project
 * by its configured path, but its realpath is outside `realpath(base)`.
 */
class SymlinkedStorageQuarantineTest extends TestCase
{
    use MakesFindings;

    private string $root;

    private string $top;

    protected function setUp(): void
    {
        parent::setUp();

        // Deployer: <top>/releases/1 is the project, <top>/shared/storage lies OUTSIDE it.
        $this->top = sys_get_temp_dir().'/ss-qlink-'.bin2hex(random_bytes(4));
        $this->root = $this->top.'/releases/1';
        File::ensureDirectoryExists($this->top.'/shared/storage/app/public/uploads');
        File::ensureDirectoryExists($this->root.'/public');
        symlink($this->top.'/shared/storage', $this->root.'/storage');
        $this->app->setBasePath($this->root);
        $this->app->useStoragePath($this->root.'/storage');

        config([
            'filesystems.disks.public.root' => $this->root.'/storage/app/public',
            'security-scanner.quarantine.auto' => true,
            'security-scanner.zones' => [
                'storage_public' => ['root' => 'storage/app/public', 'kind' => 'upload:web'],
                'public' => ['root' => 'public', 'kind' => 'webroot'],
            ],
        ]);
    }

    protected function tearDown(): void
    {
        File::deleteDirectory($this->top);

        parent::tearDown();
    }

    private function scan(): void
    {
        Artisan::call('security:scan', ['--trigger' => 'manual', '--fail-on' => 'none']);
    }

    public function test_auto_quarantine_and_restore_work_with_a_symlinked_storage(): void
    {
        $this->scan(); // the first run never moves files
        $file = $this->top.'/shared/storage/app/public/uploads/shell.php';
        file_put_contents($file, '<?php echo "neutralized"; ?>');

        $this->scan();

        $finding = SecurityFinding::query()->where('path', 'storage/app/public/uploads/shell.php')->firstOrFail();
        $this->assertSame(SecurityFindingStatus::Quarantined, $finding->status);
        $this->assertFileDoesNotExist($file);

        Quarantine::restore($finding);
        $this->assertFileExists($file);
    }

    public function test_a_failed_auto_quarantine_is_reported_in_the_run(): void
    {
        $this->scan();
        // The quarantine directory cannot be created: `private` is a file.
        file_put_contents($this->top.'/shared/storage/app/private', 'x');
        file_put_contents($this->top.'/shared/storage/app/public/uploads/shell.php', '<?php echo "neutralized"; ?>');

        $this->scan();

        $issues = implode("\n", SecurityScan::query()->latest('id')->firstOrFail()->scanners['issues'] ?? []);
        $this->assertStringContainsString('auto-quarantine failed for storage/app/public/uploads/shell.php', $issues);
    }

    public function test_a_symlinked_directory_inside_the_zone_is_refused_and_reported(): void
    {
        File::ensureDirectoryExists($this->top.'/elsewhere');
        symlink($this->top.'/elsewhere', $this->top.'/shared/storage/app/public/uploads/lnk');
        file_put_contents($this->top.'/elsewhere/shell.php', '<?php echo "neutralized"; ?>');

        $rules = RuleRegistry::load(fresh: true);
        [$zones] = Zones::resolve();
        $context = new ScanContext(base: Zones::base(), zones: $zones, rules: $rules, isFirstRun: false);
        $rule = $rules->get('uploads.executable-extension');
        $this->assertInstanceOf(Rule::class, $rule);
        $finding = new Finding('uploads.executable-extension', 'uploads', SecuritySeverity::High, 'x', 'storage/app/public/uploads/lnk/shell.php', zone: 'storage_public', zoneKind: SecurityZoneKind::UploadWeb, deterministic: true);

        $refusal = null;
        $this->assertFalse(Quarantine::mayAutoQuarantine($finding, $rule, $context, Zones::base().'/'.$finding->path, $refusal));
        $this->assertStringContainsString('outside its zone', (string) $refusal);

        $model = $this->makeFinding($finding->path);
        $this->expectException(RuntimeException::class);
        Quarantine::move($model, auto: false);
    }
}
