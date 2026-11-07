<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Feature;

use Asignua\FilamentSecurityScanner\Enums\SecurityZoneKind;
use Asignua\FilamentSecurityScanner\Models\SecurityFinding;
use Asignua\FilamentSecurityScanner\Scanning\Quarantine;
use Asignua\FilamentSecurityScanner\Tests\TestCase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\File;
use RuntimeException;

/**
 * A finding row is DB data: a tampered `zone_kind` must not widen what the
 * quarantine may move.
 */
class QuarantineTamperTest extends TestCase
{
    private string $root;

    protected function setUp(): void
    {
        parent::setUp();

        $this->root = sys_get_temp_dir().'/ss-qtamper-'.bin2hex(random_bytes(4));
        File::ensureDirectoryExists($this->root.'/storage/app/public/uploads');
        File::ensureDirectoryExists($this->root.'/public');
        $this->app->setBasePath($this->root);
        $this->app->useStoragePath($this->root.'/storage');

        config([
            'filesystems.disks.public.root' => $this->root.'/storage/app/public',
            'security-scanner.zones' => [
                'storage_public' => ['root' => 'storage/app/public', 'kind' => 'upload:web'],
                'public' => ['root' => 'public', 'kind' => 'webroot'],
            ],
        ]);

        file_put_contents($this->root.'/storage/app/public/uploads/shell.php', '<?php echo "neutralized"; ?>');
        file_put_contents($this->root.'/public/index.php', '<?php echo "front controller";');
    }

    protected function tearDown(): void
    {
        File::deleteDirectory($this->root);

        parent::tearDown();
    }

    private function shellFinding(): SecurityFinding
    {
        Artisan::call('security:scan', ['--trigger' => 'manual', '--fail-on' => 'none']);

        return SecurityFinding::query()->where('path', 'storage/app/public/uploads/shell.php')->firstOrFail();
    }

    public function test_a_tampered_row_cannot_move_a_file_of_a_webroot_zone(): void
    {
        $finding = $this->shellFinding();
        $finding->path = 'public/index.php';
        $finding->zone = 'public';
        $finding->zone_kind = SecurityZoneKind::UploadWeb;

        try {
            Quarantine::move($finding, auto: false);
            $this->fail('public/index.php must not be quarantined.');
        } catch (RuntimeException) {
            $this->assertFileExists($this->root.'/public/index.php');
        }
    }

    public function test_a_tampered_row_cannot_restore_into_a_webroot_zone(): void
    {
        $finding = $this->shellFinding();
        Quarantine::move($finding, auto: false);
        $finding->refresh();
        $finding->path = 'public/index.php';
        $finding->zone = 'public';
        $finding->zone_kind = SecurityZoneKind::UploadWeb;
        unlink($this->root.'/public/index.php');

        try {
            Quarantine::restore($finding);
            $this->fail('Restore must not write into the webroot.');
        } catch (RuntimeException) {
            $this->assertFileDoesNotExist($this->root.'/public/index.php');
        }
    }

    public function test_a_move_never_overwrites_an_existing_target(): void
    {
        $source = $this->root.'/storage/app/public/uploads/shell.php';
        $target = $this->root.'/storage/app/public/uploads/taken.php';
        file_put_contents($target, 'precious');

        $this->assertFalse(Quarantine::moveWithoutOverwrite($source, $target));
        $this->assertSame('precious', file_get_contents($target));
        $this->assertFileExists($source);

        symlink($this->root.'/nowhere', $this->root.'/storage/app/public/uploads/dangling.php');
        $this->assertFalse(Quarantine::moveWithoutOverwrite($source, $this->root.'/storage/app/public/uploads/dangling.php'));
        $this->assertFileExists($source);

        $free = $this->root.'/storage/app/public/uploads/free.php';
        $this->assertTrue(Quarantine::moveWithoutOverwrite($source, $free));
        $this->assertFileDoesNotExist($source);
        $this->assertSame('<?php echo "neutralized"; ?>', file_get_contents($free));
    }
}
