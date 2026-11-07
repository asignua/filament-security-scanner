<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Feature;

use Asignua\FilamentSecurityScanner\Enums\SecurityFindingStatus;
use Asignua\FilamentSecurityScanner\Models\SecurityFinding;
use Asignua\FilamentSecurityScanner\Models\SecurityScan;
use Asignua\FilamentSecurityScanner\Tests\TestCase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\File;

/**
 * A directory the web user cannot list (`chmod 0311`) still executes files inside
 * it by name. The scanner must not treat it as walked, and must not close
 * findings under it.
 */
class UnreadableDirectoryTest extends TestCase
{
    private string $root;

    protected function setUp(): void
    {
        parent::setUp();

        $this->root = sys_get_temp_dir().'/ss-unread-'.bin2hex(random_bytes(4));
        File::ensureDirectoryExists($this->root.'/storage/app/public/uploads/locked');
        $this->app->setBasePath($this->root);
        $this->app->useStoragePath($this->root.'/storage');

        config([
            'filesystems.disks.public.root' => $this->root.'/storage/app/public',
            'security-scanner.zones' => [
                'storage_public' => ['root' => 'storage/app/public', 'kind' => 'upload:web'],
            ],
        ]);

        file_put_contents($this->root.'/storage/app/public/uploads/locked/s.php', '<?php echo "neutralized"; ?>');
    }

    protected function tearDown(): void
    {
        @chmod($this->root.'/storage/app/public/uploads/locked', 0755);
        File::deleteDirectory($this->root);

        parent::tearDown();
    }

    /**
     * Runs the callback as an unprivileged user: root can list any directory, so a
     * 0311 directory is only "unreadable" to somebody else.
     */
    private function asWebUser(callable $callback): void
    {
        $dropped = function_exists('posix_geteuid') && posix_geteuid() === 0;

        if ($dropped && !posix_seteuid(65534)) {
            $this->markTestSkipped('Cannot drop privileges to emulate the web user.');
        }

        try {
            $callback();
        } finally {
            if ($dropped) {
                posix_seteuid(0);
            }
        }
    }

    public function test_an_unreadable_directory_keeps_its_findings_open_and_is_reported(): void
    {
        Artisan::call('security:scan', ['--trigger' => 'manual', '--fail-on' => 'none']);
        $finding = SecurityFinding::query()->where('path', 'like', '%locked/s.php')->firstOrFail();
        $this->assertSame(SecurityFindingStatus::New, $finding->status);

        chmod($this->root.'/storage/app/public/uploads/locked', 0311);

        $this->asWebUser(function (): void {
            Artisan::call('security:scan', ['--trigger' => 'manual', '--fail-on' => 'none']);
        });

        $this->assertSame(SecurityFindingStatus::New, $finding->fresh()?->status, 'A finding under an unreadable directory must not be resolved.');

        $scan = SecurityScan::query()->latest('id')->firstOrFail();
        $this->assertContains('uploads', $scan->scanners['incomplete'] ?? []);
        $this->assertStringContainsString('storage/app/public/uploads/locked', implode("\n", $scan->scanners['issues'] ?? []));
        $this->assertTrue(SecurityFinding::query()->where('rule_id', 'hygiene.scanner-degraded')->exists());
    }
}
