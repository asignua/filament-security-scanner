<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Feature;

use Asignua\FilamentSecurityScanner\Models\SecurityFinding;
use Asignua\FilamentSecurityScanner\Scanning\Quarantine;
use Asignua\FilamentSecurityScanner\Tests\TestCase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\File;
use Symfony\Component\Process\Process;

/**
 * Final hardening round: partial runs that stayed silent, a head that was never
 * recorded, a restore that followed a planted symlink.
 */
class HardeningRoundTest extends TestCase
{
    private string $root;

    protected function setUp(): void
    {
        parent::setUp();

        $this->root = sys_get_temp_dir().'/ss-round-'.bin2hex(random_bytes(4));
        File::ensureDirectoryExists($this->root.'/public');
        File::ensureDirectoryExists($this->root.'/app');
        File::ensureDirectoryExists($this->root.'/storage/app/public');
        file_put_contents($this->root.'/public/index.php', '<?php echo "front controller";');
        file_put_contents($this->root.'/app/A.php', '<?php class A {}');

        $this->app->setBasePath($this->root);
        $this->app->useStoragePath($this->root.'/storage');
        config([
            'filesystems.disks.public.root' => $this->root.'/storage/app/public',
            'security-scanner.zones' => [
                'public' => ['root' => 'public', 'kind' => 'webroot'],
            ],
        ]);
    }

    protected function tearDown(): void
    {
        @chmod($this->root.'/public', 0755);
        File::deleteDirectory($this->root);

        parent::tearDown();
    }

    /**
     * @param list<string> $args
     */
    private function git(array $args): string
    {
        $process = new Process(array_merge(['git', '-c', 'safe.directory='.$this->root, '-C', $this->root], $args));
        $process->mustRun();

        return $process->getOutput();
    }

    private function initGit(): void
    {
        $this->git(['init', '-q', '-b', 'main']);
        $this->commit('init');
    }

    private function commit(string $message): void
    {
        $this->git(['add', '-A']);
        $this->git(['-c', 'user.email=t@example.test', '-c', 'user.name=t', 'commit', '-q', '-m', $message]);
    }

    private function scan(): void
    {
        Artisan::call('security:scan', ['--trigger' => 'manual', '--fail-on' => 'none']);
    }

    /**
     * @return list<string>
     */
    private function paths(string $rule): array
    {
        return SecurityFinding::query()->where('rule_id', $rule)->pluck('path')->all();
    }

    public function test_an_unreadable_webroot_does_not_end_the_hygiene_run_silently(): void
    {
        chmod($this->root.'/public', 0311);

        if (function_exists('posix_geteuid') && posix_geteuid() === 0 && !posix_seteuid(65534)) {
            $this->markTestSkipped('Cannot drop privileges to emulate the web user.');
        }

        try {
            $this->scan();
        } finally {
            if (function_exists('posix_geteuid') && posix_geteuid() !== 0) {
                posix_seteuid(0);
            }
        }

        $this->assertContains(
            'hygiene:webroot',
            $this->paths('hygiene.scanner-degraded'),
            'A walk that throws must still be reported as a degraded scanner.',
        );
    }

    public function test_a_repository_without_a_recorded_head_raises_a_finding(): void
    {
        $this->initGit();

        $this->scan();

        $paths = $this->paths('code.head-unrecorded');
        $this->assertCount(1, $paths);
        $this->assertStringStartsWith('HEAD#', $paths[0]);
    }

    public function test_the_head_sha_is_part_of_the_fingerprint_so_an_ignored_finding_does_not_mask_a_later_move(): void
    {
        $this->initGit();
        $this->scan();
        $first = $this->paths('code.head-unrecorded');

        SecurityFinding::query()->where('rule_id', 'code.head-unrecorded')->update(['status' => 'ignored']);

        file_put_contents($this->root.'/app/B.php', '<?php class B {}');
        $this->commit('second');
        $this->scan();

        $paths = $this->paths('code.head-unrecorded');
        $this->assertCount(2, $paths);
        $this->assertNotSame($first[0], array_values(array_diff($paths, $first))[0]);
    }

    public function test_restore_never_follows_a_planted_symlink_when_the_target_appears_late(): void
    {
        $victim = $this->root.'/victim.txt';
        $source = $this->root.'/storage/app/source.php';
        $target = $this->root.'/storage/app/public/target.php';
        file_put_contents($victim, 'precious');
        file_put_contents($source, 'restored');
        symlink($victim, $target);

        $this->assertFalse(Quarantine::copyWithoutOverwrite($source, $target));
        $this->assertSame('precious', file_get_contents($victim));
        $this->assertFileExists($source);

        $free = $this->root.'/storage/app/public/free.php';
        $this->assertTrue(Quarantine::copyWithoutOverwrite($source, $free));
        $this->assertSame('restored', file_get_contents($free));
        $this->assertFileDoesNotExist($source);
    }
}
