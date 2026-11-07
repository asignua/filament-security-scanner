<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Feature;

use Asignua\FilamentSecurityScanner\Models\SecurityFinding;
use Asignua\FilamentSecurityScanner\Scanning\GitStatus;
use Asignua\FilamentSecurityScanner\Tests\TestCase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\File;
use Symfony\Component\Process\Process;

/**
 * Against a real throw-away git checkout.
 */
class GitHardeningTest extends TestCase
{
    private string $root;

    protected function setUp(): void
    {
        parent::setUp();

        $this->root = sys_get_temp_dir().'/ss-git-'.bin2hex(random_bytes(4));
        File::ensureDirectoryExists($this->root.'/config');
        File::ensureDirectoryExists($this->root.'/app');
        File::ensureDirectoryExists($this->root.'/bootstrap/cache');
        File::ensureDirectoryExists($this->root.'/storage/app/public');
        file_put_contents($this->root.'/config/app.php', '<?php return [];');
        file_put_contents($this->root.'/app/A.php', '<?php class A {}');

        $this->git(['init', '-q', '-b', 'main']);
        $this->git(['add', '-A']);
        $this->git(['-c', 'user.email=t@example.test', '-c', 'user.name=t', 'commit', '-q', '-m', 'init']);

        $this->app->setBasePath($this->root);
        $this->app->useStoragePath($this->root.'/storage');
        config([
            'filesystems.disks.public.root' => $this->root.'/storage/app/public',
            'security-scanner.zones' => [
                'storage_public' => ['root' => 'storage/app/public', 'kind' => 'upload:web'],
            ],
        ]);
    }

    protected function tearDown(): void
    {
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

    private function scan(): void
    {
        Artisan::call('security:scan', ['--trigger' => 'manual', '--fail-on' => 'none']);
    }

    public function test_git_status_does_not_run_a_configured_fsmonitor_command(): void
    {
        $marker = $this->root.'/fsmonitor-ran';
        $hook = $this->root.'/hook.sh';
        file_put_contents($hook, "#!/bin/sh\ntouch ".escapeshellarg($marker)."\n");
        chmod($hook, 0755);
        $this->git(['config', 'core.fsmonitor', $hook]);
        file_put_contents($this->root.'/app/A.php', '<?php class A { /* changed */ }');

        $entries = (new GitStatus($this->root))->entries();

        $this->assertIsArray($entries);
        $this->assertFileDoesNotExist($marker, 'git status must not execute core.fsmonitor.');
    }

    public function test_a_php_file_hidden_by_a_nested_gitignore_is_reported(): void
    {
        file_put_contents($this->root.'/config/.gitignore', "aaa.php\n");
        file_put_contents($this->root.'/config/aaa.php', '<?php echo "neutralized";');
        file_put_contents($this->root.'/bootstrap/cache/services.php', '<?php return [];');
        $this->git(['add', 'config/.gitignore']);
        $this->git(['-c', 'user.email=t@example.test', '-c', 'user.name=t', 'commit', '-q', '-m', 'ignore']);

        $this->scan();

        $paths = SecurityFinding::query()->where('rule_id', 'code.ignored-php-file')->pluck('path')->all();
        $this->assertSame(['config/aaa.php'], $paths, 'bootstrap/cache must stay out of it.');
    }

    public function test_the_ignored_php_directories_are_configurable(): void
    {
        File::ensureDirectoryExists($this->root.'/modules');
        file_put_contents($this->root.'/modules/.gitignore', "x.php\n");
        file_put_contents($this->root.'/modules/x.php', '<?php echo "neutralized";');
        config(['security-scanner.git.ignored_php_paths' => ['modules']]);

        $this->scan();

        $this->assertSame(['modules/x.php'], SecurityFinding::query()->where('rule_id', 'code.ignored-php-file')->pluck('path')->all());
    }

    public function test_assume_unchanged_and_skip_worktree_entries_are_reported(): void
    {
        $this->git(['update-index', '--assume-unchanged', 'config/app.php']);
        $this->git(['update-index', '--skip-worktree', 'app/A.php']);
        file_put_contents($this->root.'/config/app.php', '<?php echo "neutralized";');

        $this->scan();

        $paths = SecurityFinding::query()->where('rule_id', 'code.git-index-flag')->pluck('path')->all();
        sort($paths);
        $this->assertSame(['app/A.php', 'config/app.php'], $paths);
    }

    public function test_a_clean_checkout_raises_none_of_them(): void
    {
        $this->scan();

        $this->assertSame([], SecurityFinding::query()->whereIn('rule_id', ['code.ignored-php-file', 'code.git-index-flag'])->pluck('path')->all());
    }

    public function test_a_command_in_the_git_config_is_reported_but_not_run(): void
    {
        $this->git(['config', 'core.fsmonitor', '/bin/true']);
        $this->git(['config', 'filter.evil.clean', 'sh -c id']);
        $this->git(['config', 'filter.lfs.clean', 'git-lfs clean -- %f']);

        $keys = (new GitStatus($this->root))->executableConfig();

        sort($keys);
        $this->assertSame(['core.fsmonitor', 'filter.evil.clean'], $keys);
    }

    /**
     * A tracked file whose stat data differ from the index, so that git has to
     * run its clean filter to learn whether the content changed.
     */
    private function trackFilteredFile(): void
    {
        file_put_contents($this->root.'/.gitattributes', "*.dat filter=evil\n");
        file_put_contents($this->root.'/app/f.dat', 'one');
        $this->git(['add', '-A']);
        $this->git(['-c', 'user.email=t@example.test', '-c', 'user.name=t', 'commit', '-q', '-m', 'dat']);
        file_put_contents($this->root.'/app/f.dat', 'two');
        touch($this->root.'/app/f.dat', time() + 10);
    }

    public function test_git_status_does_not_run_a_clean_filter_that_passes_the_old_check(): void
    {
        $marker = $this->root.'/filter-ran';
        $this->trackFilteredFile();
        $this->git(['config', 'filter.evil.clean', 'true && touch '.escapeshellarg($marker).' && cat']);

        $git = new GitStatus($this->root);
        $entries = $git->entries();

        $this->assertIsArray($entries);
        $this->assertFileDoesNotExist($marker, 'git status must not execute a clean filter.');
        $this->assertContains('filter.evil.clean', $git->executableConfig());
    }

    public function test_a_filter_defined_behind_an_include_is_neither_run_nor_missed(): void
    {
        $marker = $this->root.'/include-filter-ran';
        $this->trackFilteredFile();
        file_put_contents($this->root.'/.git/extra.cfg', "[filter \"evil\"]\n\tclean = touch ".$marker." && cat\n");
        $this->git(['config', 'include.path', 'extra.cfg']);

        $git = new GitStatus($this->root);
        $git->entries();

        $this->assertFileDoesNotExist($marker);
        $this->assertContains('filter.evil.clean', $git->executableConfig());
    }

    public function test_executable_git_config_becomes_a_finding(): void
    {
        $this->git(['config', 'filter.evil.clean', 'sh -c id']);

        $this->scan();

        $this->assertSame(
            ['.git/config#filter.evil.clean'],
            SecurityFinding::query()->where('rule_id', 'code.git-executable-config')->pluck('path')->all(),
        );
    }
}
