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

    public function test_a_php_file_inside_a_nested_repository_is_reported_as_executable(): void
    {
        File::ensureDirectoryExists($this->root.'/app/nested');
        $nested = new Process(['git', '-C', $this->root.'/app/nested', 'init', '-q']);
        $nested->mustRun();
        file_put_contents($this->root.'/app/nested/s.php', '<?php echo "neutralized";');

        $this->scan();

        $this->assertContains(
            'app/nested/s.php',
            SecurityFinding::query()->where('rule_id', 'code.untracked-executable')->pluck('path')->all(),
        );
    }

    public function test_a_self_ignored_nested_repository_does_not_hide_a_php_file(): void
    {
        File::ensureDirectoryExists($this->root.'/config/z2');
        $nested = new Process(['git', '-C', $this->root.'/config/z2', 'init', '-q']);
        $nested->mustRun();
        file_put_contents($this->root.'/config/z2/.gitignore', "*\n");
        file_put_contents($this->root.'/config/z2/s.php', '<?php echo "neutralized";');

        $this->scan();

        $this->assertContains(
            'config/z2/s.php',
            SecurityFinding::query()->where('rule_id', 'code.untracked-executable')->pluck('path')->all(),
        );
    }

    public function test_resources_is_searched_for_ignored_php_files_by_default(): void
    {
        File::ensureDirectoryExists($this->root.'/resources/views');
        file_put_contents($this->root.'/resources/views/.gitignore', "x.php\n");
        file_put_contents($this->root.'/resources/views/x.php', '<?php echo "neutralized";');
        $this->git(['add', '-A']);
        $this->git(['-c', 'user.email=t@example.test', '-c', 'user.name=t', 'commit', '-q', '-m', 'res']);

        $this->scan();

        $this->assertContains(
            'resources/views/x.php',
            SecurityFinding::query()->where('rule_id', 'code.ignored-php-file')->pluck('path')->all(),
        );
    }

    public function test_a_staged_added_php_file_is_reported(): void
    {
        file_put_contents($this->root.'/app/Staged.php', '<?php echo "neutralized";');
        $this->git(['add', 'app/Staged.php']);

        $this->scan();

        $this->assertContains(
            'app/Staged.php',
            SecurityFinding::query()->where('rule_id', 'code.untracked-executable')->pluck('path')->all(),
        );
    }

    public function test_a_commit_after_the_baseline_is_reported_until_the_baseline_is_retaken(): void
    {
        File::ensureDirectoryExists($this->root.'/vendor');
        file_put_contents($this->root.'/vendor/v.txt', 'x');
        config(['security-scanner.zones' => array_merge((array) config('security-scanner.zones'), [
            'vendor' => ['root' => 'vendor', 'kind' => 'vendor'],
        ])]);

        Artisan::call('security:baseline', ['--zone' => ['vendor']]);
        $this->scan();
        $this->assertSame([], SecurityFinding::query()->where('rule_id', 'code.git-head-moved')->pluck('path')->all());
        $this->assertSame([], SecurityFinding::query()->where('rule_id', 'code.head-unrecorded')->pluck('path')->all());

        file_put_contents($this->root.'/app/Hidden.php', '<?php echo "neutralized";');
        $this->git(['add', '-A']);
        $this->git(['-c', 'user.email=t@example.test', '-c', 'user.name=t', 'commit', '-q', '-m', 'hide']);

        $this->scan();
        $this->assertSame(['HEAD#'.substr(trim($this->git(['rev-parse', 'HEAD'])), 0, 12)], SecurityFinding::query()->where('rule_id', 'code.git-head-moved')->pluck('path')->all());

        Artisan::call('security:baseline', ['--zone' => ['vendor']]);
        $this->scan();
        $this->assertSame('resolved', SecurityFinding::query()->where('rule_id', 'code.git-head-moved')->firstOrFail()->status->value);
    }

    private function commit(string $message = 'c'): void
    {
        $this->git(['add', '-A']);
        $this->git(['-c', 'user.email=t@example.test', '-c', 'user.name=t', 'commit', '-q', '-m', $message]);
    }

    public function test_a_filter_name_with_an_equals_sign_is_still_emptied(): void
    {
        $marker = $this->root.'/eq-filter-ran';
        file_put_contents($this->root.'/.gitattributes', "*.dat filter=a=b\n");
        file_put_contents($this->root.'/app/f.dat', 'one');
        $this->commit('dat');
        file_put_contents($this->root.'/app/f.dat', 'two');
        touch($this->root.'/app/f.dat', time() + 10);
        $this->git(['config', 'filter.a=b.clean', 'touch '.escapeshellarg($marker).' && cat']);

        $git = new GitStatus($this->root);
        $this->assertIsArray($git->entries());

        $this->assertFileDoesNotExist($marker, 'a filter whose name contains = must be emptied too.');
        $this->assertContains('filter.a=b.clean', $git->executableConfig());
    }

    public function test_inherited_git_environment_is_stripped(): void
    {
        $other = sys_get_temp_dir().'/ss-nogit-'.bin2hex(random_bytes(4));
        File::ensureDirectoryExists($other);
        putenv('GIT_DIR='.$other);
        $_ENV['GIT_DIR'] = $other;
        $_SERVER['GIT_WORK_TREE'] = $other;

        try {
            $git = new GitStatus($this->root);

            $this->assertIsArray($git->entries(), 'GIT_* from the inherited environment must not steer git.');
            $this->assertSame([], $git->issues());
        } finally {
            putenv('GIT_DIR');
            unset($_ENV['GIT_DIR'], $_SERVER['GIT_WORK_TREE']);
            File::deleteDirectory($other);
        }
    }

    public function test_weakened_stat_settings_cannot_hide_a_same_size_change(): void
    {
        $file = $this->root.'/app/A.php';
        $content = file_get_contents($file);
        $this->assertNotFalse($content);
        (new Process(['touch', '-d', '2020-01-01 00:00:00.000000000', $file]))->mustRun();
        $this->git(['update-index', '--refresh']);
        $this->git(['config', 'core.trustctime', 'false']);
        $this->git(['config', 'core.checkStat', 'minimal']);

        sleep(1); // ctime has a one-second resolution in git's index
        file_put_contents($file, strrev($content));
        (new Process(['touch', '-d', '2020-01-01 00:00:00.500000000', $file]))->mustRun();

        $entries = (new GitStatus($this->root))->entries();

        $this->assertIsArray($entries);
        $this->assertContains('app/A.php', array_column($entries, 'path'));
    }

    public function test_alias_lfs_and_promisor_keys_are_flagged(): void
    {
        $this->git(['config', 'alias.lfs', '!id']);
        $this->git(['config', 'remote.origin.promisor', 'true']);
        $this->git(['config', 'remote.origin.uploadpack', 'sh -c id']);
        $this->git(['config', 'extensions.partialClone', 'origin']);

        $keys = (new GitStatus($this->root))->executableConfig();

        $this->assertContains('alias.lfs', $keys);
        $this->assertContains('remote.origin.promisor', $keys);
        $this->assertContains('remote.origin.uploadpack', $keys);
        $this->assertContains('extensions.partialclone', $keys);
    }

    public function test_gitlinks_are_reported_once(): void
    {
        $sha = trim($this->git(['rev-parse', 'HEAD']));
        $this->git(['update-index', '--add', '--cacheinfo', '160000,'.$sha.',vendor-a']);
        $this->git(['update-index', '--add', '--cacheinfo', '160000,'.$sha.',vendor-b']);

        $git = new GitStatus($this->root);
        $git->entries();
        $git->entries();

        $mentions = array_filter($git->issues(), static fn (string $i): bool => str_contains($i, 'gitlink'));
        $this->assertCount(1, $mentions);
    }

    /**
     * A fake `git-lfs` on PATH that records the environment it runs with.
     */
    private function fakeLfs(string $marker): string
    {
        $bin = $this->root.'/fake-bin';
        File::ensureDirectoryExists($bin);
        file_put_contents($bin.'/git-lfs', "#!/bin/sh\necho \"skip=\$GIT_LFS_SKIP_SMUDGE\" >> ".escapeshellarg($marker)."\ncat\n");
        chmod($bin.'/git-lfs', 0755);

        $path = (string) getenv('PATH');
        putenv('PATH='.$bin.':'.$path);
        $_SERVER['PATH'] = $_ENV['PATH'] = $bin.':'.$path;

        return $path;
    }

    public function test_the_lfs_filter_stays_but_runs_with_smudge_skipped(): void
    {
        $marker = $this->root.'/lfs-ran';
        $path = $this->fakeLfs($marker);

        try {
            file_put_contents($this->root.'/.gitattributes', "*.dat filter=lfs\n");
            file_put_contents($this->root.'/app/f.dat', 'one');
            $this->commit('dat');
            $this->git(['config', 'filter.lfs.clean', 'git-lfs clean -- %f']);
            $this->git(['config', 'filter.lfs.smudge', 'git-lfs smudge -- %f']);
            file_put_contents($this->root.'/app/f.dat', 'two');
            touch($this->root.'/app/f.dat', time() + 10);

            $git = new GitStatus($this->root);
            $this->assertIsArray($git->entries());

            $this->assertFileExists($marker, 'a plain git-lfs filter is left intact.');
            $this->assertStringContainsString('skip=1', (string) file_get_contents($marker));
            $this->assertSame([], $git->executableConfig());
        } finally {
            putenv('PATH='.$path);
            $_SERVER['PATH'] = $_ENV['PATH'] = $path;
        }
    }

    public function test_the_lfs_filter_is_emptied_when_an_alias_or_another_trick_is_present(): void
    {
        $marker = $this->root.'/lfs-ran';
        $path = $this->fakeLfs($marker);

        try {
            file_put_contents($this->root.'/.gitattributes', "*.dat filter=lfs\n");
            file_put_contents($this->root.'/app/f.dat', 'one');
            $this->commit('dat');
            $this->git(['config', 'filter.lfs.clean', 'git-lfs clean -- %f']);
            $this->git(['config', 'alias.lfs', '!touch '.escapeshellarg($marker.'-alias')]);
            file_put_contents($this->root.'/app/f.dat', 'two');
            touch($this->root.'/app/f.dat', time() + 10);

            $git = new GitStatus($this->root);
            $this->assertIsArray($git->entries());

            $this->assertFileDoesNotExist($marker);
            $this->assertFileDoesNotExist($marker.'-alias');
            $this->assertContains('alias.lfs', $git->executableConfig());
        } finally {
            putenv('PATH='.$path);
            $_SERVER['PATH'] = $_ENV['PATH'] = $path;
        }
    }

    public function test_a_writable_git_directory_is_a_finding_in_production_only(): void
    {
        config(['app.env' => 'production']);
        $this->scan();
        $this->assertSame(['.git'], SecurityFinding::query()->where('rule_id', 'code.git-dir-writable')->pluck('path')->all());

        SecurityFinding::query()->delete();
        config(['app.env' => 'local']);
        $this->scan();
        $this->assertSame([], SecurityFinding::query()->where('rule_id', 'code.git-dir-writable')->pluck('path')->all());
    }

    public function test_a_git_directory_the_web_user_cannot_write_is_not_a_finding(): void
    {
        // PHP's is_writable() is always true for root, and seteuid() does not change that.
        if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
            $this->markTestSkipped('Needs a non-root user (run with docker --user).');
        }

        $paths = [$this->root.'/.git/config', $this->root.'/.git/HEAD', $this->root.'/.git'];

        foreach ($paths as $path) {
            chmod($path, is_dir($path) ? 0555 : 0444);
        }

        try {
            $this->assertFalse((new GitStatus($this->root))->gitDirWritable());
        } finally {
            foreach (array_reverse($paths) as $path) {
                chmod($path, is_dir($path) ? 0755 : 0644);
            }
        }
    }
}
