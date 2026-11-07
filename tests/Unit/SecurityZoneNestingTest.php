<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Unit;

use Asignua\FilamentSecurityScanner\Scanning\Zones;
use Asignua\FilamentSecurityScanner\Tests\PureTestCase;
use SplFileInfo;

/**
 * Nested zones: the more specific one takes its directory away from the more general one.
 *
 * Without this the `storage_app` zone (the whole application uploads directory) would walk
 * the media disk and `storage/app/public` a SECOND time: in production that is 71,786 files,
 * a doubled nightly pass and double content reading on the first run. Worse
 * than the cost is attribution: the same finding would get the zone kind of whichever
 * came first in the config, i.e. `upload:private` instead of `upload:web`, and
 * auto-quarantine in a web-reachable zone would silently stop working.
 */
class SecurityZoneNestingTest extends PureTestCase
{
    private string $base;

    protected function setUp(): void
    {
        parent::setUp();

        $this->base = sys_get_temp_dir().'/sec-zones-'.uniqid();

        foreach (['/storage/app/public', '/storage/app/media', '/storage/app/certificates'] as $dir) {
            @mkdir($this->base.$dir, 0755, true);
        }

        file_put_contents($this->base.'/storage/app/loose.txt', 'x');
        file_put_contents($this->base.'/storage/app/public/in-public.txt', 'x');
        file_put_contents($this->base.'/storage/app/media/in-media.txt', 'x');
        file_put_contents($this->base.'/storage/app/certificates/in-certs.txt', 'x');
    }

    protected function tearDown(): void
    {
        self::removeTree($this->base);

        parent::tearDown();
    }

    public function test_the_broader_zone_does_not_walk_into_a_nested_one(): void
    {
        config(['security-scanner.zones' => [
            'storage_app' => ['root' => 'storage/app', 'kind' => 'upload:private'],
            'storage_public' => ['root' => 'storage/app/public', 'kind' => 'upload:web'],
        ]]);

        [$zones, $issues] = Zones::resolve($this->base);

        $this->assertSame([], $issues);
        $this->assertCount(2, $zones);

        $files = $this->walk($zones[0]);

        $this->assertContains('storage/app/loose.txt', $files);
        $this->assertContains('storage/app/certificates/in-certs.txt', $files, 'an ordinary subdirectory stays in the zone');
        $this->assertNotContains('storage/app/public/in-public.txt', $files, 'a nested zone belongs to itself');

        $this->assertSame(['storage/app/public/in-public.txt'], $this->walk($zones[1]));
    }

    public function test_the_nested_zone_owns_its_paths(): void
    {
        config(['security-scanner.zones' => [
            'storage_app' => ['root' => 'storage/app', 'kind' => 'upload:private'],
            'storage_public' => ['root' => 'storage/app/public', 'kind' => 'upload:web'],
        ]]);

        [$zones] = Zones::resolve($this->base);
        [$app, $public] = $zones;

        // `contains()` stays geometry (a path under a root), `owns()` adds
        // ownership: a targeted run after an upload must hand the
        // file to EXACTLY one zone, otherwise config order decides the zone kind again.
        $this->assertTrue($app->contains('storage/app/public/in-public.txt', $this->base));
        $this->assertFalse($app->owns('storage/app/public/in-public.txt', $this->base));
        $this->assertTrue($public->owns('storage/app/public/in-public.txt', $this->base));
        $this->assertTrue($app->owns('storage/app/loose.txt', $this->base));
    }

    public function test_restricted_candidates_skip_paths_owned_by_a_nested_zone(): void
    {
        config(['security-scanner.zones' => [
            'storage_app' => ['root' => 'storage/app', 'kind' => 'upload:private'],
            'storage_public' => ['root' => 'storage/app/public', 'kind' => 'upload:web'],
        ]]);

        [$zones] = Zones::resolve($this->base);
        $paths = ['storage/app/loose.txt', 'storage/app/public/in-public.txt'];

        $this->assertSame(
            ['storage/app/loose.txt'],
            $this->relative($zones[0]->restrictedCandidates($paths, $this->base)),
        );
        $this->assertSame(
            ['storage/app/public/in-public.txt'],
            $this->relative($zones[1]->restrictedCandidates($paths, $this->base)),
        );
    }

    public function test_two_zones_on_the_same_folder_are_reported(): void
    {
        config(['security-scanner.zones' => [
            'storage_app' => ['root' => 'storage/app', 'kind' => 'upload:private'],
            'the_same_again' => ['root' => 'storage/app/', 'kind' => 'upload:web'],
        ]]);

        [$zones, $issues] = Zones::resolve($this->base);

        $this->assertCount(2, $zones, 'we do not drop the duplicate, we report it');
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('the_same_again', $issues[0]);
    }

    /**
     * @return list<string>
     */
    private function walk(\Asignua\FilamentSecurityScanner\Scanning\Zone $zone): array
    {
        $files = [];

        foreach ($zone->iterator() as $file) {
            if ($file->isDir()) {
                continue;
            }

            $files[] = ltrim(str_replace($this->base, '', $file->getPathname()), '/');
        }

        sort($files);

        return $files;
    }

    /**
     * @param iterable<SplFileInfo> $files
     *
     * @return list<string>
     */
    private function relative(iterable $files): array
    {
        $paths = [];

        foreach ($files as $file) {
            $paths[] = ltrim(str_replace($this->base, '', $file->getPathname()), '/');
        }

        sort($paths);

        return $paths;
    }

    private static function removeTree(string $dir): void
    {
        foreach ((array) glob($dir.'/*') as $entry) {
            if (!is_string($entry)) {
                continue;
            }

            is_dir($entry) ? self::removeTree($entry) : @unlink($entry);
        }

        @rmdir($dir);
    }
}
