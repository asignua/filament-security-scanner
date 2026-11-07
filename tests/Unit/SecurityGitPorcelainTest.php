<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Unit;

use Asignua\FilamentSecurityScanner\Scanning\GitStatus;
use Asignua\FilamentSecurityScanner\Tests\PureTestCase;

/**
 * Parsing of `git status --porcelain=v1 -z`.
 *
 * Home-grown parsers break here, and break silently: a rename carries
 * TWO NUL fields instead of one, and file names in upload zones may contain
 * spaces and Cyrillic, i.e. exactly the kind that git, without `-z`, would wrap
 * in its own quoting.
 */
final class SecurityGitPorcelainTest extends PureTestCase
{
    public function test_an_empty_status_gives_nothing(): void
    {
        $this->assertSame([], GitStatus::parsePorcelainZ(''));
        $this->assertSame([], GitStatus::parsePorcelainZ("\0"));
    }

    public function test_it_parses_untracked_and_modified(): void
    {
        $raw = "?? public/shell.php\0 M app/Models/User.php\0";

        $entries = GitStatus::parsePorcelainZ($raw);

        $this->assertCount(2, $entries);
        $this->assertSame('??', $entries[0]['status']);
        $this->assertSame('public/shell.php', $entries[0]['path']);
        $this->assertSame(' M', $entries[1]['status']);
        $this->assertSame('app/Models/User.php', $entries[1]['path']);
    }

    /**
     * Rename: the old path comes as a SEPARATE field after the new one. A parser
     * unaware of this swallows the old path as the next entry and reports a
     * non-existent change with an empty status.
     */
    public function test_a_rename_consumes_the_second_field(): void
    {
        $raw = "R  new/name.php\0old/name.php\0?? other.php\0";

        $entries = GitStatus::parsePorcelainZ($raw);

        $this->assertCount(2, $entries);
        $this->assertSame('R ', $entries[0]['status']);
        $this->assertSame('new/name.php', $entries[0]['path']);
        $this->assertSame('old/name.php', $entries[0]['from']);
        $this->assertSame('other.php', $entries[1]['path']);
        $this->assertNull($entries[1]['from']);
    }

    /**
     * Same for copies.
     */
    public function test_a_copy_consumes_the_second_field(): void
    {
        $entries = GitStatus::parsePorcelainZ("C  copy.php\0source.php\0");

        $this->assertCount(1, $entries);
        $this->assertSame('source.php', $entries[0]['from']);
    }

    /**
     * Spaces and Cyrillic in a name are normal for a media disk, and they are why
     * `-z` cannot be replaced by line parsing: without it git would return the name
     * in quotes with its own escaping.
     */
    public function test_it_survives_spaces_and_cyrillic_in_names(): void
    {
        $raw = "?? storage/app/public/QR підписка.jpeg\0";

        $entries = GitStatus::parsePorcelainZ($raw);

        $this->assertCount(1, $entries);
        $this->assertSame('storage/app/public/QR підписка.jpeg', $entries[0]['path']);
    }

    public function test_it_ignores_truncated_tail(): void
    {
        $entries = GitStatus::parsePorcelainZ("?? a.php\0??\0");

        $this->assertCount(1, $entries);
    }

    /**
     * A git failure is `null`, not an empty list: an empty one would read as "no
     * changes", and the run would close all code-integrity findings.
     */
    public function test_a_failed_status_is_null_not_an_empty_list(): void
    {
        $dir = sys_get_temp_dir().'/sec-no-git-'.uniqid();
        mkdir($dir);

        try {
            $git = new GitStatus($dir);

            $this->assertNull($git->entries());
            $this->assertNotSame([], $git->issues());
        } finally {
            rmdir($dir);
        }
    }
}
