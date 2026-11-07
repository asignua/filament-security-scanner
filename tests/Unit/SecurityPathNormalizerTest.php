<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Unit;

use Asignua\FilamentSecurityScanner\Scanning\PathNormalizer;
use Asignua\FilamentSecurityScanner\Tests\PureTestCase;

/**
 * Path normalisation is the foundation of a finding's fingerprint. If the same file
 * yields two different spellings, it looks like a NEW finding every night, and the
 * panel drowns in duplicates within a week.
 */
final class SecurityPathNormalizerTest extends PureTestCase
{
    public function test_it_normalises_writings_of_the_same_path(): void
    {
        $expected = 'storage/app/public/files/12/baal.php';

        foreach ([
            'storage/app/public/files/12/baal.php',
            './storage/app/public/files/12/baal.php',
            'storage//app/public//files/12/baal.php',
            '/storage/app/public/files/12/baal.php',
        ] as $variant) {
            $this->assertSame($expected, PathNormalizer::relative($variant), $variant);
        }
    }

    public function test_it_strips_the_base_directory(): void
    {
        $this->assertSame(
            'public/index.php',
            PathNormalizer::relative('/var/www/html/public/index.php', '/var/www/html'),
        );
    }

    /**
     * Case is lowered on purpose: `shell.PHP` is executed by the same php-fpm
     * as `shell.php`, and a production media disk already holds a file with "PNG".
     */
    public function test_the_extension_chain_is_lowercased_and_reversed(): void
    {
        $this->assertSame(['jpg', 'php'], PathNormalizer::extensionChain('files/12/baal.PHP.JPG'));
        $this->assertSame(['php'], PathNormalizer::extensionChain('shell.PhP'));
    }

    /**
     * A leading dot alone does not make an extension: `.htaccess` is caught
     * by a rule on the NAME, not on the extension.
     */
    public function test_a_leading_dot_alone_is_not_an_extension(): void
    {
        $this->assertSame([], PathNormalizer::extensionChain('.htaccess'));
        $this->assertSame([], PathNormalizer::extensionChain('README'));
    }

    /**
     * But a real extension AFTER the leading dot remains an extension,
     * and this is not cosmetic. If the leading dot "ate" the whole tail of the name,
     * a hidden `.shell.php` would have an empty chain and slip past the
     * executable-extensions matcher, i.e. past the only deterministic rule
     * of the scanner.
     */
    public function test_a_hidden_file_keeps_its_real_extension(): void
    {
        $this->assertSame(['php'], PathNormalizer::extensionChain('.shell.php'));
        $this->assertSame(['php'], PathNormalizer::extensionChain('uploads/.php'));
        $this->assertSame(['jpg', 'php'], PathNormalizer::extensionChain('.PHP.jpg'));
        $this->assertSame(['ini'], PathNormalizer::extensionChain('storage/.user.ini'));
    }

    /**
     * Distinguishing `*` from `**` is not pedantry. An entry `storage/*` must cover
     * only one level: if it covered the whole subtree, an allowlist would accidentally
     * exclude the entire media disk from scanning.
     */
    public function test_single_star_does_not_cross_a_slash(): void
    {
        $this->assertTrue(PathNormalizer::matchesGlob('storage/logs', 'storage/*'));
        $this->assertFalse(PathNormalizer::matchesGlob('storage/logs/laravel.log', 'storage/*'));
        $this->assertTrue(PathNormalizer::matchesGlob('storage/logs/laravel.log', 'storage/**'));
    }

    public function test_double_star_also_matches_zero_segments(): void
    {
        $this->assertTrue(PathNormalizer::matchesGlob('public/a.php', 'public/**/*.php'));
        $this->assertTrue(PathNormalizer::matchesGlob('public/deep/nested/a.php', 'public/**/*.php'));
    }

    public function test_is_inside_does_not_match_a_sibling_with_the_same_prefix(): void
    {
        $this->assertTrue(PathNormalizer::isInside('storage/app/media/1.jpg', 'storage/app/media'));
        $this->assertFalse(PathNormalizer::isInside('storage/app/media-backup/1.jpg', 'storage/app/media'));
    }

    /**
     * A file name on Linux is bytes, not UTF-8. Raw bytes in a utf8mb4 column of
     * strict MySQL throw "Incorrect string value", and the failure of one record
     * used to stop the whole scanner together with everything it had to walk after the shell.
     */
    public function test_storable_escapes_invalid_utf8_and_control_bytes(): void
    {
        $stored = PathNormalizer::storable("storage/app/public/x\xff\x01.php");

        $this->assertSame('storage/app/public/x\xFF\x01.php', $stored);
        $this->assertTrue(mb_check_encoding($stored, 'UTF-8'));
    }

    public function test_storable_keeps_valid_unicode_as_is(): void
    {
        $this->assertSame('storage/app/public/звіт 2026.pdf', PathNormalizer::storable('storage/app/public/звіт 2026.pdf'));
    }

    /**
     * A long path does not fit `string(400)`: we truncate, but with a hash of the full
     * path in the tail, so two different deep paths with the same beginning do not
     * merge into one row in the panel.
     */
    public function test_storable_caps_the_length_with_a_hash_of_the_full_path(): void
    {
        $a = str_repeat('deep/', 100).'a.php';
        $b = str_repeat('deep/', 100).'b.php';

        $storedA = PathNormalizer::storable($a);
        $storedB = PathNormalizer::storable($b);

        $this->assertSame(PathNormalizer::MAX_STORED_LENGTH, mb_strlen($storedA));
        $this->assertNotSame($storedA, $storedB);
        $this->assertStringStartsWith('deep/deep/', $storedA);
    }
}
