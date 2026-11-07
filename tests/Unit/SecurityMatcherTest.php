<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Unit;

use Asignua\FilamentSecurityScanner\Enums\SecurityZoneKind;
use Asignua\FilamentSecurityScanner\Scanning\Matchers\ExtensionMatcher;
use Asignua\FilamentSecurityScanner\Scanning\Matchers\FlagMatcher;
use Asignua\FilamentSecurityScanner\Scanning\Matchers\PathMatcher;
use Asignua\FilamentSecurityScanner\Scanning\Matchers\RegexMatcher;
use Asignua\FilamentSecurityScanner\Scanning\MatchSubject;
use Asignua\FilamentSecurityScanner\Tests\PureTestCase;

final class SecurityMatcherTest extends PureTestCase
{
    private function subject(string $path, ?string $bytes = null, bool $symlink = false): MatchSubject
    {
        return MatchSubject::make($path, SecurityZoneKind::UploadWeb, bytes: $bytes, isSymlink: $symlink);
    }

    public function test_extension_matcher_is_case_insensitive(): void
    {
        $matcher = new ExtensionMatcher(extensions: ['php']);

        $this->assertNotEmpty($matcher->match('r', $this->subject('uploads/shell.PHP')));
    }

    /**
     * `baal.php.jpg` is served as an image but executed as PHP wherever the
     * handler latches onto a partial match. This is exactly what happened in the incident.
     */
    public function test_extension_matcher_sees_the_whole_chain(): void
    {
        $matcher = new ExtensionMatcher(extensions: ['php'], chain: true);
        $evidence = $matcher->match('r', $this->subject('uploads/baal.php.jpg'));

        $this->assertNotEmpty($evidence);
        $this->assertSame('extension-in-chain', $evidence[0]->detail['reason']);
    }

    public function test_extension_matcher_can_be_limited_to_the_last_extension(): void
    {
        $matcher = new ExtensionMatcher(extensions: ['php'], chain: false);

        $this->assertSame([], $matcher->match('r', $this->subject('uploads/baal.php.jpg')));
    }

    public function test_extension_matcher_matches_exact_names(): void
    {
        $matcher = new ExtensionMatcher(names: ['.htaccess']);

        $this->assertNotEmpty($matcher->match('r', $this->subject('uploads/.htaccess')));
        $this->assertSame([], $matcher->match('r', $this->subject('uploads/backup.htaccess')));
    }

    public function test_path_matcher_honours_exceptions(): void
    {
        $matcher = new PathMatcher(patterns: ['public/*.php', 'public/**/*.php'], except: ['public/index.php']);

        $this->assertSame([], $matcher->match('r', $this->subject('public/index.php')));
        $this->assertNotEmpty($matcher->match('r', $this->subject('public/shell.php')));
        $this->assertNotEmpty($matcher->match('r', $this->subject('public/deep/shell.php')));
    }

    /**
     * Without content a content matcher must stay silent, not claim "clean".
     * The difference is critical: the scanner does not always read bytes, and "not
     * checked" must not look like "checked and found nothing".
     */
    public function test_regex_matcher_says_nothing_without_content(): void
    {
        $matcher = new RegexMatcher('~eval~');

        $this->assertSame([], $matcher->match('r', $this->subject('a/b.php')));
    }

    public function test_regex_matcher_reports_one_evidence_per_file(): void
    {
        $matcher = new RegexMatcher('~eval~');
        $evidence = $matcher->match('r', $this->subject('a/b.php', 'eval eval eval eval'));

        $this->assertCount(1, $evidence);
        $this->assertSame(4, $evidence[0]->detail['matches']);
    }

    /**
     * Bytes from a binary file must reach the panel defanged.
     */
    public function test_regex_evidence_escapes_binary_bytes(): void
    {
        $matcher = new RegexMatcher('~<\?php~');
        $evidence = $matcher->match('r', $this->subject('a/b.jpg', "\xff\xd8\xff\x00<?php echo 1;"));

        $this->assertNotEmpty($evidence);
        $this->assertStringContainsString('\xFF', $evidence[0]->excerpt);
        $this->assertStringNotContainsString("\xff", $evidence[0]->excerpt);
    }

    public function test_flag_matcher_detects_a_symlink(): void
    {
        $matcher = new FlagMatcher('symlink');

        $this->assertNotEmpty($matcher->match('r', $this->subject('uploads/link', symlink: true)));
        $this->assertSame([], $matcher->match('r', $this->subject('uploads/file', symlink: false)));
    }
}
