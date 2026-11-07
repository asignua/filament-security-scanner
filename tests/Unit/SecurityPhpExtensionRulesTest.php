<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Unit;

use Asignua\FilamentSecurityScanner\Enums\SecurityZoneKind;
use Asignua\FilamentSecurityScanner\Scanning\MatchSubject;
use Asignua\FilamentSecurityScanner\Scanning\RuleRegistry;
use Asignua\FilamentSecurityScanner\Tests\PureTestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Every spelling a web server hands to the PHP engine must be caught, in any case.
 */
final class SecurityPhpExtensionRulesTest extends PureTestCase
{
    protected function tearDown(): void
    {
        RuleRegistry::flush();

        parent::tearDown();
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function pathsProvider(): array
    {
        $paths = [];

        foreach (['php', 'PHP', 'Php', 'phtml', 'PhTmL', 'phar', 'PHAR', 'pht', 'PHT', 'php3', 'php4', 'php5', 'php6', 'php7', 'php8', 'PHP8'] as $ext) {
            $paths['x.'.$ext] = [$ext];
        }

        return $paths;
    }

    #[DataProvider('pathsProvider')]
    public function test_the_webroot_rule_catches_the_extension_in_any_case(string $ext): void
    {
        $rule = RuleRegistry::load(fresh: true)->get('webroot.unexpected-php');
        $this->assertNotNull($rule);

        foreach (['public/shell.'.$ext, 'public/deep/er/shell.'.$ext] as $path) {
            $this->assertNotEmpty($rule->evaluate(MatchSubject::make($path, SecurityZoneKind::Webroot)), $path);
        }
    }

    #[DataProvider('pathsProvider')]
    public function test_the_upload_rule_catches_the_extension_in_any_case(string $ext): void
    {
        $rule = RuleRegistry::load(fresh: true)->get('uploads.executable-extension');
        $this->assertNotNull($rule);

        $this->assertNotEmpty($rule->evaluate(MatchSubject::make('uploads/a/shell.'.$ext, SecurityZoneKind::UploadWeb)), $ext);
        $this->assertNotEmpty($rule->evaluate(MatchSubject::make('uploads/a/shell.'.$ext, SecurityZoneKind::UploadPrivate)), $ext);
    }

    public function test_only_the_exact_front_controller_is_exempt_and_assets_stay_clean(): void
    {
        $rule = RuleRegistry::load(fresh: true)->get('webroot.unexpected-php');
        $this->assertNotNull($rule);

        $this->assertSame([], $rule->evaluate(MatchSubject::make('public/index.php', SecurityZoneKind::Webroot)));
        $this->assertNotEmpty($rule->evaluate(MatchSubject::make('public/INDEX.php', SecurityZoneKind::Webroot)));
        $this->assertSame([], $rule->evaluate(MatchSubject::make('public/build/app.js', SecurityZoneKind::Webroot)));
        $this->assertSame([], $rule->evaluate(MatchSubject::make('public/phpinfo.txt', SecurityZoneKind::Webroot)));
    }
}
