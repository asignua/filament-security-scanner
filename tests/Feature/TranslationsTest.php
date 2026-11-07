<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Feature;

use Asignua\FilamentSecurityScanner\Tests\TestCase;

class TranslationsTest extends TestCase
{
    private const array LOCALES = ['de', 'en', 'es', 'fr', 'it', 'nl', 'pl', 'pt_BR', 'tr', 'uk'];

    private const array GROUPS = ['ui', 'rules'];

    public function test_every_locale_has_the_same_keys_as_english(): void
    {
        foreach (self::GROUPS as $group) {
            $english = array_keys($this->load('en', $group));
            sort($english);

            $this->assertNotEmpty($english);

            foreach (self::LOCALES as $locale) {
                $keys = array_keys($this->load($locale, $group));
                sort($keys);

                $this->assertSame($english, $keys, "Locale [{$locale}] group [{$group}] is out of step with [en].");
            }
        }
    }

    public function test_placeholders_match_english_in_every_locale(): void
    {
        foreach (self::GROUPS as $group) {
            $english = $this->load('en', $group);

            foreach (self::LOCALES as $locale) {
                foreach ($this->load($locale, $group) as $key => $value) {
                    $this->assertSame(
                        $this->placeholders($english[$key]),
                        $this->placeholders($value),
                        "Placeholders differ in [{$locale}] {$group}.{$key}.",
                    );
                    $this->assertNotSame('', trim($value), "Empty value in [{$locale}] {$group}.{$key}.");
                }
            }
        }
    }

    public function test_the_package_namespace_resolves_in_the_application(): void
    {
        app()->setLocale('en');

        $this->assertSame('Security findings', __('security-scanner::ui.Security findings'));

        app()->setLocale('uk');

        $this->assertNotSame('security-scanner::ui.Security findings', __('security-scanner::ui.Security findings'));
    }

    /**
     * @return array<string, string>
     */
    private function load(string $locale, string $group): array
    {
        $path = __DIR__.'/../../resources/lang/'.$locale.'/'.$group.'.php';

        $this->assertFileExists($path);

        /** @var array<string, string> */
        return require $path;
    }

    /**
     * @return list<string>
     */
    private function placeholders(string $value): array
    {
        preg_match_all('/:[a-z_]+/i', $value, $matches);
        $found = array_values(array_unique($matches[0]));
        sort($found);

        return $found;
    }
}
