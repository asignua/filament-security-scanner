<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Console;

use Asignua\FilamentSecurityScanner\Enums\SecurityZoneKind;
use Asignua\FilamentSecurityScanner\Scanning\MatchSubject;
use Asignua\FilamentSecurityScanner\Scanning\Rule;
use Asignua\FilamentSecurityScanner\Scanning\RuleRegistry;
use Illuminate\Console\Command;

/**
 * Heuristics registry check — a gate for new or edited rules.
 *
 * `--validate` — compilation, schema, duplicates, rejected rules (exit code 1
 * if there is at least one). `--against=<dir>` — run ALL obfuscation rules over
 * the files of the directory: everything in the `clean/` subdirectory must give zero, everything in `malicious/` —
 * at least one match. A rule set that flags a clean JPEG is rejected - that is the only thing
 * standing between a rules update and a flood of false alarms at 04:40.
 */
class SecurityRulesCommand extends Command
{
    protected $signature = 'security:rules
        {--validate : Load the registry and show rejected rules}
        {--against= : Run the rules over the fixtures in this directory (clean/ and malicious/)}
        {--list : List the rules}';

    protected $description = 'Validate and inspect the scanner heuristics registry';

    public function handle(): int
    {
        $set = RuleRegistry::load(fresh: true);
        $fail = false;

        $this->components->info(sprintf('Registry %s: %d rules, %d rejected.', $set->version, $set->count(), count($set->issues)));

        foreach ($set->issues as $issue) {
            $this->components->error($issue);
            $fail = true;
        }

        if ((bool) $this->option('list')) {
            $this->table(
                ['id', 'scanner', 'level', 'det.', 'source', 'enabled'],
                array_map(static fn (Rule $r): array => [
                    $r->id, $r->scanner, $r->severity->value, $r->deterministic ? 'yes' : '',
                    $r->source, $r->enabled ? 'yes' : 'no',
                ], $set->all()),
            );
        }

        $against = $this->option('against');

        // Without --against we check against the package's own fixtures — the command
        // stays a useful gate even without the host's set of samples.
        $dir = is_string($against) && $against !== '' ? $against : dirname(__DIR__, 2).'/tests/fixtures';

        $fail = $this->against($dir, $set) || $fail;

        return $fail ? self::FAILURE : self::SUCCESS;
    }

    /**
     * @return bool whether there is a failure
     */
    private function against(string $dir, \Asignua\FilamentSecurityScanner\Scanning\RuleSet $set): bool
    {
        $fail = false;

        foreach (['clean' => false, 'malicious' => true] as $sub => $expectHit) {
            $path = rtrim($dir, '/').'/'.$sub;

            if (!is_dir($path)) {
                continue;
            }

            foreach ((array) glob($path.'/*') as $file) {
                if (!is_string($file) || !is_file($file)) {
                    continue;
                }

                // A thumbnail named .php is a target of the structural scanner, not of obfuscation.
                if (str_contains(basename($file), 'clean-jpeg-with-php-extension')) {
                    continue;
                }

                $subject = MatchSubject::make($file, SecurityZoneKind::Code, dirname($dir), (int) filesize($file), (string) file_get_contents($file));
                $hits = [];

                foreach ($set->forScanner('obfuscation') as $rule) {
                    if ($rule->covers($subject) && $rule->evaluate($subject) !== []) {
                        $hits[] = $rule->id;
                    }
                }

                $ok = $expectHit ? $hits !== [] : $hits === [];
                $fail = $fail || !$ok;

                $line = sprintf('%s/%s → %s', $sub, basename($file), $hits === [] ? 'clean' : implode(', ', $hits));
                $ok ? $this->components->twoColumnDetail($line, 'ok') : $this->components->error($line.' — EXPECTED '.($expectHit ? 'a match' : 'clean'));
            }
        }

        return $fail;
    }
}
