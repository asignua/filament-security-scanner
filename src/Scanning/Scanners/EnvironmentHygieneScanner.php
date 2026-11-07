<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning\Scanners;

use Asignua\FilamentSecurityScanner\Enums\SecuritySeverity;
use Asignua\FilamentSecurityScanner\Enums\SecurityZoneKind;
use Asignua\FilamentSecurityScanner\Scanning\Contracts\Scanner;
use Asignua\FilamentSecurityScanner\Scanning\Evidence;
use Asignua\FilamentSecurityScanner\Scanning\Finding;
use Asignua\FilamentSecurityScanner\Scanning\PathNormalizer;
use Asignua\FilamentSecurityScanner\Scanning\Rule;
use Asignua\FilamentSecurityScanner\Scanning\ScanContext;
use Asignua\FilamentSecurityScanner\Scanning\UnreadableDirectories;
use Asignua\FilamentSecurityScanner\Scanning\Zone;
use Generator;

/**
 * Environment hygiene: the posture of the runtime, not file content.
 *
 * Runs LAST and must complete even when everything before it crashed: it is
 * here that problems of other scanners become a `hygiene.scanner-degraded` finding.
 * Without it, "the scanner did not look into the zone" would stay a line in the console, while the panel
 * showed a clean list with a clear conscience.
 *
 * The overlap with the host's config-contract check (if the host has one) is deliberate
 * and separate: that one checks the CONFIG CONTRACT at deploy, this one the state of the FS and
 * runtime every night. Some of the checks
 * here are invariants of this particular stack, recorded in the project documentation: `proc_open` in
 * disable_functions kills the whole media pipeline, without ext-pcntl `queue:work
 * --timeout` silently does not work, MAGICK_TIME_LIMIT gives 502 from nginx.
 */
final class EnvironmentHygieneScanner implements Scanner
{
    /** @var list<string> */
    private array $issues = [];

    public function id(): string
    {
        return 'hygiene';
    }

    public function enabled(): bool
    {
        return (bool) config('security-scanner.enabled', false);
    }

    /**
     * @return list<string>
     */
    public function issues(): array
    {
        return $this->issues;
    }

    /**
     * @return Generator<Finding>
     */
    public function scan(ScanContext $context): Generator
    {
        yield from $this->application($context);
        yield from $this->phpRuntime($context);
        yield from $this->webroot($context);
        yield from $this->registry($context);
        yield from $this->degradation($context);
    }

    /**
     * @return Generator<Finding>
     */
    private function application(ScanContext $context): Generator
    {
        $env = (string) config('app.env', 'production');
        $debug = (bool) config('app.debug', false);

        if ($debug && $env === 'production') {
            yield $this->make($context, 'hygiene.debug-enabled', '.env', ['APP_ENV' => $env, 'APP_DEBUG' => 'true']);
        }

        if (trim((string) config('app.key', '')) === '') {
            yield $this->make($context, 'hygiene.app-key-missing', '.env');
        }

        // .env inside the webroot is not a "file on disk", it is all secrets going out into
        // the world with a single GET request.
        foreach ($context->zones as $zone) {
            if ($zone->kind !== SecurityZoneKind::Webroot) {
                continue;
            }

            foreach (['.env', '.env.production', '.env.local', '.env.backup'] as $name) {
                if (is_file($zone->absolutePath.'/'.$name)) {
                    yield $this->make($context, 'hygiene.env-in-webroot', PathNormalizer::relative($zone->absolutePath.'/'.$name, $context->base), [], $zone);
                }
            }
        }
    }

    /**
     * @return Generator<Finding>
     */
    private function phpRuntime(ScanContext $context): Generator
    {
        $disabled = array_map('trim', explode(',', (string) ini_get('disable_functions')));

        // Stack invariant: proc_open is needed by the image optimizer (jpegoptim/cwebp/
        // avifenc via Symfony Process) and composer. Forbidding it kills the
        // media pipeline SILENTLY.
        // The path carries the directive, not a bare `php.ini`: the fingerprint is rule|scanner|
        // path, and two different dangerous directives would otherwise merge into one
        // finding, with the runner silently dropping the second.
        if (in_array('proc_open', $disabled, true)) {
            yield $this->make($context, 'hygiene.dangerous-ini', 'php.ini#disable_functions', ['disable_functions' => 'proc_open']);
        }

        if (filter_var(ini_get('allow_url_include'), FILTER_VALIDATE_BOOLEAN)) {
            yield $this->make($context, 'hygiene.dangerous-ini', 'php.ini#allow_url_include', ['allow_url_include' => 'On']);
        }

        // Without pcntl `queue:work --timeout` silently does nothing: a worker
        // may hang on a job forever. This is exactly how production once lost it.
        if (!extension_loaded('pcntl')) {
            yield $this->make($context, 'hygiene.pcntl-missing', 'php', []);
        }

        // MAGICK_TIME_LIMIT limits the LIFETIME OF THE PROCESS, not one operation: an fpm worker
        // lives for minutes, outlives the limit, and every Imagick call dies with a
        // C-level exit(), i.e. nginx returns 502. Cannot be caught from PHP.
        $magick = getenv('MAGICK_TIME_LIMIT');

        if (is_string($magick) && $magick !== '') {
            yield $this->make($context, 'hygiene.magick-time-limit', 'env', ['MAGICK_TIME_LIMIT' => $magick]);
        }
    }

    /**
     * @return Generator<Finding>
     */
    private function webroot(ScanContext $context): Generator
    {
        foreach ($context->zones as $zone) {
            if ($zone->kind !== SecurityZoneKind::Webroot) {
                continue;
            }

            // A web server config in the webroot that loads code BEFORE every
            // request is a classic way to hide a shell so that no file
            // looks executable.
            foreach (['.htaccess', '.user.ini'] as $name) {
                $path = $zone->absolutePath.'/'.$name;

                if (!is_file($path)) {
                    continue;
                }

                $content = (string) @file_get_contents($path, false, null, 0, 65536);

                if (preg_match('~auto_(?:prepend|append)_file|php_value\s+include_path~i', $content) === 1) {
                    yield $this->make($context, 'hygiene.prepend-in-webroot', PathNormalizer::relative($path, $context->base), ['file' => $name], $zone);
                }
            }

            // A file anyone can write to is a file anyone can rewrite.
            // In the webroot this means "anyone can replace code".
            if (DIRECTORY_SEPARATOR === '/') {
                yield from $this->worldWritable($context, $zone);
            }
        }
    }

    /**
     * @return Generator<Finding>
     */
    private function worldWritable(ScanContext $context, Zone $zone): Generator
    {
        $unreadable = new UnreadableDirectories;
        $iterator = $zone->iterator(\RecursiveIteratorIterator::SELF_FIRST, $unreadable);

        $reported = 0;

        /** @var \SplFileInfo $file */
        foreach ($iterator as $file) {
            if ($file->isLink()) {
                continue;
            }

            $perms = @$file->getPerms();

            if ($perms === false || ($perms & 0002) === 0) {
                continue;
            }

            $relative = PathNormalizer::relative($file->getPathname(), $context->base);

            if ($context->isAllowlisted($relative)) {
                continue;
            }

            yield $this->make($context, 'hygiene.world-writable', $relative, ['mode' => sprintf('%04o', $perms & 0777)], $zone);

            // A ceiling, so that a broken chmod -R does not turn the panel into a thousand
            // identical rows. Beyond that the problem is one: permissions.
            if (++$reported >= 50) {
                $this->issues[] = sprintf('zone "%s": more than 50 world-writable files, the rest not listed', $zone->name);

                return;
            }
        }

        $context->issues?->addUnreadable($this->id(), $zone->name, $unreadable, $context->base);
    }

    /**
     * @return Generator<Finding>
     */
    private function registry(ScanContext $context): Generator
    {
        // Each rejected heuristic is a separate finding with a stable "path"
        // derived from the problem text: a shared `heuristics` gave one fingerprint for
        // all of them, and only the first reached the panel.
        foreach ($context->rules->issues as $issue) {
            yield $this->make($context, 'hygiene.registry-rule-invalid', 'heuristics#'.substr(hash('sha256', $issue), 0, 12), ['issue' => $issue]);
        }
    }

    /**
     * Problems of other scanners become a finding. One per scanner, not per message:
     * "uploads did not look into the zone" is one fact, however many lines it produced.
     *
     * @return Generator<Finding>
     */
    private function degradation(ScanContext $context): Generator
    {
        $byScanner = [];

        foreach ($context->issues?->all() ?? [] as $issue) {
            if ($issue['scanner'] === $this->id()) {
                continue;
            }

            $byScanner[$issue['scanner']][] = $issue['message'];
        }

        foreach ($byScanner as $scanner => $messages) {
            yield $this->make($context, 'hygiene.scanner-degraded', $scanner, [
                'scanner' => $scanner,
                'count' => count($messages),
                'first' => $messages[0],
            ]);
        }
    }

    /**
     * @param array<string, scalar|null> $detail
     */
    private function make(ScanContext $context, string $ruleId, string $path, array $detail = [], ?Zone $zone = null): Finding
    {
        $rule = $context->rules->get($ruleId);

        return new Finding(
            ruleId: $ruleId,
            scanner: $this->id(),
            severity: $rule instanceof Rule ? $rule->severity : SecuritySeverity::Medium,
            title: $rule instanceof Rule ? $rule->message : $ruleId,
            path: $path,
            evidence: [Evidence::plain($ruleId, $path, $detail)],
            zone: $zone?->name,
            zoneKind: $zone?->kind,
            disk: $zone?->disk,
            deterministic: false,
            registrySource: $rule?->source,
            registryVersion: $rule?->version,
        );
    }
}
