<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning;

use Asignua\FilamentSecurityScanner\Enums\SecuritySeverity;
use Asignua\FilamentSecurityScanner\Enums\SecurityZoneKind;
use Asignua\FilamentSecurityScanner\Scanning\Exceptions\InvalidSecurityRuleException;
use Asignua\FilamentSecurityScanner\Scanning\Matchers\Matcher;
use Asignua\FilamentSecurityScanner\Scanning\Matchers\MatcherFactory;

/**
 * One rule of the heuristics registry.
 *
 * Rules are DATA, not code: they live in `resources/security/heuristics*.php`,
 * and a host layers its own file over the package's without editing it. Because of this the
 * class deliberately has no scanning logic at all: only parsing, validation and
 * the question "does this concern me".
 *
 * `$source` is set by the LOADER based on the origin file, not by the rule author.
 * Otherwise a host rule could declare itself `package` and pose as the
 * package's own.
 */
final readonly class Rule
{
    /** Scanners able to execute rules. */
    public const array SCANNERS = ['uploads', 'code', 'obfuscation', 'hygiene'];

    /** Keys allowed in a rule entry. Anything else is an error, not "for the future". */
    private const array KNOWN_KEYS = [
        'id', 'scanner', 'severity', 'deterministic', 'enabled', 'applies_to',
        'targets', 'matcher', 'weight', 'max_read_bytes', 'message',
        'source', 'origin', 'version', 'references', 'allowlist',
    ];

    /**
     * @param list<SecurityZoneKind> $appliesTo
     * @param list<string>           $targets         extensions the rule applies to; empty = all
     * @param list<string>           $references
     * @param list<string>           $allowlistPaths
     * @param list<string>           $allowlistHashes
     */
    public function __construct(
        public string $id,
        public string $scanner,
        public SecuritySeverity $severity,
        public Matcher $matcher,
        public array $appliesTo,
        public bool $deterministic = false,
        public bool $enabled = true,
        public array $targets = [],
        public int $weight = 1,
        public int $maxReadBytes = 1048576,
        public string $message = '',
        public string $source = 'package',
        public ?string $origin = null,
        public ?string $version = null,
        public array $references = [],
        public array $allowlistPaths = [],
        public array $allowlistHashes = [],
    ) {}

    /**
     * @param array<string, mixed> $raw
     *
     * @throws InvalidSecurityRuleException
     */
    public static function fromArray(array $raw, string $source): self
    {
        $id = $raw['id'] ?? null;

        if (!is_string($id) || !preg_match('~^[a-z0-9]+(?:[._-][a-z0-9]+)+$~', $id)) {
            throw new InvalidSecurityRuleException(
                is_string($id) ? $id : '(no id)',
                'id must be a string of the form "scanner.rule-name"',
            );
        }

        // An unknown key is exactly the symptom a silently corrupted import starts with:
        // a typo in `applies_to` would quietly make the rule global.
        $unknown = array_diff(array_keys($raw), self::KNOWN_KEYS);

        if ($unknown !== []) {
            throw new InvalidSecurityRuleException($id, 'unknown keys: '.implode(', ', $unknown));
        }

        $scanner = $raw['scanner'] ?? null;

        if (!is_string($scanner) || !in_array($scanner, self::SCANNERS, true)) {
            throw new InvalidSecurityRuleException($id, 'scanner must be one of: '.implode(', ', self::SCANNERS));
        }

        $severity = SecuritySeverity::tryFromName(is_string($raw['severity'] ?? null) ? $raw['severity'] : null);

        if ($severity === null) {
            throw new InvalidSecurityRuleException($id, 'unknown severity');
        }

        $matcherConfig = $raw['matcher'] ?? null;

        if (!is_array($matcherConfig)) {
            throw new InvalidSecurityRuleException($id, 'matcher must be an array');
        }

        /** @var array<string, mixed> $matcherConfig */
        $matcher = MatcherFactory::make($id, $matcherConfig);

        $deterministic = (bool) ($raw['deterministic'] ?? false);

        // Structural guarantee of auto-quarantine. It must NOT be replaced by an agreement:
        // this is exactly the one place where a regex could get the right to move someone else's file.
        if ($deterministic && !in_array($matcherConfig['type'], MatcherFactory::deterministicTypes(), true)) {
            throw new InvalidSecurityRuleException(
                $id,
                sprintf(
                    'deterministic is allowed only for matcher.type in {%s}; a heuristic cannot enable auto-quarantine',
                    implode(', ', MatcherFactory::deterministicTypes()),
                ),
            );
        }

        $appliesTo = [];

        foreach ((array) ($raw['applies_to'] ?? []) as $kind) {
            $resolved = is_string($kind) ? SecurityZoneKind::tryFrom($kind) : null;

            if ($resolved === null) {
                throw new InvalidSecurityRuleException($id, sprintf('unknown zone kind "%s" in applies_to', is_string($kind) ? $kind : gettype($kind)));
            }

            $appliesTo[] = $resolved;
        }

        if ($appliesTo === []) {
            throw new InvalidSecurityRuleException($id, 'applies_to is empty; the rule is not applicable anywhere');
        }

        $weight = $raw['weight'] ?? 1;
        $maxRead = $raw['max_read_bytes'] ?? 1048576;

        if (!is_int($weight) || $weight < 0) {
            throw new InvalidSecurityRuleException($id, 'weight must be an integer >= 0');
        }

        if (!is_int($maxRead) || $maxRead < 1) {
            throw new InvalidSecurityRuleException($id, 'max_read_bytes must be an integer >= 1');
        }

        /** @var array<string, mixed> $allowlist */
        $allowlist = is_array($raw['allowlist'] ?? null) ? $raw['allowlist'] : [];

        return new self(
            id: $id,
            scanner: $scanner,
            severity: $severity,
            matcher: $matcher,
            appliesTo: $appliesTo,
            deterministic: $deterministic,
            enabled: (bool) ($raw['enabled'] ?? true),
            targets: self::strings($raw['targets'] ?? []),
            weight: $weight,
            maxReadBytes: $maxRead,
            message: is_string($raw['message'] ?? null) ? $raw['message'] : '',
            source: $source,
            origin: is_string($raw['origin'] ?? null) ? $raw['origin'] : null,
            version: is_string($raw['version'] ?? null) ? $raw['version'] : null,
            references: self::strings($raw['references'] ?? []),
            allowlistPaths: self::strings($allowlist['paths'] ?? []),
            allowlistHashes: self::strings($allowlist['hashes'] ?? []),
        );
    }

    public function appliesToZone(SecurityZoneKind $kind): bool
    {
        return in_array($kind, $this->appliesTo, true);
    }

    /**
     * Whether the rule looks at this file at all: zone kind + (if set) extension.
     * An empty `targets` means "any extension", not "none".
     */
    public function covers(MatchSubject $subject): bool
    {
        if (!$this->enabled || !$this->appliesToZone($subject->zoneKind)) {
            return false;
        }

        if ($this->targets === []) {
            return true;
        }

        return array_intersect($subject->extensionChain, $this->targets) !== [];
    }

    public function isAllowlisted(string $path, ?string $hash = null): bool
    {
        if ($hash !== null && in_array($hash, $this->allowlistHashes, true)) {
            return true;
        }

        foreach ($this->allowlistPaths as $pattern) {
            if (PathNormalizer::matchesGlob($path, $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return list<Evidence>
     */
    public function evaluate(MatchSubject $subject): array
    {
        return $this->matcher->match($this->id, $subject);
    }

    /**
     * @return list<string>
     */
    private static function strings(mixed $value): array
    {
        if (!is_array($value)) {
            return [];
        }

        return array_values(array_filter(
            array_map(static fn (mixed $v): string => is_string($v) ? $v : '', $value),
            static fn (string $v): bool => $v !== '',
        ));
    }
}
