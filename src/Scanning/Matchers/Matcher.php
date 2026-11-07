<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning\Matchers;

use Asignua\FilamentSecurityScanner\Scanning\Evidence;
use Asignua\FilamentSecurityScanner\Scanning\MatchSubject;

/**
 * One check over one file.
 *
 * A matcher knows nothing about severity, quarantine or the DB; it only
 * says "matched here". Everything else is decided by the rule that wraps it. Thanks to
 * this, the whole layer is testable without the filesystem, Laravel or the DB.
 */
interface Matcher
{
    /**
     * Name of the type in the heuristics registry (`matcher.type`).
     */
    public static function type(): string;

    /**
     * Whether the matcher needs the file content. The scanner reads bytes ONLY when
     * at least one applicable rule wants them; this is what cuts out reading 69k files
     * of the media disk on every nightly pass.
     */
    public function needsContent(): bool;

    /**
     * @return list<Evidence>
     */
    public function match(string $ruleId, MatchSubject $subject): array;
}
