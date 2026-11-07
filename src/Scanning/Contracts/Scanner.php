<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning\Contracts;

use Asignua\FilamentSecurityScanner\Scanning\Finding;
use Asignua\FilamentSecurityScanner\Scanning\ScanContext;

/**
 * One scanner.
 *
 * `scan()` returns a GENERATOR of findings and writes nothing to the DB itself. This is the boundary
 * of the layer: a scanner is a pure function from (FS, rules) to findings, so it is testable
 * without a database, while batching, dedup and statuses stay in {@see \Asignua\FilamentSecurityScanner\Scanning\ScanRunner}.
 */
interface Scanner
{
    /**
     * Identifier from Rule::SCANNERS.
     */
    public function id(): string;

    public function enabled(): bool;

    /**
     * @return iterable<Finding>
     */
    public function scan(ScanContext $context): iterable;

    /**
     * Problems of the scanner itself (zone unavailable, no git, budget exhausted).
     * Silent degradation is the main enemy of a detection subsystem.
     *
     * @return list<string>
     */
    public function issues(): array;
}
