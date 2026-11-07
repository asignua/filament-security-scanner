<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning\Exceptions;

use RuntimeException;

/**
 * A registry rule failed validation.
 *
 * Thrown by the loader PER RULE and caught right there: a broken rule is
 * dropped from the set instead of bringing down the whole scanner. The reason is not delicacy:
 * a host-supplied rules file can be hand-edited or generated, and a
 * syntactically valid but semantically corrupted entry must not
 * blind the scanner entirely. A rejected rule turns into a
 * `hygiene.registry-rule-invalid` finding, so there is no silent loss.
 */
final class InvalidSecurityRuleException extends RuntimeException
{
    public function __construct(
        public readonly string $ruleId,
        public readonly string $reason,
    ) {
        parent::__construct(sprintf('Rule "%s" rejected: %s', $ruleId, $reason));
    }
}
