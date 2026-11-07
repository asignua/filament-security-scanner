<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning;

use RecursiveDirectoryIterator;
use UnexpectedValueException;

/**
 * Records the directories that cannot be opened instead of letting
 * `RecursiveIteratorIterator::CATCH_GET_CHILD` swallow them without a trace.
 *
 * @internal used by {@see Zone::iterator()}
 */
final class ZoneDirectoryIterator extends RecursiveDirectoryIterator
{
    public ?UnreadableDirectories $unreadable = null;

    public function getChildren(): RecursiveDirectoryIterator
    {
        try {
            $child = parent::getChildren();
        } catch (UnexpectedValueException $e) {
            $this->unreadable?->add($this->getPathname());

            // Rethrown: CATCH_GET_CHILD then skips the directory, as before.
            throw $e;
        }

        if ($child instanceof self) {
            $child->unreadable = $this->unreadable;
        }

        return $child;
    }
}
