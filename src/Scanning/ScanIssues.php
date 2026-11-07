<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning;

/**
 * Problems of the SCANNERS THEMSELVES during a run: an unavailable zone, no git,
 * an exhausted budget, a file that failed to open.
 *
 * Mutable, like {@see CandidateSet}, and for the same reason: the hygiene scanner
 * goes last and must turn these problems into a `hygiene.scanner-degraded`
 * FINDING. Otherwise "the scanner did not look into the zone" would stay a line
 * in a console that nobody reads, while the panel showed a clean list with a
 * clear conscience.
 */
final class ScanIssues
{
    /** @var list<array{scanner: string, message: string}> */
    private array $items = [];

    /** @var array<string, true> */
    private array $incomplete = [];

    /**
     * The scanner ran but did NOT SEE everything it should have (git did not answer).
     *
     * Deliberately separate from ordinary issues: "one file failed to open" does
     * not prevent closing the scanner's other findings, while "git status failed"
     * prevents it for all of them: an empty change list means "not checked", not
     * "clean". The run excludes such a scanner from closing findings.
     */
    public function markIncomplete(string $scanner): void
    {
        $this->incomplete[$scanner] = true;
    }

    /**
     * @return list<string>
     */
    public function incomplete(): array
    {
        return array_keys($this->incomplete);
    }

    public function add(string $scanner, string $message): void
    {
        $this->items[] = ['scanner' => $scanner, 'message' => $message];
    }

    /**
     * @param list<string> $messages
     */
    public function addMany(string $scanner, array $messages): void
    {
        foreach ($messages as $message) {
            $this->add($scanner, $message);
        }
    }

    /**
     * @return list<array{scanner: string, message: string}>
     */
    public function all(): array
    {
        return $this->items;
    }

    /**
     * @return list<string>
     */
    public function messages(): array
    {
        return array_map(static fn (array $i): string => $i['scanner'].': '.$i['message'], $this->items);
    }

    public function isEmpty(): bool
    {
        return $this->items === [];
    }
}
