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

    /** @var list<string> */
    private array $unreadable = [];

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

    /**
     * Directories the walk could not open: the scanner did NOT see their contents.
     * Marks it incomplete (its findings are not closed) and records an issue, which
     * hygiene turns into a `hygiene.scanner-degraded` finding.
     */
    public function addUnreadable(string $scanner, string $zone, UnreadableDirectories $directories, string $base): void
    {
        foreach ($directories->all() as $directory) {
            $message = sprintf(
                'zone "%s": directory "%s" cannot be read, its contents were NOT scanned',
                $zone,
                PathNormalizer::relative($directory, $base),
            );

            $this->markIncomplete($scanner);
            $this->add($scanner, $message);
            $this->unreadable[] = $scanner.': '.$message;
        }
    }

    /**
     * A single entry the scanner could not stat or open (a `0444` directory lists
     * but does not stat; a `0000` file does not open): the scanner did NOT see it,
     * so it is incomplete and must not close findings, but the run goes on.
     */
    public function addUnreadableFile(string $scanner, string $relative, string $reason = 'cannot be read'): void
    {
        $message = sprintf('file "%s" %s, it was NOT fully scanned', $relative, $reason);

        $this->markIncomplete($scanner);
        $this->add($scanner, $message);
        $this->unreadable[] = $scanner.': '.$message;
    }

    /**
     * Messages about unreadable directories, for the run row (scanners add them to
     * the context only, so without this they would never reach the run's issue list).
     *
     * @return list<string>
     */
    public function unreadable(): array
    {
        return array_values(array_unique($this->unreadable));
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
