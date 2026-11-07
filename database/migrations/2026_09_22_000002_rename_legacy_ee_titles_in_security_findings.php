<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Legacy finding titles from before the scanner became a standalone package.
 *
 * Back then `title` stored a translation key prefixed with `ee.`; now it is
 * `security-scanner::rules.` — the `ee.` keys no longer exist in the lang files,
 * and an old row was shown in the table literally ("ee.PHP code inside a
 * binary file"). Repeated runs do not update `title` (a fingerprint match
 * only bumps counters), so the only way is to rewrite the data. The key text
 * after the prefix is the same, so replacing the prefix is enough.
 *
 * Only for hosts upgrading from the private package; on any other install there are no such rows
 * and the migration is a no-op. It is done in PHP so it does not depend on the database dialect. Idempotent: a second run will not find `ee.%`.
 */
return new class extends Migration
{
    public function up(): void
    {
        $table = (string) config('security-scanner.tables.prefix', '').'security_findings';

        if (!Schema::hasTable($table)) {
            return;
        }

        // In PHP, chunked: `CONCAT` does not exist in SQLite before 3.44 (`||` is not MySQL),
        // and a fresh install has no such rows at all, so this is a cheap no-op there.
        DB::table($table)
            ->where('title', 'like', 'ee.%')
            ->orderBy('id')
            ->chunkById(500, function ($rows) use ($table): void {
                foreach ($rows as $row) {
                    DB::table($table)
                        ->where('id', $row->id)
                        ->update(['title' => 'security-scanner::rules.'.substr((string) $row->title, 3)]);
                }
            });
    }

    public function down(): void
    {
        // There is deliberately no way back: the old format is read nowhere.
    }
};
