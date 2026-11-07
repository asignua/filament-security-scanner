<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

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
 * Hosts that never had the previous host-integrated version of the scanner have no such rows —
 * the migration is a no-op for them. Idempotent: a second run will not find `ee.%`.
 */
return new class extends Migration
{
    public function up(): void
    {
        $table = (string) config('security-scanner.tables.prefix', '').'security_findings';

        DB::table($table)
            ->where('title', 'like', 'ee.%')
            ->update(['title' => DB::raw("CONCAT('security-scanner::rules.', SUBSTRING(title, 4))")]);
    }

    public function down(): void
    {
        // There is deliberately no way back: the old format is read nowhere.
    }
};
