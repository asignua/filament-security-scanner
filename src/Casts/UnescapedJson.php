<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Casts;

use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Database\Eloquent\Model;
use JsonException;

/**
 * A JSON cast that does NOT escape non-ASCII and slashes.
 *
 * The stock `array` cast encodes via `json_encode()` without flags, so Cyrillic
 * lands in the column as `\u0414\u043e\u0434\u0430\u0442\u0438` — semantically the same,
 * but unreadable to the eye in the DB, in dumps and in backup diffs. MariaDB does not
 * help here: `json` there is a `longtext` with `CHECK (json_valid(...))`, i.e. the string
 * is stored literally as PHP sent it (unlike MySQL 5.7+,
 * which parses JSON into its own binary format).
 *
 * Reading is tolerant of BOTH formats: `json_decode()` expands `\uXXXX` itself,
 * so existing rows need not be re-encoded — they keep reading correctly.
 *
 * @implements CastsAttributes<array<array-key, mixed>, array<array-key, mixed>>
 */
final class UnescapedJson implements CastsAttributes
{
    /**
     * @param array<string, mixed> $attributes
     *
     * @return array<array-key, mixed>|null
     */
    public function get(Model $model, string $key, mixed $value, array $attributes): ?array
    {
        if ($value === null || $value === '') {
            return null;
        }

        if (is_array($value)) {
            return $value;
        }

        $decoded = json_decode((string) $value, true);

        return is_array($decoded) ? $decoded : null;
    }

    /**
     * @param array<string, mixed> $attributes
     *
     * @throws JsonException
     */
    public function set(Model $model, string $key, mixed $value, array $attributes): ?string
    {
        if ($value === null) {
            return null;
        }

        return json_encode(
            $value,
            JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR,
        );
    }
}
