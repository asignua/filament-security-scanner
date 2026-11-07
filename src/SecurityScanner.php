<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner;

use Closure;
use Filament\Facades\Filament;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Gate;

/**
 * The single entry point for the host application. Everything has a working
 * default: the package runs without a line of code in the host; hosts only ADD
 * their own (gates, recipients, config).
 */
final class SecurityScanner
{
    /**
     * Abilities that, when left undefined, inherit another ability instead of
     * falling back to the default. See {@see self::can()}.
     */
    public const array FALLBACK_ABILITIES = ['triage' => 'quarantine'];

    private static ?Closure $notifyUsersResolver = null;

    public static function enabled(): bool
    {
        return (bool) config('security-scanner.enabled', false);
    }

    /**
     * Full table name including the host's prefix.
     */
    public static function table(string $name): string
    {
        return (string) config('security-scanner.tables.prefix', '').$name;
    }

    /**
     * The user model comes from the auth provider, not from a key of our own: the
     * package has no business asking the host for yet another config value for
     * something Laravel already knows.
     */
    public static function userModel(): ?string
    {
        $model = config('auth.providers.users.model');

        return is_string($model) && class_exists($model) ? $model : null;
    }

    /**
     * The host says who receives in-panel notifications (Filament database
     * notifications).
     *
     * @param Closure(): Collection<int, \Illuminate\Database\Eloquent\Model> $resolver
     */
    public static function notifyUsersUsing(Closure $resolver): void
    {
        self::$notifyUsersResolver = $resolver;
    }

    /**
     * @return Collection<int, \Illuminate\Database\Eloquent\Model>
     */
    public static function notifyUsers(): Collection
    {
        if (self::$notifyUsersResolver === null) {
            return new Collection;
        }

        $users = (self::$notifyUsersResolver)();

        return $users instanceof Collection ? $users : new Collection;
    }

    /**
     * Resets the static state (tests).
     */
    public static function flush(): void
    {
        self::$notifyUsersResolver = null;
    }

    /**
     * @return list<string>
     */
    public static function validateConfig(): array
    {
        return ConfigValidator::check();
    }

    /**
     * Gate check with a default. Evaluated AT CALL TIME, not at boot: host service
     * providers boot after package ones, so the host's Gate::define always makes it.
     * The default is "anybody who got into the panel", so the package works without
     * a line of code in the host; the host narrows it through
     * Gate::define('security-scanner.view', ...).
     *
     * An undefined gate listed in {@see self::FALLBACK_ABILITIES} inherits its
     * "elder" instead of the "everyone" default: `triage` (acknowledge/ignore -
     * both take a finding off the alerts, ignore forever) without its own
     * definition equals `quarantine`. Otherwise a host that widened `view` to
     * editors would also hand them the right to silence a web shell.
     */
    public static function can(string $ability): bool
    {
        $user = Filament::auth()->user();

        if ($user === null) {
            return false;
        }

        $gate = 'security-scanner.'.$ability;

        if (Gate::has($gate)) {
            return Gate::forUser($user)->allows($gate);
        }

        $fallback = self::FALLBACK_ABILITIES[$ability] ?? null;

        return $fallback !== null ? self::can($fallback) : true;
    }
}
