<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Filament\Resources\Security;

use Asignua\FilamentSecurityScanner\Filament\Resources\Security\Pages\ListSecurityFindings;
use Asignua\FilamentSecurityScanner\Filament\Resources\Security\Pages\ViewSecurityFinding;
use Asignua\FilamentSecurityScanner\Filament\Resources\Security\Tables\SecurityFindingsTable;
use Asignua\FilamentSecurityScanner\Models\SecurityFinding;
use Asignua\FilamentSecurityScanner\SecurityPresenter;
use Asignua\FilamentSecurityScanner\SecurityScanner;
use Asignua\FilamentSecurityScanner\SecurityScannerPlugin;
use Filament\Infolists\Components\TextEntry;
use Filament\Resources\Resource;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;
use Filament\Support\Icons\Heroicon;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Model;
use UnitEnum;

/**
 * Findings of the intrusion-trace scanner.
 *
 * Read-only: records are created by {@see \Asignua\FilamentSecurityScanner\Scanning\ScanRunner}.
 * Create/edit/delete are closed AT THE RESOURCE LEVEL, not merely hidden in the
 * UI - an audit log that can be edited is worth nothing. Only a finding's
 * STATUS can change, and that happens through separate table actions, not a form.
 *
 * Access goes through the gate {@see SecurityScanner::can()} ('view'). It is
 * denied until the host defines it with Gate::define('security-scanner.view', ...).
 *
 * There is deliberately no separate resource for scan RUNS: the state of the
 * last run is shown by the list page's subheading. A second navigation entry
 * for a log that is read once a quarter does not pay off, whereas "when did it
 * last scan" is needed every time you look at the findings and must sit next to them.
 */
class SecurityResource extends Resource
{
    protected static ?string $model = SecurityFinding::class;

    // The resource URL is public API (the e-mail and Telegram messages link to it); it is
    // pinned so that Filament does not derive `securities` from the class name.
    protected static ?string $slug = 'security';

    protected static string|\BackedEnum|null $navigationIcon = Heroicon::OutlinedShieldExclamation;

    protected static ?string $recordTitleAttribute = 'path';

    public static function canAccess(): bool
    {
        return SecurityScanner::enabled() && SecurityScanner::can('view');
    }

    public static function getNavigationGroup(): string|UnitEnum|null
    {
        return SecurityScannerPlugin::resolvedNavigationGroup();
    }

    public static function getNavigationSort(): ?int
    {
        return SecurityScannerPlugin::resolvedNavigationSort();
    }

    public static function canCreate(): bool
    {
        return false;
    }

    public static function canEdit(Model $record): bool
    {
        return false;
    }

    public static function canDelete(Model $record): bool
    {
        return false;
    }

    public static function getNavigationLabel(): string
    {
        return __('security-scanner::ui.Security findings');
    }

    public static function getModelLabel(): string
    {
        return __('security-scanner::ui.Security finding');
    }

    public static function getPluralModelLabel(): string
    {
        return __('security-scanner::ui.Security findings');
    }

    /**
     * The navigation badge counts only OPEN findings. A total that includes closed
     * ones says nothing about whether there is work to do.
     */
    public static function getNavigationBadge(): ?string
    {
        if (!static::canAccess()) {
            return null;
        }

        $open = SecurityFinding::query()->open()->count();

        return $open > 0 ? (string) $open : null;
    }

    public static function getNavigationBadgeColor(): ?string
    {
        return 'danger';
    }

    public static function table(Table $table): Table
    {
        return SecurityFindingsTable::configure($table);
    }

    public static function infolist(Schema $schema): Schema
    {
        return $schema->components([
            Section::make(__('security-scanner::ui.Security finding'))
                ->columns(2)
                ->schema([
                    TextEntry::make('severity')
                        ->label(__('security-scanner::ui.Severity'))
                        ->badge()
                        ->formatStateUsing(fn (mixed $state): string => SecurityPresenter::severityLabel(self::scalar($state)))
                        ->color(fn (mixed $state): string => SecurityPresenter::severityColor(self::scalar($state))),

                    TextEntry::make('status')
                        ->label(__('security-scanner::ui.Status'))
                        ->badge()
                        ->formatStateUsing(fn (mixed $state): string => SecurityPresenter::statusLabel(self::scalar($state)))
                        ->color(fn (mixed $state): string => SecurityPresenter::statusColor(self::scalar($state))),

                    TextEntry::make('rule_id')
                        ->label(__('security-scanner::ui.Rule'))
                        ->formatStateUsing(fn (mixed $state, SecurityFinding $record): string => SecurityPresenter::ruleLabel(self::scalar($state), $record->title))
                        ->helperText(fn (SecurityFinding $record): string => $record->rule_id),

                    TextEntry::make('scanner')
                        ->label(__('security-scanner::ui.Scanner'))
                        ->formatStateUsing(fn (mixed $state): string => SecurityPresenter::scannerLabel(self::scalar($state))),

                    TextEntry::make('path')
                        ->label(__('security-scanner::ui.Path'))
                        ->columnSpanFull()
                        ->copyable()
                        ->placeholder('—'),

                    TextEntry::make('zone')->label(__('security-scanner::ui.Zone'))->placeholder('—'),
                    TextEntry::make('disk')->label(__('security-scanner::ui.Disk'))->placeholder('—'),

                    TextEntry::make('first_seen_at')->label(__('security-scanner::ui.First seen'))->dateTime('d.m.Y H:i'),
                    TextEntry::make('last_seen_at')->label(__('security-scanner::ui.Last seen'))->dateTime('d.m.Y H:i'),

                    TextEntry::make('times_seen')->label(__('security-scanner::ui.Times seen')),
                    TextEntry::make('content_hash')->label(__('security-scanner::ui.Content hash'))->placeholder('—')->copyable(),
                ]),

            /*
             * Evidence excerpts are bytes written by the attacker. They are already
             * neutralised on the way in ({@see \Asignua\FilamentSecurityScanner\Scanning\Evidence}), but
             * we still show them as TEXT, never as markup: rendering is the place
             * where it is easiest to get this wrong.
             */
            Section::make(__('security-scanner::ui.Evidence'))
                ->visible(fn (SecurityFinding $record): bool => is_array($record->evidence) && $record->evidence !== [])
                ->schema([
                    TextEntry::make('evidence')
                        ->label(__('security-scanner::ui.Evidence'))
                        ->hiddenLabel()
                        ->columnSpanFull()
                        ->listWithLineBreaks()
                        ->formatStateUsing(fn (mixed $state): string => self::formatEvidence($state)),
                ]),

            Section::make(__('security-scanner::ui.Handling'))
                ->columns(2)
                ->visible(fn (SecurityFinding $record): bool => $record->status_changed_at !== null || $record->quarantine_path !== null)
                ->schema([
                    TextEntry::make('status_by_label')->label(__('security-scanner::ui.Changed by'))->placeholder('—'),
                    TextEntry::make('status_changed_at')->label(__('security-scanner::ui.Changed at'))->dateTime('d.m.Y H:i')->placeholder('—'),
                    TextEntry::make('status_note')->label(__('security-scanner::ui.Note'))->columnSpanFull()->placeholder('—'),
                    TextEntry::make('quarantine_path')->label(__('security-scanner::ui.Quarantine path'))->columnSpanFull()->placeholder('—'),
                ]),
        ])->columns(1);
    }

    public static function getPages(): array
    {
        return [
            'index' => ListSecurityFindings::route('/'),
            'view' => ViewSecurityFinding::route('/{record}'),
        ];
    }

    private static function scalar(mixed $state): ?string
    {
        if ($state instanceof \BackedEnum) {
            return (string) $state->value;
        }

        return is_scalar($state) ? (string) $state : null;
    }

    /**
     * Filament calls the formatter once per ITEM of an array state, so $state is one
     * evidence entry, not the list.
     */
    private static function formatEvidence(mixed $state): string
    {
        if (!is_array($state)) {
            return '—';
        }

        $rule = is_string($state['ruleId'] ?? null) ? $state['ruleId'] : '';
        $excerpt = is_string($state['excerpt'] ?? null) ? $state['excerpt'] : '';
        $offset = is_int($state['offset'] ?? null) ? ' @'.$state['offset'] : '';

        $line = trim($rule.$offset.': '.$excerpt);

        return $line === ':' ? '—' : $line;
    }
}
