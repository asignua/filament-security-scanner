<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Filament\Resources\Security\Tables;

use Asignua\FilamentSecurityScanner\Enums\SecurityFindingStatus;
use Asignua\FilamentSecurityScanner\Enums\SecurityZoneKind;
use Asignua\FilamentSecurityScanner\Models\SecurityFinding;
use Asignua\FilamentSecurityScanner\Scanning\Quarantine;
use Asignua\FilamentSecurityScanner\SecurityPresenter;
use Asignua\FilamentSecurityScanner\SecurityScanner;
use Filament\Actions\Action;
use Filament\Actions\ActionGroup;
use Filament\Actions\ViewAction;
use Filament\Forms\Components\DatePicker;
use Filament\Notifications\Notification;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\Filter;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;

class SecurityFindingsTable
{
    public static function configure(Table $table): Table
    {
        return $table
            ->columns([
                TextColumn::make('severity')
                    ->label(__('security-scanner::ui.Severity'))
                    ->badge()
                    ->formatStateUsing(fn (mixed $state): string => SecurityPresenter::severityLabel(self::scalar($state)))
                    ->color(fn (mixed $state): string => SecurityPresenter::severityColor(self::scalar($state)))
                    // We sort by WEIGHT, not by the string: alphabetical order
                    // would put critical after medium, and the worst would go
                    // to the tail of the list.
                    // We normalize the direction: orderBy() accepts only 'asc'|'desc',
                    // while Filament passes an arbitrary string.
                    ->sortable(query: fn (Builder $query, string $direction): Builder => $query->orderBy(
                        'severity_weight',
                        strtolower($direction) === 'desc' ? 'desc' : 'asc',
                    )),

                TextColumn::make('rule_id')
                    ->label(__('security-scanner::ui.Rule'))
                    ->formatStateUsing(fn (mixed $state, SecurityFinding $record): string => SecurityPresenter::ruleLabel(self::scalar($state), $record->title))
                    ->description(fn (SecurityFinding $record): string => $record->rule_id)
                    ->searchable(),

                TextColumn::make('path')
                    ->label(__('security-scanner::ui.Path'))
                    ->limit(70)
                    ->tooltip(fn (SecurityFinding $record): ?string => $record->path)
                    ->searchable(),

                TextColumn::make('status')
                    ->label(__('security-scanner::ui.Status'))
                    ->badge()
                    ->formatStateUsing(fn (mixed $state): string => SecurityPresenter::statusLabel(self::scalar($state)))
                    ->color(fn (mixed $state): string => SecurityPresenter::statusColor(self::scalar($state))),

                TextColumn::make('scanner')
                    ->label(__('security-scanner::ui.Scanner'))
                    ->formatStateUsing(fn (mixed $state): string => SecurityPresenter::scannerLabel(self::scalar($state)))
                    ->toggleable(isToggledHiddenByDefault: true),

                TextColumn::make('first_seen_at')
                    ->label(__('security-scanner::ui.First seen'))
                    ->dateTime('d.m.Y H:i')
                    ->sortable()
                    ->toggleable(isToggledHiddenByDefault: true),

                TextColumn::make('last_seen_at')
                    ->label(__('security-scanner::ui.Last seen'))
                    ->dateTime('d.m.Y H:i')
                    ->sortable(),

                // Numeric columns are right-aligned — the base rule for the panel's tables.
                TextColumn::make('times_seen')
                    ->label(__('security-scanner::ui.Times seen'))
                    ->alignEnd()
                    ->sortable(),
            ])
            ->filters([
                SelectFilter::make('severity')
                    ->label(__('security-scanner::ui.Severity'))
                    ->options(SecurityPresenter::severityOptions()),

                SelectFilter::make('status')
                    ->label(__('security-scanner::ui.Status'))
                    ->options(SecurityPresenter::statusOptions()),

                SelectFilter::make('scanner')
                    ->label(__('security-scanner::ui.Scanner'))
                    ->options(SecurityPresenter::scannerOptions()),

                Filter::make('period')
                    ->label(__('security-scanner::ui.Period'))
                    ->schema([
                        DatePicker::make('from')->label(__('security-scanner::ui.From date')),
                        DatePicker::make('to')->label(__('security-scanner::ui.To date')),
                    ])
                    ->query(fn (Builder $query, array $data): Builder => $query
                        ->when(
                            $data['from'] ?? null,
                            fn (Builder $q, string $from): Builder => $q->whereDate('last_seen_at', '>=', Carbon::parse($from)),
                        )
                        ->when(
                            $data['to'] ?? null,
                            fn (Builder $q, string $to): Builder => $q->whereDate('last_seen_at', '<=', Carbon::parse($to)),
                        )),
            ])
            // Row actions ALWAYS go in a single ActionGroup — the base rule for all
            // panel tables. Status changes — ONLY here, not via the form: the resource is
            // read-only at class level, and every action leaves a signature in status_by_*.
            // "Acknowledge"/"Ignore" take a finding off the alerts, so they
            // sit behind the `triage` gate (when undefined = `quarantine`), not
            // behind `view` alone.
            ->recordActions([
                ActionGroup::make([
                    ViewAction::make(),

                    Action::make('acknowledge')
                        ->label(__('security-scanner::ui.Acknowledge'))
                        ->icon('heroicon-o-check')
                        ->visible(fn (SecurityFinding $r): bool => $r->status === SecurityFindingStatus::New
                            && SecurityScanner::can('triage'))
                        ->action(fn (SecurityFinding $r) => self::setStatus($r, SecurityFindingStatus::Acknowledged)),

                    Action::make('ignore')
                        ->label(__('security-scanner::ui.Ignore'))
                        ->icon('heroicon-o-eye-slash')
                        ->color('gray')
                        ->requiresConfirmation()
                        ->modalDescription(__('security-scanner::ui.Ignored findings never alert again, even if the file changes.'))
                        ->visible(fn (SecurityFinding $r): bool => $r->status->isOpen()
                            && SecurityScanner::can('triage'))
                        ->action(fn (SecurityFinding $r) => self::setStatus($r, SecurityFindingStatus::Ignored)),

                    Action::make('quarantine')
                        ->label(__('security-scanner::ui.Quarantine'))
                        ->icon('heroicon-o-archive-box-x-mark')
                        ->color('danger')
                        ->requiresConfirmation()
                        ->modalDescription(__('security-scanner::ui.The file will be moved out of its location and made non-executable. It can be restored later.'))
                        ->visible(fn (SecurityFinding $r): bool => $r->status->isOpen()
                            && is_string($r->path)
                            && (bool) config('security-scanner.quarantine.enabled', true)
                            && $r->zone_kind instanceof SecurityZoneKind
                            && $r->zone_kind->allowsManualQuarantine()
                            && SecurityScanner::can('quarantine'))
                        ->action(function (SecurityFinding $r): void {
                            try {
                                Quarantine::move($r, auto: false, byLabel: self::actor(), byId: self::actorId());
                                Notification::make()->title(__('security-scanner::ui.Quarantined'))->success()->send();
                            } catch (\Throwable $e) {
                                Notification::make()->title(__('security-scanner::ui.Quarantine failed'))->body($e->getMessage())->danger()->send();
                            }
                        }),

                    // Putting a known shell back into the webroot is strictly more dangerous than taking it
                    // out of there — so the host narrows the `restore` gate separately from
                    // `quarantine`. We bind not to the `Quarantined` status but to the
                    // presence of a copy: a reopened finding (the file appeared again)
                    // becomes `New` while `quarantine_path` still points at a real
                    // copy — and that is what there is to restore. `Quarantine::restore()` itself will
                    // refuse loudly if the original path is occupied.
                    Action::make('restore')
                        ->label(__('security-scanner::ui.Restore'))
                        ->icon('heroicon-o-arrow-uturn-left')
                        ->color('warning')
                        ->requiresConfirmation()
                        ->visible(fn (SecurityFinding $r): bool => $r->quarantine_path !== null
                            && SecurityScanner::can('restore'))
                        ->action(function (SecurityFinding $r): void {
                            try {
                                Quarantine::restore($r, byLabel: self::actor(), byId: self::actorId());
                                Notification::make()->title(__('security-scanner::ui.Restored'))->success()->send();
                            } catch (\Throwable $e) {
                                Notification::make()->title(__('security-scanner::ui.Restore failed'))->body($e->getMessage())->danger()->send();
                            }
                        }),
                ]),
            ])
            // The heaviest and freshest on top. Sorted by weight, not by string.
            ->defaultSort(fn (Builder $query): Builder => $query
                ->orderByDesc('severity_weight')
                ->orderByDesc('last_seen_at'))
            ->paginated([25, 50, 100]);
    }

    private static function setStatus(SecurityFinding $finding, SecurityFindingStatus $status): void
    {
        $finding->status = $status;
        $finding->status_changed_at = now();
        $finding->status_by_id = self::actorId();
        $finding->status_by_label = self::actor();
        $finding->save();

        Notification::make()->title(__('security-scanner::ui.Saved'))->success()->send();
    }

    /**
     * Auth::id() is int|string|null by the Authenticatable contract; the status_by_id
     * column is bigint. The host of this package has an integer key, but the
     * contract does not promise it, so we normalize in one place.
     */
    private static function actorId(): ?int
    {
        $id = Auth::id();

        return is_int($id) ? $id : (is_numeric($id) ? (int) $id : null);
    }

    /**
     * The label AT THE MOMENT of the action — a lesson from the activity log: after a user is renamed or
     * deleted, the record must stay readable.
     */
    private static function actor(): ?string
    {
        $user = Auth::user();

        if ($user === null) {
            return null;
        }

        $name = $user->getAttribute('name');

        return is_string($name) && $name !== '' ? $name : (string) $user->getAuthIdentifier();
    }

    private static function scalar(mixed $state): ?string
    {
        if ($state instanceof \BackedEnum) {
            return (string) $state->value;
        }

        return is_scalar($state) ? (string) $state : null;
    }
}
