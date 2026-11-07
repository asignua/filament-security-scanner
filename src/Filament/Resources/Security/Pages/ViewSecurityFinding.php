<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Filament\Resources\Security\Pages;

use Asignua\FilamentSecurityScanner\Filament\Resources\Security\SecurityResource;
use Filament\Resources\Pages\ViewRecord;

/**
 * Finding view.
 *
 * There are deliberately no header actions: status handling lives in the table, where neighbouring
 * findings are visible and bulk action is possible. Duplicating the same actions here would mean two
 * places that would drift apart in access rights.
 */
class ViewSecurityFinding extends ViewRecord
{
    protected static string $resource = SecurityResource::class;
}
