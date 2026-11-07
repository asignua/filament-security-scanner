@use('Asignua\FilamentSecurityScanner\SecurityPresenter')
{{-- Table cells go through markdownText(): the file name is written by the attacker, and {{ }} escapes HTML, not markdown. --}}
<x-mail::message>
# {{ $isFirstRun ? __('security-scanner::ui.Security baseline inventory: :count findings', ['count' => $newCount]) : __('security-scanner::ui.Security findings: :count new', ['count' => $newCount]) }}

{{ $siteName }}

<x-mail::table>
| {{ __('security-scanner::ui.Severity') }} | {{ __('security-scanner::ui.Rule') }} | {{ __('security-scanner::ui.Path') }} |
|:--|:--|:--|
@foreach ($findings as $row)
| {{ SecurityPresenter::markdownText($row['severity']) }} | {{ SecurityPresenter::markdownText($row['rule']) }} | {{ SecurityPresenter::markdownText($row['path']) }} |
@endforeach
</x-mail::table>

<x-mail::button :url="$panelUrl">
{{ __('security-scanner::ui.Open') }}
</x-mail::button>
</x-mail::message>
