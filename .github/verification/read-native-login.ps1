param([long] $WindowHandle)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
$window = [Windows.Automation.AutomationElement]::FromHandle([IntPtr] $WindowHandle)
$all = $window.FindAll([Windows.Automation.TreeScope]::Descendants, [Windows.Automation.Condition]::TrueCondition)
$hits = @(
  foreach ($item in $all) {
    $current = $item.Current
    if ($current.Name -match 'Ваши пароли|Только у вас|Создать|Мастер-пароль|копии|Новый мастер' -and !$current.IsOffscreen) {
      "$($current.LocalizedControlType):$($current.Name)"
    }
  }
)
if (!$hits.Count) { throw "No accessible PasswordSaver controls. UIA descendants: $($all.Count)." }
Write-Output ("::notice title=Real WebView2 accessibility::" + ($hits -join ' | '))
