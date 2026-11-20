param([long] $WindowHandle)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
$window = [Windows.Automation.AutomationElement]::FromHandle([IntPtr] $WindowHandle)
$until = [DateTime]::UtcNow.AddSeconds(15)
do {
  $all = $window.FindAll([Windows.Automation.TreeScope]::Descendants, [Windows.Automation.Condition]::TrueCondition)
  $hits = @(
    foreach ($item in $all) {
      try {
        $current = $item.Current
        if ($current.Name -match 'Ваши пароли|Только у вас|Создать|Мастер-пароль|копии|Новый мастер' -and !$current.IsOffscreen) {
          "$($current.LocalizedControlType):$($current.Name)"
        }
      } catch [Windows.Automation.ElementNotAvailableException] { }
    }
  )
  if ($hits.Count) { break }
  Start-Sleep -Seconds 1
} while ([DateTime]::UtcNow -lt $until)
if (!$hits.Count) {
  $labels = @(
    foreach ($item in $all | Select-Object -First 30) {
      try { "$($item.Current.LocalizedControlType)/$($item.Current.ClassName)/$($item.Current.Name)" }
      catch [Windows.Automation.ElementNotAvailableException] { }
    }
  ) -join ' | '
  throw "No accessible PasswordSaver controls. Window=$($window.Current.Name) :: $labels"
}
Write-Output ("::notice title=Real WebView2 accessibility::" + ($hits -join ' | '))
