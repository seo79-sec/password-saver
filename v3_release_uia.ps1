$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, System.Windows.Forms
$script:process = $null
$script:window = $null
$oldTitle = 'Edited after activation'
$laterTitle = 'Synthetic mail'
function Note($text) {
  Write-Output "::notice title=Native backup scenario::$text"
  if ($env:GITHUB_STEP_SUMMARY) { Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value $text -Encoding UTF8 }
}

function Find-Control($name, $type, [switch]$partial) {
  $elementType = [Windows.Automation.AutomationElement]
  $condition = if ($type) {
    $controlType = switch ($type) {
      'Button' { [Windows.Automation.ControlType]::Button }
      'Edit' { [Windows.Automation.ControlType]::Edit }
      'CheckBox' { [Windows.Automation.ControlType]::CheckBox }
      default { throw 'Unknown native test control type' }
    }
    [Windows.Automation.PropertyCondition]::new($elementType::ControlTypeProperty, $controlType)
  } else { [Windows.Automation.Condition]::TrueCondition }
  if (!$partial) {
    $condition = [Windows.Automation.AndCondition]::new($condition,
      [Windows.Automation.PropertyCondition]::new($elementType::NameProperty, $name))
  }
  foreach ($control in $script:window.FindAll([Windows.Automation.TreeScope]::Descendants, $condition)) {
    try {
      if (!$partial -or ([string]$control.Current.Name).Contains($name)) { return $control }
    } catch [Windows.Automation.ElementNotAvailableException] { }
  }
  return $null
}

function Control($name, $type, [switch]$partial) {
  $end = [DateTime]::UtcNow.AddSeconds(16)
  do {
    try {
      $control = Find-Control $name $type -partial:$partial
      if ($null -ne $control) { return $control }
    } catch [Windows.Automation.ElementNotAvailableException] { }
    if ($script:process.HasExited) { throw 'EXE exited while locating a control' }
    Start-Sleep -Milliseconds 180
  } while ([DateTime]::UtcNow -lt $end)
  throw "Missing $type control '$name'"
}

function See($text) { $null = Control $text '' -partial }
# WebView2 exposes static text and Svelte interpolation as separate UIA
# text fragments, even when they appear on a single line to the user.
function See-CombinedText($pattern) {
  $condition = [Windows.Automation.PropertyCondition]::new(
    [Windows.Automation.AutomationElement]::ControlTypeProperty,
    [Windows.Automation.ControlType]::Text)
  $until = [DateTime]::UtcNow.AddSeconds(8)
  do {
    $strings = @(
      foreach ($element in $script:window.FindAll([Windows.Automation.TreeScope]::Descendants, $condition)) {
        try { if (!$element.Current.IsOffscreen) { [string] $element.Current.Name } }
        catch [Windows.Automation.ElementNotAvailableException] { }
      }
    )
    if (($strings -join ' ') -match $pattern) { return }
    Start-Sleep -Milliseconds 150
  } while ([DateTime]::UtcNow -lt $until)
  throw "Missing preview text matching '$pattern'"
}

function Absent($text, $type) {
  if ($null -ne (Find-Control $text $type -partial)) { throw "Unexpected GUI control '$text'" }
}

function Click($name) {
  $button = Control $name 'Button'
  $end = [DateTime]::UtcNow.AddSeconds(8)
  while (!$button.Current.IsEnabled -and [DateTime]::UtcNow -lt $end) {
    Start-Sleep -Milliseconds 160
    $button = Control $name 'Button'
  }
  $button.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke()
}

function Type-Value($label, $value, [switch]$partial, [switch]$keyboard) {
  $field = Control $label 'Edit' -partial:$partial
  if (!$keyboard) {
    try {
      $pattern = $field.GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern)
      $pattern.SetValue($value)
      return
    } catch [InvalidOperationException] { }
  }
  # A protected edit may omit ValuePattern. Enter the synthetic values through
  # normal Windows keystrokes in the focused field. No clipboard or logs.
  $null = (New-Object -ComObject WScript.Shell).AppActivate($script:process.Id)
  $field.SetFocus()
  [Windows.Forms.SendKeys]::SendWait('^a')
  if ($value) { [Windows.Forms.SendKeys]::SendWait($value) }
  else { [Windows.Forms.SendKeys]::SendWait('{BACKSPACE}') }
}

function Wait-Window($exe, $profile) {
  $psi = [Diagnostics.ProcessStartInfo]::new($exe)
  $psi.WorkingDirectory = $profile
  $psi.UseShellExecute = $false
  $psi.EnvironmentVariables['LOCALAPPDATA'] = Join-Path $profile 'Local'
  $psi.EnvironmentVariables['APPDATA'] = Join-Path $profile 'Roaming'
  $psi.RedirectStandardError = $true
  $script:process = [Diagnostics.Process]::Start($psi)
  $script:appStderr = $script:process.StandardError.ReadToEndAsync()
  $end = [DateTime]::UtcNow.AddSeconds(40)
  do {
    $script:process.Refresh()
    if ($script:process.HasExited) { throw 'EXE exited before its native window opened' }
    if ($script:process.MainWindowHandle -ne 0) { break }
    Start-Sleep -Milliseconds 250
  } while ([DateTime]::UtcNow -lt $end)
  if ($script:process.MainWindowHandle -eq 0) {
    Note ("The pinned EXE stayed alive with no native window handle. Session ID=" + $script:process.SessionId + ".")
    throw 'EXE had no native window handle'
  }
  $script:window = [Windows.Automation.AutomationElement]::FromHandle($script:process.MainWindowHandle)
  See 'Только у вас.'
  Note 'Observed the actual Windows login window and WebView2 controls via UI Automation.'
}

function Close-App {
  if (!$script:process.HasExited) {
    if (!$script:process.CloseMainWindow() -or !$script:process.WaitForExit(10000)) {
      throw 'The EXE did not close cleanly'
    }
  }
  if ($script:process.ExitCode -ne 0) { throw "Unexpected EXIT code $($script:process.ExitCode)" }
  $script:process.Dispose()
  $script:process = $null
  $script:window = $null
}

function Test-TOTP($encoding, [int]$offset = 0) {
  $letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  $bytes = [Collections.Generic.List[byte]]::new()
  [int]$value = 0
  $bits = 0
  foreach ($letter in $encoding.TrimEnd('=').ToCharArray()) {
    $number = $letters.IndexOf($letter)
    if ($number -lt 0) { throw 'Unrecognized authenticator encoding' }
    $value = ($value -shl 5) -bor $number
    $bits += 5
    if ($bits -ge 8) {
      $bits -= 8
      $bytes.Add([byte](($value -shr $bits) -band 255))
    }
  }
  $counter = [BitConverter]::GetBytes([UInt64][Math]::Floor(([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + $offset) / 30))
  [Array]::Reverse($counter)
  $key = $bytes.ToArray()
  $hmac = [Security.Cryptography.HMACSHA1]::new($key)
  try {
    $mac = $hmac.ComputeHash($counter)
    $index = $mac[-1] -band 15
    $code = (([int] $mac[$index] -band 127) -shl 24) -bor (([int] $mac[$index + 1]) -shl 16) -bor (([int] $mac[$index + 2]) -shl 8) -bor ([int] $mac[$index + 3])
    return '{0:D6}' -f ($code % 1000000)
  } finally {
    $hmac.Dispose()
    [Array]::Clear($key, 0, $key.Length)
    $bytes.Clear()
  }
}

function Login-TestVault($password, $totpSecret) {
  Type-Value 'Мастер-пароль' $password
  Click 'Разблокировать'
  if ($totpSecret) {
    Type-Value 'Код TOTP' (Test-TOTP $totpSecret)
    Click 'Подтвердить код'
  }
  See $oldTitle
  Absent $laterTitle ''
  Absent 'Код TOTP' 'Edit'
}
try {
  Wait-Window $env:PS_V3_RELEASE_EXE $env:PS_V3_RELEASE_PROFILE
  Login-TestVault 'synthetic-migration-master-password' 'JBSWY3DPEHPK3PXP'
  See 'Synthetic bank'
  Close-App
  Note 'The published v2.5.0 EXE opened the isolated rollback with TOTP and displayed the post-activation edit.'
} finally {
  if ($null -ne $script:process -and !$script:process.HasExited) {
    $script:process.Kill()
    $script:process.WaitForExit(10000)
  }
}
