$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, System.Windows.Forms

$verifiedExe = $env:PASSWORDSAVER_TEST_EXE
$primaryName = 'vault_data.v2.enc'
$backupName = "$primaryName.bak"
$selectorName = 'vault_format.state'
$oldTitle = 'Synthetic archived record'
$laterTitle = 'Synthetic later record'
$script:stage = 'initializing'
$script:process = $null
$script:window = $null

function Note($text) {
  Write-Output "::notice title=Native recovery key scenario::$text"
  if ($env:GITHUB_STEP_SUMMARY) { $text >> $env:GITHUB_STEP_SUMMARY }
}

function Find-Control($name, $type, [switch]$partial) {
  $elementType = [Windows.Automation.AutomationElement]
  $condition = if ($type) {
    $controlType = switch ($type) {
      'Button' { [Windows.Automation.ControlType]::Button }
      'Edit' { [Windows.Automation.ControlType]::Edit }
      'CheckBox' { [Windows.Automation.ControlType]::CheckBox }
      'ComboBox' { [Windows.Automation.ControlType]::ComboBox }
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
  $end = [DateTime]::UtcNow.AddSeconds(55)
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

function Digest($path) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash }
function Snapshot($root) {
  $state = [ordered]@{}
  foreach ($item in Get-ChildItem -LiteralPath $root -File -Force | Sort-Object Name) {
    $state[$item.Name] = Digest $item.FullName
  }
  return $state
}
function Equal-Disk($expected, $actual) {
  if (($expected | ConvertTo-Json -Compress) -cne ($actual | ConvertTo-Json -Compress)) {
    throw 'Synthetic vault files changed unexpectedly'
  }
}
function Add-Record($title) {
  Click 'Мои пароли'
  Click 'Добавить'
  Type-Value 'Название' $title
  Type-Value 'Логин' 'synthetic@example.invalid'
  Type-Value 'Пароль' ([Guid]::NewGuid().ToString('N')) -partial
  Click 'Сохранить запись'
  See $title
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

function Enable-TOTP {
  Click 'Безопасность'
  Click 'Настроить TOTP'
  See 'Секрет TOTP'
  $alphabet = '^[A-Z2-7]{16,64}={0,6}$'
  $base32 = $null
  foreach ($item in $script:window.FindAll([Windows.Automation.TreeScope]::Descendants, [Windows.Automation.Condition]::TrueCondition)) {
    if ($item.Current.Name -cmatch $alphabet) { $base32 = $item.Current.Name; break }
  }
  if (!$base32) { throw 'Synthetic authenticator value was absent in the setup dialog' }
  $script:stage = 'TOTP on / initialize the authenticator in GUI'
  Type-Value 'Код подтверждения' (Test-TOTP $base32) -keyboard
  Click 'Включить TOTP'
  See 'Двухфакторная аутентификация успешно включена!'
  $script:stage = 'TOTP on / dismiss the enabled confirmation'
  Click 'Понятно'
  $null = Control 'Хранилища' 'Button'
  return $base32
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

function New-ApplicationProfile($exe, $root, $password) {
  New-Item -ItemType Directory -Path (Join-Path $root 'Local'), (Join-Path $root 'Roaming') -Force | Out-Null
  Wait-Window $exe $root
  $empty = Control 'Создать отдельное пустое хранилище; перенос сейчас не требуется' 'CheckBox' -partial
  $empty.GetCurrentPattern([Windows.Automation.TogglePattern]::Pattern).Toggle()
  Type-Value 'Новый мастер-пароль' $password
  Type-Value 'Повторите мастер-пароль' $password
  Click 'Создать хранилище v2'
  $null = Control 'Добавить' 'Button'
}

function Open-KeyManagement {
  Click 'Настройки'
  Click 'Ключ восстановления'
}

function Key-ManagementAuth($password, $secret) {
  Type-Value 'Текущий мастер-пароль' $password
  if ($secret) { Type-Value 'Код TOTP' (Test-TOTP $secret) }
}

function New-GUIRecoveryKey($password, $secret) {
  Open-KeyManagement
  Absent 'Новый ключ восстановления' 'Edit'
  Key-ManagementAuth $password $secret
  Click 'Создать ключ'
  $printed = Control 'Новый ключ восстановления' 'Edit'
  $secretValue = $printed.GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern).Current.Value
  if ($secretValue -cnotmatch '^PSRK1-[A-Za-z0-9_-]{43}$') { throw 'Expected a new printable recovery key' }
  See 'Сохраните ключ вне этого компьютера.'
  Click 'Готово'
  Absent 'Новый ключ восстановления' 'Edit'
  return $secretValue
}

function Select-KeyAction([int]$index) {
  $field = Control 'Действие' 'ComboBox'
  $null = (New-Object -ComObject WScript.Shell).AppActivate($script:process.Id)
  $field.SetFocus()
  [Windows.Forms.SendKeys]::SendWait('{HOME}' + ('{DOWN}' * $index))
}

function Open-KeyReset {
  Click 'Забыли мастер-пароль? Восстановить по ключу'
  See 'восстановить доступ невозможно'
}

function Prepare-KeyReset($key, $password, $code) {
  Type-Value 'Сохранённый ключ восстановления' $key -keyboard
  Type-Value 'Новый мастер-пароль' $password
  Type-Value 'Повторите новый мастер-пароль' $password
  if ($code) { Type-Value 'Код TOTP выбранной версии, если он включён' $code }
  Click 'Проверить и подготовить'
}

function Check-BackupBox {
  $field = Control 'Использовать .bak, если основной файл отсутствует или повреждён' 'CheckBox' -partial
  $field.GetCurrentPattern([Windows.Automation.TogglePattern]::Pattern).Toggle()
}

function Check-ArchivedDigest($disk, $name, $expected) {
  foreach ($file in $disk.Keys) {
    if ($file.StartsWith("$name.pre-restore-") -and $disk[$file] -ceq $expected) { return }
  }
  throw 'A previous digest is absent from the encrypted archives'
}

function Test-KeyProfile($withTOTP) {
  $mode = if ($withTOTP) { 'TOTP on / primary' } else { 'TOTP off / explicit backup' }
  $base = Join-Path $env:RUNNER_TEMP ([Guid]::NewGuid().ToString('N'))
  $exe = Join-Path $base 'password-saver.exe'
  $vaultDir = Join-Path $base 'Local/PasswordSaver/vaults/default'
  $password = [Guid]::NewGuid().ToString('N')
  $newPassword = [Guid]::NewGuid().ToString('N')
  $authenticator = $null
  $script:stage = "$mode / create disposable profile"
  try {
    New-Item -ItemType Directory -Path $base -Force | Out-Null
    Copy-Item -LiteralPath $verifiedExe -Destination $exe
    if ((Digest $exe) -cne (Digest $verifiedExe)) { throw 'Isolated EXE SHA-256 differs' }
    New-ApplicationProfile $exe $base $password
    Add-Record $oldTitle
    if ($withTOTP) { $authenticator = Enable-TOTP }

    $script:stage = "$mode / enroll and verify a key"
    $first = New-GUIRecoveryKey $password $authenticator
    $before = Snapshot $vaultDir
    Open-KeyManagement
    Select-KeyAction 1
    Type-Value 'Сохранённый ключ восстановления' $first -keyboard
    Key-ManagementAuth $password $authenticator
    Click 'Проверить ключ'
    See 'Ключ подходит к текущему хранилищу.'
    Equal-Disk $before (Snapshot $vaultDir)
    Click 'Отмена'
    $script:stage = "$mode / rotate key"
    $second = New-GUIRecoveryKey $password $authenticator
    if ($second -ceq $first) { throw 'Rotation returned the same key' }
    $rotated = Snapshot $vaultDir
    Check-ArchivedDigest $rotated $primaryName $before[$primaryName]
    Check-ArchivedDigest $rotated $backupName $before[$backupName]
    Click 'Заблокировать'
    Open-KeyReset

    $script:stage = "$mode / reject revoked key"
    Prepare-KeyReset $first $newPassword ''
    See 'Не удалось проверить ключ и контейнер.'
    Absent 'Подтвердить смену пароля' 'Button'
    Equal-Disk $rotated (Snapshot $vaultDir)
    if ($authenticator) {
      $script:stage = "$mode / reject wrong TOTP"
      $live = @(-60, -30, 0, 30, 60 | ForEach-Object { Test-TOTP $authenticator $_ })
      $wrong = '100000', '200000', '300000', '400000', '500000', '600000' | Where-Object { $_ -notin $live } | Select-Object -First 1
      Prepare-KeyReset $second $newPassword $wrong
      See 'Неверный код двухфакторной аутентификации.'
      Absent 'Подтвердить смену пароля' 'Button'
      Equal-Disk $rotated (Snapshot $vaultDir)
    } else {
      $script:stage = "$mode / corrupt only disposable primary and choose .bak"
      Set-Content -LiteralPath (Join-Path $vaultDir $primaryName) -Value 'synthetic damaged container' -Encoding ascii
      Check-BackupBox
      $rotated = Snapshot $vaultDir
    }
    $script:stage = "$mode / cancel after valid preparation"
    $code = if ($authenticator) { Test-TOTP $authenticator } else { '' }
    Prepare-KeyReset $second $newPassword $code
    $null = Control 'Подтвердить смену пароля' 'Button'
    Absent 'Сохранённый ключ восстановления' 'Edit'
    Absent 'Новый мастер-пароль' 'Edit'
    Equal-Disk $rotated (Snapshot $vaultDir)
    Click 'Отмена'
    Equal-Disk $rotated (Snapshot $vaultDir)

    $script:stage = "$mode / confirm and verify encrypted diagnostics"
    Open-KeyReset
    if (!$withTOTP) { Check-BackupBox }
    $code = if ($authenticator) { Test-TOTP $authenticator } else { '' }
    Prepare-KeyReset $second $newPassword $code
    Click 'Подтвердить смену пароля'
    See 'Мастер-пароль изменён. Войдите с новым паролем.'
    $changed = Snapshot $vaultDir
    Check-ArchivedDigest $changed $primaryName $rotated[$primaryName]
    Check-ArchivedDigest $changed $backupName $rotated[$backupName]
    if ($changed[$primaryName] -cne $changed[$backupName] -or $changed[$selectorName] -cne $rotated[$selectorName]) {
      throw 'New working revisions or selector do not match expected digests'
    }
    Note "${mode}: observed a one-time key display, verification, rotation, rejection, cancel and explicit reset in the actual window. Verified old encrypted file digests in archives."

    $script:stage = "$mode / restart and refuse old password"
    Close-App
    Wait-Window $exe $base
    Type-Value 'Мастер-пароль' $password
    Click 'Разблокировать'
    See 'Мастер-пароль неверен'
    Login-TestVault $newPassword $authenticator

    $script:stage = "$mode / disable and refuse the newly enrolled key"
    $third = New-GUIRecoveryKey $newPassword $authenticator
    Open-KeyManagement
    Select-KeyAction 2
    Key-ManagementAuth $newPassword $authenticator
    Click 'Отключить ключ'
    See 'Восстановление по ключу отключено.'
    Click 'Отмена'
    Click 'Заблокировать'
    Open-KeyReset
    $code = if ($authenticator) { Test-TOTP $authenticator } else { '' }
    Prepare-KeyReset $third $password $code
    See 'ключ восстановления не настроен.'
    Click 'Отмена'
    Login-TestVault $newPassword $authenticator
    Close-App
    Note "${mode}: after restart the old password failed and the new password opened the original record. Disabling a freshly enrolled key denied its subsequent use."
  } finally {
    if ($null -ne $script:process) {
      if (!$script:process.HasExited) { $script:process.Kill(); $script:process.WaitForExit() }
      $script:process.Dispose()
      $script:process = $null
    }
    Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction SilentlyContinue
  }
}

try {
  if ((Get-Process -Id $PID).SessionId -eq 0 -or ![Environment]::UserInteractive) {
    throw 'No interactive Windows desktop is available'
  }
  Test-KeyProfile ($env:PASSWORDSAVER_TEST_TOTP -eq 'enabled')
  Note 'Native PasswordSaver recovery key scenario passed.'
} catch {
  $line = $_.InvocationInfo.ScriptLineNumber
  $kind = $_.FullyQualifiedErrorId.Split(',')[0]
  Write-Output "::error title=Native recovery key scenario failed::$script:stage. Type=$($_.Exception.GetType().Name), ID=$kind, script line=$line"
  if ($_.Exception.Message -match '^(Missing|Unexpected GUI|Expected a new printable|EXE had no native|Native|A previous digest|Synthetic vault files)') {
    Write-Output "::notice title=Native driver detail::$($_.Exception.Message)"
  }
  exit 1
}
