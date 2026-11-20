$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, System.Windows.Forms

$verifiedExe = $env:PASSWORDSAVER_TEST_EXE
$primaryName = 'vault_data.v2.enc'
$backupName = "$primaryName.bak"
$selectorName = 'vault_format.state'
$saveTitle = 'Экспорт зашифрованной копии PasswordSaver'
$openTitle = 'Выберите зашифрованную копию PasswordSaver v2'
$restoreTitle = 'Восстановить из внешней копии v2'
$oldTitle = 'Synthetic archived record'
$laterTitle = 'Synthetic later record'
$script:stage = 'initializing'
$script:process = $null
$script:window = $null

function Note($text) {
  Write-Output "::notice title=Native backup scenario::$text"
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

function Native-Pick($title, $action, $path, $submitName) {
  $params = @{ AppProcessId = $script:process.Id; Title = $title; Action = $action; ButtonName = $submitName }
  if ($path) { $params.FilePath = $path }
  try { $result = & "$PSScriptRoot/native-file-dialog.ps1" @params }
  catch {
    $script:process.Refresh()
    if ($script:process.HasExited) {
      $stderr = $script:appStderr.GetAwaiter().GetResult()
      $signal = if ($stderr -match 'panic:|fatal error:|Exception 0x') { 'Go runtime failure marker present' } else { 'no Go runtime failure marker' }
      Note ("Native EXE exited unexpectedly during file dialog. Exit code=" + $script:process.ExitCode + ". " + $signal + ".")
      $safeFrames = @([regex]::Matches($stderr, '(?m)^(github\.com/wailsapp/[-.a-zA-Z0-9/]+\.[-a-zA-Z0-9]+|main\.\(\*App\)\.[a-zA-Z0-9]+)') |
        Select-Object -First 8 | ForEach-Object { $_.Value })
      if ($safeFrames) { Note ('Runtime frames (function names only): ' + ($safeFrames -join ', ')) }
    } else {
      Note ("Native EXE still runs after the driver lost its window. Main HWND=" + $script:process.MainWindowHandle + ".")
    }
    $safeMessages = @('Хранилище заблокировано', 'Операция не выполнена',
      'выберите файл вне папки', 'Сохранение копии', 'Экспортировать зашифрованную копию')
    $observed = @($safeMessages | Where-Object { $null -ne (Find-Control $_ '' -partial) })
    Note ('Visible WebView2 state during file-dialog failure: ' + ($observed -join ', '))
    throw
  }
  if (-not ($result -match 'Native file dialog')) { throw 'No native file dialog was observed' }
  if ($action -eq 'cancel') { Note 'Observed the native dialog close after cancellation.' }
  if ($result -match 'Native overwrite prompt acknowledged') { Note 'Acknowledged the native Windows overwrite prompt.' }
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

function Login-TestVault($password, $totpSecret, [switch]$AllowLater) {
  Type-Value 'Мастер-пароль' $password
  Click 'Разблокировать'
  if ($totpSecret) {
    Type-Value 'Код TOTP' (Test-TOTP $totpSecret)
    Click 'Подтвердить код'
  }
  See $oldTitle
  if (!$AllowLater) { Absent $laterTitle '' }
  Absent 'Код TOTP' 'Edit'
}

function Login-Consent($password) {
  Type-Value 'Мастер-пароль' $password
  Click 'Разблокировать'
  $null = Control 'Добавить' 'Button'
}

function Test-V1Migration($exe, $base, $vaultDir) {
  $fixture = Join-Path $env:GITHUB_WORKSPACE 'testdata/vault_data_v1_legacy.enc'
  $password = 'legacy-fixture-key'
  $names = @('vault_data.enc', 'vault_data.enc.bak')
  $digest = Digest $fixture
  foreach ($name in $names) { Copy-Item -LiteralPath $fixture -Destination (Join-Path $base $name) }

  $script:stage = 'v1 fixture / discover CWD and migrate to AppData'
  Wait-Window $exe $base
  See 'Найдено старое зашифрованное хранилище'
  Click 'Проверить и перенести зашифрованное хранилище'
  Type-Value 'Мастер-пароль' $password
  Click 'Проверить хранилище'
  See 'Аутентификация пройдена.'
  foreach ($name in $names) {
    if (Test-Path -LiteralPath (Join-Path $vaultDir $name)) { throw 'Fixture was copied before explicit confirmation' }
  }
  Click 'Подтвердить копирование'
  $null = Control 'Разблокировать' 'Button'
  foreach ($name in $names) {
    if ((Digest (Join-Path $vaultDir $name)) -cne $digest -or (Digest (Join-Path $base $name)) -cne $digest) {
      throw 'Source or transferred v1 bytes differ from the fixture'
    }
  }
  Login-Consent $password
  See-CombinedText '1\s*записей в хранилище'
  Note 'Observed v1 login after confirmed AppData copy. Both v1 source and transferred file digests match.'

  $script:stage = 'v1 fixture / explicitly activate v2 and restart'
  Click 'Хранилища'
  Click 'Подготовить переход на v2'
  Type-Value 'Повторно введите мастер-пароль' $password
  Click 'Создать и проверить контейнер'
  See 'Контейнер v2 проверен'
  Type-Value 'Мастер-пароль для подтверждения' $password
  Click 'Явно активировать v2'
  $null = Control 'Разблокировать' 'Button'
  Close-App
  Wait-Window $exe $base
  Login-Consent $password
  See-CombinedText '1\s*записей в хранилище'
  if (!(Test-Path -LiteralPath (Join-Path $vaultDir $primaryName))) { throw 'v2 target is absent' }
  foreach ($name in $names) {
    if ((Digest (Join-Path $vaultDir $name)) -cne $digest -or (Digest (Join-Path $base $name)) -cne $digest) {
      throw 'Activation modified the legacy source or its AppData copy'
    }
  }
  Close-App
  Note 'Observed separate v2 activation and login after restart with the migrated entry. Both legacy files were retained.'
}

function Test-V2Password($exe, $base, $vaultDir) {
  $fixture = Join-Path $env:GITHUB_WORKSPACE 'crypto/v2/testdata/v2-original.enc'
  $password = 'v2-test-only-master-password'
  $new = [Guid]::NewGuid().ToString('N')
  New-Item -ItemType Directory -Path $vaultDir -Force | Out-Null
  foreach ($name in @($primaryName, $backupName)) { Copy-Item -LiteralPath $fixture -Destination (Join-Path $vaultDir $name) }
  $selector = [ordered]@{
    format = 'passwordsaver-vault-selector'; version = 1; mode = 'v2-active'
    activatedV2Sha256 = (Digest $fixture).ToLowerInvariant(); nativeV2 = $true
  } | ConvertTo-Json -Compress
  [IO.File]::WriteAllText((Join-Path $vaultDir $selectorName), $selector)

  $script:stage = 'original v2 / authenticate old format, add records and TOTP'
  Wait-Window $exe $base
  Login-Consent $password
  Add-Record $oldTitle
  Add-Record $laterTitle
  $secret = Enable-TOTP
  Click 'Заблокировать'
  Login-TestVault $password $secret -AllowLater
  Note 'Observed login of the original v2 fixture, record creation, manual lock and TOTP login.'

  $script:stage = 'original v2 / change known password and compare encrypted files'
  Click 'Настройки'
  Click 'Изменить мастер-пароль'
  Type-Value 'Текущий мастер-пароль' $password
  Type-Value 'Новый мастер-пароль' $new
  Type-Value 'Повтор нового мастер-пароля' $new
  Type-Value 'Код TOTP' (Test-TOTP $secret)
  $before = Snapshot $vaultDir
  Click 'Сменить пароль'
  See 'Мастер-пароль изменён. Войдите с новым паролем'
  $after = Snapshot $vaultDir
  if ($after[$primaryName] -ceq $before[$primaryName] -or $after[$primaryName] -cne $after[$backupName] -or
      $before[$selectorName] -cne $after[$selectorName]) { throw 'Password change file digests differ from expectation' }
  Close-App
  Wait-Window $exe $base
  Type-Value 'Мастер-пароль' $password
  Click 'Разблокировать'
  See 'Мастер-пароль неверен'
  Login-TestVault $new $secret -AllowLater
  See $laterTitle
  Close-App
  Note 'Observed the actual password change, old-password refusal and successful new-password login with TOTP after EXE restart.'
}

$base = Join-Path $env:RUNNER_TEMP ([Guid]::NewGuid().ToString('N'))
try {
  if ((Get-Process -Id $PID).SessionId -eq 0 -or ![Environment]::UserInteractive) { throw 'No interactive Windows desktop is available' }
  $script:stage = 'isolated profile setup'
  New-Item -ItemType Directory -Path (Join-Path $base 'Local'), (Join-Path $base 'Roaming') -Force | Out-Null
  $exe = Join-Path $base 'password-saver.exe'
  Copy-Item -LiteralPath $verifiedExe -Destination $exe
  if ((Digest $exe) -cne (Digest $verifiedExe)) { throw 'Isolated EXE digest mismatch' }
  $vaultDir = Join-Path $base 'Local/PasswordSaver/vaults/default'
  if ($env:PASSWORDSAVER_TEST_SCENARIO -eq 'legacy-v1') { Test-V1Migration $exe $base $vaultDir }
  else { Test-V2Password $exe $base $vaultDir }
  Note 'Native compatibility scenario passed.'
} catch {
  $line = $_.InvocationInfo.ScriptLineNumber
  $kind = $_.FullyQualifiedErrorId.Split(',')[0]
  Write-Output "::error title=Native compatibility GUI verification failed::$script:stage. Type=$($_.Exception.GetType().Name), ID=$kind, script line=$line"
  if ($_.Exception.Message -match '^(Missing|Unexpected GUI|EXE had no native|Source or transferred|Activation modified|Password change file digests)') {
    Write-Output "::notice title=Native GUI driver detail::$($_.Exception.Message)"
  }
  exit 1
} finally {
  if ($null -ne $script:process) {
    if (!$script:process.HasExited) { $script:process.Kill(); $script:process.WaitForExit() }
    $script:process.Dispose()
  }
  Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction SilentlyContinue
}
