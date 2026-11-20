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
  $script:process = [Diagnostics.Process]::Start($psi)
  $end = [DateTime]::UtcNow.AddSeconds(20)
  do {
    $script:process.Refresh()
    if ($script:process.HasExited) { throw 'EXE exited before its native window opened' }
    if ($script:process.MainWindowHandle -ne 0) { break }
    Start-Sleep -Milliseconds 250
  } while ([DateTime]::UtcNow -lt $end)
  if ($script:process.MainWindowHandle -eq 0) { throw 'EXE had no native window handle' }
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
    $code = (($mac[$index] -band 127) -shl 24) -bor ($mac[$index + 1] -shl 16) -bor ($mac[$index + 2] -shl 8) -bor $mac[$index + 3]
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

function Check-RestoreSource($copy, $password, $code) {
  Click 'Выбрать файл'
  Native-Pick $openTitle 'select' $copy 'Open'
  See 'external.v2.enc'
  Type-Value 'Мастер-пароль копии' $password
  if ($code) { Type-Value 'Код TOTP копии, если он был включён' $code }
  Click 'Проверить копию'
}

function Preview($copy, $password, $totpSecret, $before, $vaultDir, $totpText) {
  $code = if ($totpSecret) { Test-TOTP $totpSecret } else { '' }
  Check-RestoreSource $copy $password $code
  See 'Проверенная копия:'
  See-CombinedText 'Записей:\s*1\s*\.'
  See-CombinedText $totpText
  Absent 'Мастер-пароль копии' 'Edit'
  Equal-Disk $before (Snapshot $vaultDir)
}

function Test-BackupProfile($withTOTP) {
  $description = if ($withTOTP) { 'TOTP on' } else { 'TOTP off' }
  $base = Join-Path $env:RUNNER_TEMP ([Guid]::NewGuid().ToString('N'))
  $password = [Guid]::NewGuid().ToString('N')
  $totpSecret = $null
  try {
    New-Item -ItemType Directory -Path (Join-Path $base 'Local'), (Join-Path $base 'Roaming'), (Join-Path $base 'external') -Force | Out-Null
    $exe = Join-Path $base 'password-saver.exe'
    Copy-Item -LiteralPath $verifiedExe -Destination $exe
    if ((Digest $exe) -cne (Digest $verifiedExe)) { throw 'Test EXE copy differs from the verified artifact' }

    $vaultDir = Join-Path $base 'Local/PasswordSaver/vaults/default'
    $script:stage = "$description / start and create"
    Wait-Window $exe $base
    $script:stage = "$description / toggle setup confirmation"
    $empty = Control 'Создать отдельное пустое хранилище; перенос сейчас не требуется' 'CheckBox' -partial
    $empty.GetCurrentPattern([Windows.Automation.TogglePattern]::Pattern).Toggle()
    $script:stage = "$description / enter setup password"
    Type-Value 'Новый мастер-пароль' $password
    Type-Value 'Повторите мастер-пароль' $password
    $script:stage = "$description / verify isolated store and create"
    if (!(Test-Path -LiteralPath $vaultDir -PathType Container)) { throw 'Isolated LOCALAPPDATA was not initialized' }
    Click 'Создать хранилище v2'
    $null = Control 'Добавить' 'Button'
    $script:stage = "$description / create synthetic record"
    Add-Record $oldTitle
    if ($withTOTP) { $totpSecret = Enable-TOTP }
    Click 'Хранилища'

    $copy = Join-Path $base 'external/external.v2.enc'
    $existing = Join-Path $base 'external/do-not-replace.v2.enc'
    $before = Snapshot $vaultDir
    $script:stage = "$description / cancel export"
    Click 'Экспортировать зашифрованную копию'
    Native-Pick $saveTitle 'cancel' '' 'Save'
    if (Get-ChildItem -LiteralPath (Join-Path $base 'external') -Force) { throw 'Cancel created an export' }
    Equal-Disk $before (Snapshot $vaultDir)

    $script:stage = "$description / save external copy"
    Click 'Экспортировать зашифрованную копию'
    Native-Pick $saveTitle 'select' $copy 'Save'
    See 'Зашифрованная копия сохранена и проверена.'
    $copyHash = Digest $copy
    if ($copyHash -cne $before[$primaryName]) { throw 'Export differs from the encrypted primary' }
    Note "${description}: selected a path in native Save As and verified the exported file equals the active encrypted primary."

    $script:stage = "$description / refuse overwrite"
    Set-Content -LiteralPath $existing -Value 'Synthetic sentinel' -Encoding ascii
    $sentinel = Digest $existing
    Click 'Экспортировать зашифрованную копию'
    Native-Pick $saveTitle 'overwrite' $existing 'Save'
    See 'существующая копия не перезаписывается'
    if ((Digest $existing) -cne $sentinel) { throw 'An existing file was overwritten' }
    Equal-Disk $before (Snapshot $vaultDir)
    Note "${description}: observed native Save dialog cancel, successful external export and refusal to overwrite an existing file."

    $script:stage = "$description / add later record and logout"
    Add-Record $laterTitle
    $before = Snapshot $vaultDir
    if ($before[$primaryName] -ceq $copyHash) { throw 'The later record did not create a new revision' }
    Click 'Заблокировать'
    Click 'Восстановить из внешней зашифрованной копии v2'

    $script:stage = "$description / cancel native open"
    Click 'Выбрать файл'
    Native-Pick $openTitle 'cancel' '' 'Open'
    Absent 'Мастер-пароль копии' 'Edit'
    Equal-Disk $before (Snapshot $vaultDir)

    $script:stage = "$description / reject wrong password"
    Check-RestoreSource $copy ([Guid]::NewGuid().ToString('N')) ''
    See 'Мастер-пароль неверен'
    Absent 'Подтвердить восстановление' 'Button'
    Equal-Disk $before (Snapshot $vaultDir)

    if ($withTOTP) {
      $script:stage = "$description / reject wrong TOTP"
      $live = @(-60, -30, 0, 30, 60 | ForEach-Object { Test-TOTP $totpSecret $_ })
      $wrong = '100000', '200000', '300000', '400000', '500000', '600000' | Where-Object { $_ -notin $live } | Select-Object -First 1
      Check-RestoreSource $copy $password $wrong
      See 'Неверный код двухфакторной аутентификации'
      Absent 'Подтвердить восстановление' 'Button'
      Equal-Disk $before (Snapshot $vaultDir)
    }
    Note "${description}: observed native Open cancellation and rejection of invalid credentials. Vault file digests stayed unchanged."

    $script:stage = "$description / preview then cancel"
    $totpText = if ($withTOTP) { 'TOTP:\s*включён' } else { 'TOTP:\s*выключен' }
    Preview $copy $password $totpSecret $before $vaultDir $totpText
    Click 'Не восстанавливать'
    See 'Только у вас.'
    Absent 'Подтвердить восстановление' 'Button'
    Equal-Disk $before (Snapshot $vaultDir)

    $script:stage = "$description / confirm recovery and verify both archives"
    Click 'Восстановить из внешней зашифрованной копии v2'
    Preview $copy $password $totpSecret $before $vaultDir $totpText
    Click 'Подтвердить восстановление'
    See 'Зашифрованная копия восстановлена. Войдите с её мастер-паролем.'
    $restored = Snapshot $vaultDir
    if ($restored[$selectorName] -cne $before[$selectorName] -or (Digest $copy) -cne $copyHash) {
      throw 'Recovery changed the source file or format selector'
    }
    foreach ($name in @($primaryName, $backupName)) {
      if ($restored[$name] -cne $copyHash) { throw 'A primary or backup did not match the authenticated copy' }
      $archives = @($restored.Keys | Where-Object { $_.StartsWith($name + '.pre-restore-') })
      if ($archives.Count -ne 1 -or $restored[$archives[0]] -cne $before[$name]) { throw 'Prior encrypted bytes were not preserved' }
    }
    Note "${description}: observed authenticated preview, cancellation and explicit restore. Both prior encrypted files matched their archived bytes."

    $script:stage = "$description / login and restart"
    Login-TestVault $password $totpSecret
    Close-App
    Wait-Window $exe $base
    Login-TestVault $password $totpSecret
    Close-App
    Note "${description}: GUI showed the restored record after new login and EXE restart. The record created after export was absent."
  } catch {
    if ($script:stage -like 'TOTP on /*' -and $null -ne $script:window) {
      $known = @('Хранилища', 'Настройка TOTP', 'Понятно', 'Успешно', 'Операция не выполнена',
        'Только у вас.', 'Хранилище заблокировано', 'Двухфакторная аутентификация успешно включена')
      $onScreen = @($known | Where-Object {
        try { $null -ne (Find-Control $_ '' -partial) }
        catch { $false }
      })
      Note ('Visible TOTP UI labels: ' + ($onScreen -join ', '))
    }
    throw
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
  Test-BackupProfile $false
  Test-BackupProfile $true
  Note 'Both real Windows EXE and native file dialog scenarios passed in separate disposable LOCALAPPDATA profiles.'
} catch {
  # Errors contain only the current step and type. Never publish an exception
  # from a value/input provider, which might include the synthetic value.
  $line = $_.InvocationInfo.ScriptLineNumber
  $kind = $_.FullyQualifiedErrorId.Split(',')[0]
  Write-Output "::error title=Native backup GUI verification failed::$script:stage. Type=$($_.Exception.GetType().Name), ID=$kind, script line=$line"
  if ($_.Exception.Message -match '^(Missing|Unexpected GUI|The EXE did not|Synthetic vault files|Expected native dialog|Native file|No native|Isolated LOCALAPPDATA)' ) {
    Write-Output "::notice title=Native GUI driver detail::$($_.Exception.Message)"
  }
  exit 1
}
