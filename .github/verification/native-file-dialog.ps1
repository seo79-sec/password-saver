param(
  [Parameter(Mandatory)][int]$AppProcessId,
  [Parameter(Mandatory)][string]$Title,
  [Parameter(Mandatory)][ValidateSet('select', 'cancel', 'overwrite')][string]$Action,
  [string]$FilePath,
  [ValidateSet('Open', 'Save')][string]$ButtonName = 'Open'
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, System.Windows.Forms

# Native shell dialogs can be owned HWNDs without appearing as immediate
# children in the desktop's UI Automation tree. Enumerate the app windows
# first, then use UI Automation to read and invoke the actual controls.
if (-not ('PWSTestWindows' -as [type])) {
  Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public static class PWSTestWindows {
    private delegate bool Enumerator(IntPtr h, IntPtr arg);
    [DllImport("user32.dll")] private static extern bool EnumWindows(Enumerator callback, IntPtr arg);
    [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll")] private static extern IntPtr GetWindow(IntPtr h, uint code);
    [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr h, int id);
    [DllImport("user32.dll")] private static extern bool PostMessage(IntPtr h, uint message, IntPtr w, IntPtr l);
    public static bool Close(IntPtr h) { return PostMessage(h, 0x0010, IntPtr.Zero, IntPtr.Zero); }
    public static bool Click(IntPtr h) { return PostMessage(h, 0x00F5, IntPtr.Zero, IntPtr.Zero); }
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] private static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] private static extern int GetClassName(IntPtr h, StringBuilder s, int n);
    public static IntPtr[] ForPid(uint wanted) {
        var list = new List<IntPtr>();
        EnumWindows((h, _) => {
            if (!IsWindowVisible(h)) return true;
            uint pid;
            GetWindowThreadProcessId(h, out pid);
            if (pid != wanted) {
                var owner = GetWindow(h, 4);
                if (owner == IntPtr.Zero) return true;
                GetWindowThreadProcessId(owner, out pid);
            }
            if (pid == wanted) list.Add(h);
            return true;
        }, IntPtr.Zero);
        return list.ToArray();
    }
    public static string Title(IntPtr h) {
        var s = new StringBuilder(512);
        GetWindowText(h, s, s.Capacity);
        return s.ToString();
    }
    public static string Class(IntPtr h) {
        var s = new StringBuilder(64);
        GetClassName(h, s, s.Capacity);
        return s.ToString();
    }
}
'@
}

function Find-Window($predicate, $seconds) {
  $end = [DateTime]::UtcNow.AddSeconds($seconds)
  do {
    foreach ($hwnd in [PWSTestWindows]::ForPid($AppProcessId)) {
      try {
        $window = [Windows.Automation.AutomationElement]::FromHandle($hwnd)
        if ($null -ne $window -and (& $predicate $window $hwnd)) { return $window }
      } catch [Windows.Automation.ElementNotAvailableException] { }
    }
    Start-Sleep -Milliseconds 150
  } while ([DateTime]::UtcNow -lt $end)
  return $null
}

function Find-Control($parent, $property, [object]$value) {
  $condition = [Windows.Automation.PropertyCondition]::new($property, $value)
  return $parent.FindFirst([Windows.Automation.TreeScope]::Descendants, $condition)
}

function Find-Button($parent, $id, $name) {
  $condition = [Windows.Automation.AndCondition]::new(
    [Windows.Automation.PropertyCondition]::new(
      [Windows.Automation.AutomationElement]::ControlTypeProperty, [Windows.Automation.ControlType]::Button),
    [Windows.Automation.OrCondition]::new(
      [Windows.Automation.PropertyCondition]::new([Windows.Automation.AutomationElement]::AutomationIdProperty, $id),
      [Windows.Automation.PropertyCondition]::new([Windows.Automation.AutomationElement]::NameProperty, $name)))
  return $parent.FindFirst([Windows.Automation.TreeScope]::Descendants, $condition)
}

function Invoke-Button($element) {
  if ($null -eq $element) { throw 'Expected native dialog button was not found' }
  # InvokePattern is asynchronous by contract, so an overwrite prompt can open.
  $element.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke()
}

function Wait-Value($find, [int]$seconds = 8) {
  $until = [DateTime]::UtcNow.AddSeconds($seconds)
  do {
    try {
      $item = & $find
      if ($null -ne $item) { return $item }
    } catch [Windows.Automation.ElementNotAvailableException] { }
    Start-Sleep -Milliseconds 200
  } while ([DateTime]::UtcNow -lt $until)
  return $null
}

$window = Find-Window {
  param($w, $handle)
  $w.Current.Name -eq $Title -or [PWSTestWindows]::Title($handle) -eq $Title
} 10
if ($null -eq $window) {
  $windows = @([PWSTestWindows]::ForPid($AppProcessId) | ForEach-Object {
    [PWSTestWindows]::Class($_) + ':' + [PWSTestWindows]::Title($_)
  }) -join ', '
  throw "Native file dialog not found. Visible owned windows: $windows"
}

$dialogHandle = [IntPtr] $window.Current.NativeWindowHandle
if ($dialogHandle -eq [IntPtr]::Zero) {
  $dialogHandle = [PWSTestWindows]::ForPid($AppProcessId) | Where-Object { [PWSTestWindows]::Title($_) -eq $Title } | Select-Object -First 1
}
if (-not $dialogHandle) { throw 'Native file dialog handle missing' }

if ($Action -eq 'cancel') {
  $cancel = Wait-Value { Find-Button $window '2' 'Cancel' } 4
  if ($null -ne $cancel) {
    Invoke-Button $cancel
  } else {
    $nativeCancel = [PWSTestWindows]::GetDlgItem($dialogHandle, 2)
    if ($nativeCancel -ne 0) {
      if (![PWSTestWindows]::Click($nativeCancel)) { throw 'Native Cancel button rejected the click' }
    } elseif (![PWSTestWindows]::Close($dialogHandle)) { throw 'Native file dialog rejected close' }
  }
  $same = Find-Window { param($w, $h) $h -eq $dialogHandle } 1
  $until = [DateTime]::UtcNow.AddSeconds(6)
  while ($null -ne $same -and [DateTime]::UtcNow -lt $until) {
    $same = Find-Window { param($w, $h) $h -eq $dialogHandle } 1
  }
  if ($same) { throw 'Native file dialog stayed open after cancel' }
  Write-Output 'Native file dialog cancellation observed'
  return
}

# The common item dialog's File name edit can be represented by different
# accessibility providers. Prefer the real control's ValuePattern when
# available. Otherwise use the Windows File name shortcut in this HWND.
$setPath = $false
try {
  $nameControl = Find-Control $window ([Windows.Automation.AutomationElement]::AutomationIdProperty) '1148'
  $edit = $null
  if ($null -ne $nameControl -and $nameControl.Current.ControlType -eq [Windows.Automation.ControlType]::Edit) {
    $edit = $nameControl
  } elseif ($null -ne $nameControl) {
    $edit = Find-Control $nameControl ([Windows.Automation.AutomationElement]::ControlTypeProperty) ([Windows.Automation.ControlType]::Edit)
  }
  if ($null -ne $edit) {
    $value = $edit.GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern)
    $value.SetValue($FilePath)
    $setPath = $value.Current.Value -ceq $FilePath
  }
} catch [InvalidOperationException] { }

if (!$setPath) {
  $null = [PWSTestWindows]::SetForegroundWindow($dialogHandle)
  Start-Sleep -Milliseconds 200
  if ([PWSTestWindows]::GetForegroundWindow() -ne $dialogHandle) {
    throw 'Native file dialog is not the foreground window'
  }
  [Windows.Forms.SendKeys]::SendWait('%n')
  [Windows.Forms.SendKeys]::SendWait('^a')
  # This is a disposable synthetic path. Credentials never use this clipboard.
  [Windows.Forms.Clipboard]::SetText($FilePath)
  try {
    [Windows.Forms.SendKeys]::SendWait('^v')
    Start-Sleep -Milliseconds 200
    [Windows.Forms.SendKeys]::SendWait('{ENTER}')
  } finally {
    [Windows.Forms.Clipboard]::Clear()
  }
} else {
  $submit = Wait-Value { Find-Button $window '1' $buttonName }
  if ($null -ne $submit) { Invoke-Button $submit }
  else {
    $nativeSubmit = [PWSTestWindows]::GetDlgItem($dialogHandle, 1)
    if ($nativeSubmit -eq 0 -or ![PWSTestWindows]::Click($nativeSubmit)) {
      throw 'Expected native dialog submit button was not found'
    }
  }
}

if ($Action -eq 'overwrite') {
  $confirm = Find-Window {
    param($w, $handle)
    return ($null -ne (Find-Button $w '6' 'Yes')) -or
      ([PWSTestWindows]::GetDlgItem($handle, 6) -ne [IntPtr]::Zero) -or
      ([PWSTestWindows]::Title($handle) -match '^Confirm Save')
  } 7
  if ($null -ne $confirm) {
    $yes = Find-Button $confirm '6' 'Yes'
    if ($null -ne $yes) {
      Invoke-Button $yes
    } else {
      $confirmationHandle = [IntPtr] $confirm.Current.NativeWindowHandle
      $nativeYes = [PWSTestWindows]::GetDlgItem($confirmationHandle, 6)
      if ($nativeYes -ne [IntPtr]::Zero) {
        if (![PWSTestWindows]::Click($nativeYes)) { throw 'Native overwrite confirmation rejected Yes' }
      } else {
        $null = [PWSTestWindows]::SetForegroundWindow($confirmationHandle)
        if ([PWSTestWindows]::GetForegroundWindow() -ne $confirmationHandle) {
          throw 'Native overwrite confirmation is not the foreground window'
        }
        [Windows.Forms.SendKeys]::SendWait('%y')
      }
    }
    Write-Output 'Native overwrite prompt acknowledged'
  } else {
    $stillOpen = Find-Window { param($w, $h) $h -eq $dialogHandle } 1
    if ($stillOpen) {
      $windows = @([PWSTestWindows]::ForPid($AppProcessId) | ForEach-Object {
        [PWSTestWindows]::Class($_) + ':' + [PWSTestWindows]::Title($_)
      }) -join ', '
      throw "Native file dialog stayed open without an identified overwrite prompt. Visible owned windows: $windows"
    }
  }
}
Write-Output 'Native file dialog and path confirmed via UI Automation'
