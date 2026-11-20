param(
  [Parameter(Mandatory)][int]$AppProcessId,
  [Parameter(Mandatory)][string]$Title,
  [Parameter(Mandatory)][ValidateSet('select', 'cancel', 'overwrite')][string]$Action,
  [string]$FilePath,
  [ValidateSet('Open', 'Save')][string]$ButtonName = 'Open'
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes

function Find-Window($predicate, $seconds) {
  $root = [Windows.Automation.AutomationElement]::RootElement
  $pidCondition = [Windows.Automation.PropertyCondition]::new(
    [Windows.Automation.AutomationElement]::ProcessIdProperty, $AppProcessId)
  $end = [DateTime]::UtcNow.AddSeconds($seconds)
  do {
    $windows = $root.FindAll([Windows.Automation.TreeScope]::Children, $pidCondition)
    foreach ($window in $windows) {
      try {
        if ($window.Current.NativeWindowHandle -and (& $predicate $window)) { return $window }
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

$window = Find-Window { param($w) $w.Current.Name -eq $Title } 12
if ($null -eq $window) { throw 'Native file dialog not found through Windows UI Automation' }

if ($Action -eq 'cancel') {
  Invoke-Button (Find-Button $window '2' 'Cancel')
  Write-Output 'Native file dialog and Cancel invoked via UI Automation'
  return
}

$nameControl = Find-Control $window ([Windows.Automation.AutomationElement]::AutomationIdProperty) '1148'
$edit = $null
if ($null -ne $nameControl -and $nameControl.Current.ControlType -eq [Windows.Automation.ControlType]::Edit) {
  $edit = $nameControl
} elseif ($null -ne $nameControl) {
  $edit = Find-Control $nameControl ([Windows.Automation.AutomationElement]::ControlTypeProperty) ([Windows.Automation.ControlType]::Edit)
}
if ($null -eq $edit) {
  $edit = Find-Control $window ([Windows.Automation.AutomationElement]::AutomationIdProperty) '1001'
}
if ($null -eq $edit) { throw 'Native file-name field was not found' }
$value = $edit.GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern)
$value.SetValue($FilePath)
if ($value.Current.Value -cne $FilePath) { throw 'File-name field did not retain the chosen path' }
Invoke-Button (Find-Button $window '1' $buttonName)

if ($Action -eq 'overwrite') {
  $confirm = Find-Window {
    param($w) $null -ne (Find-Button $w '6' 'Yes')
  } 5
  if ($null -ne $confirm) {
    Invoke-Button (Find-Button $confirm '6' 'Yes')
    Write-Output 'Native overwrite prompt acknowledged via UI Automation'
  }
}
Write-Output 'Native file dialog and path confirmed via UI Automation'
