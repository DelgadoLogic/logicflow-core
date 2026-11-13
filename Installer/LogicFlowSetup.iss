; LogicFlow — Inno Setup Installer Script
; Proprietary by DelgadoLogic.Tech
; Creates professional Windows installer with registry, shortcuts, uninstall, and DLL registration

#define AppName "LogicFlow"
#define AppVersion "1.0.0"
#define AppPublisher "DelgadoLogic.Tech"
#define AppURL "https://delgadologic.tech/logicflow"
#define AppExeName "LogicFlow.exe"
#define AgentExeName "LogicFlowAgent.exe"
#define AppId "{{D3LG4D0-L0G1C-FL0W-2026-DELGADOTECH}}"

; --- Aeon Browser ---
#define AeonName "Aeon Browser"
#define AeonExeName "Aeon.exe"
#define AeonVersion "1.0.0"
#define AeonInstallDir "{autopf}\DelgadoLogic\Aeon"

[Setup]
AppId={#AppId}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}/support
AppUpdatesURL={#AppURL}/updates
DefaultDirName={autopf}\DelgadoLogic\LogicFlow
DefaultGroupName=DelgadoLogic\LogicFlow
AllowNoIcons=yes
LicenseFile=..\Docs\EULA.txt
OutputDir=..\dist
OutputBaseFilename=LogicFlowSetup_v{#AppVersion}
SetupIconFile=..\Assets\Icons\LogicFlow.ico
UninstallDisplayIcon={app}\LogicFlow.exe
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
DisableProgramGroupPage=yes
SetupLogging=yes
; RestorePointInConfig is removed in Inno Setup 6.7+ — system restore points auto-handled by OS
; RestorePointInConfig=yes
VersionInfoVersion={#AppVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoDescription=LogicFlow — AI-Powered Windows Optimization & Data Recovery Suite
VersionInfoCopyright=© 2026 DelgadoLogic.Tech. All rights reserved.
VersionInfoProductName={#AppName}
VersionInfoProductVersion={#AppVersion}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Types]
Name: "full"; Description: "Full installation (Recommended)"
Name: "compact"; Description: "Compact installation (Dashboard only)"
Name: "custom"; Description: "Custom installation"; Flags: iscustom

[Components]
Name: "main";   Description: "LogicFlow Dashboard";                               Types: full compact custom; Flags: fixed
Name: "agent";  Description: "LogicFlow Background Agent (Windows Service)";       Types: full
Name: "cli";    Description: "LogicFlow Enterprise CLI (lf.exe)";                  Types: full custom
Name: "native"; Description: "Native Kernel Drivers && Crypto Engine";           Types: full
Name: "docs";   Description: "Documentation && API Reference";                   Types: full
Name: "aeon";   Description: "Aeon Browser by DelgadoLogic (recommended)";       Types: full; Flags: checkablealone

[Tasks]
Name: "desktopicon";         Description: "{cm:CreateDesktopIcon}";                                                                                  GroupDescription: "{cm:AdditionalIcons}"
Name: "quicklaunchicon";     Description: "Create Quick Launch shortcut";                                                                               GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "startupentry";        Description: "Start LogicFlow with Windows";                                                                               GroupDescription: "Startup:"
Name: "installservice";      Description: "Install LogicFlow Agent as Windows Service";                                                                Components: agent
Name: "firewallrule";        Description: "Add Windows Firewall rules for updates, telemetry, and Agent sync (HTTPS only)";                             GroupDescription: "Network:"; Flags: checkedonce
Name: "aeonfirewallrule";   Description: "Add Windows Firewall rule for Aeon Browser (HTTPS only — updates, Tor bootstrap, telemetry)"; GroupDescription: "Network:"; Components: aeon; Flags: checkedonce
Name: "aeondesktopicon";    Description: "Create Aeon Browser desktop shortcut";                                                                           GroupDescription: "{cm:AdditionalIcons}"; Components: aeon
Name: "defenderexclusion"; Description: "Add Windows Defender exclusion (prevents false positives)"; GroupDescription: "Security:"
Name: "telemetry"; Description: "Send anonymous system data to help improve LogicFlow (no personal info collected)"; GroupDescription: "Privacy:"; Flags: checkedonce

[Files]
; Main Dashboard Application
Source: "..\publish\dashboard\*"; DestDir: "{app}"; Components: main; Flags: ignoreversion recursesubdirs createallsubdirs

; Enterprise CLI
Source: "..\publish\cli\*"; DestDir: "{app}\CLI"; Components: cli; Flags: ignoreversion recursesubdirs createallsubdirs

; Background Agent Service
Source: "..\publish\agent\*"; DestDir: "{app}\Agent"; Components: agent; Flags: ignoreversion recursesubdirs createallsubdirs

; Native Libraries
Source: "..\publish\native\LogicFlow.Native.dll"; DestDir: "{app}"; Components: native; Flags: ignoreversion
Source: "..\publish\native\LogicFlow.Kernel.dll"; DestDir: "{app}\Drivers"; Components: native; Flags: ignoreversion
Source: "..\publish\native\LogicFlow.CryptoEngine.dll"; DestDir: "{app}\Drivers"; Components: native; Flags: ignoreversion

; Documentation
Source: "..\Docs\*"; DestDir: "{app}\Docs"; Components: docs; Flags: ignoreversion recursesubdirs

; Assets
Source: "..\Assets\Icons\*"; DestDir: "{app}\Assets\Icons"; Flags: ignoreversion
Source: "..\branding\*"; DestDir: "{app}\Assets\Branding"; Flags: ignoreversion

; ============================================================
; Aeon Browser — optional component (installed to separate dir)
; Only included in installer if AeonBrowser has been published.
; ============================================================
#ifexist "..\..\AeonBrowser\publish\Aeon.exe"
; Core browser executable
Source: "..\..\AeonBrowser\publish\Aeon.exe";              DestDir: "{#AeonInstallDir}"; Components: aeon; Flags: ignoreversion
; Engine DLLs (tier-selected at install time)
Source: "..\..\AeonBrowser\publish\aeon_blink.dll";        DestDir: "{#AeonInstallDir}"; Components: aeon; Flags: ignoreversion
Source: "..\..\AeonBrowser\publish\aeon_router.dll";       DestDir: "{#AeonInstallDir}"; Components: aeon; Flags: ignoreversion
; WolfSSL TLS DLL (legacy OS support)
Source: "..\..\AeonBrowser\publish\wolfssl.dll";           DestDir: "{#AeonInstallDir}"; Components: aeon; Flags: ignoreversion
; Network components (Tor + i2pd)
Source: "..\..\AeonBrowser\publish\network\*";            DestDir: "{#AeonInstallDir}\Network"; Components: aeon; Flags: ignoreversion recursesubdirs createallsubdirs
; Content block lists
Source: "..\..\AeonBrowser\publish\blocklists\*";         DestDir: "{#AeonInstallDir}\blocklists"; Components: aeon; Flags: ignoreversion recursesubdirs
#endif
; Aeon Icons (always available from LogicFlow assets)
Source: "..\Assets\Icons\Aeon.ico";                        DestDir: "{#AeonInstallDir}\Assets"; Components: aeon; Flags: ignoreversion

[Icons]
Name: "{group}\LogicFlow";         Filename: "{app}\{#AppExeName}";             IconFilename: "{app}\Assets\Icons\LogicFlow.ico"
; Aeon Browser shortcuts
Name: "{group}\Aeon Browser";      Filename: "{#AeonInstallDir}\{#AeonExeName}"; IconFilename: "{#AeonInstallDir}\Assets\Aeon.ico"; Components: aeon
Name: "{autodesktop}\Aeon Browser"; Filename: "{#AeonInstallDir}\{#AeonExeName}"; IconFilename: "{#AeonInstallDir}\Assets\Aeon.ico"; Tasks: aeondesktopicon; Components: aeon
Name: "{group}\LogicFlow Documentation"; Filename: "{app}\Docs\API.md"
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"; IconFilename: "{app}\Assets\Icons\LogicFlow.ico"
Name: "{autodesktop}\LogicFlow"; Filename: "{app}\{#AppExeName}"; IconFilename: "{app}\Assets\Icons\LogicFlow.ico"; Tasks: desktopicon

[Registry]
; Application registration
Root: HKLM; Subkey: "SOFTWARE\DelgadoLogic\LogicFlow"; ValueType: string; ValueName: "InstallPath"; ValueData: "{app}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\DelgadoLogic\LogicFlow"; ValueType: string; ValueName: "Version"; ValueData: "{#AppVersion}"
Root: HKLM; Subkey: "SOFTWARE\DelgadoLogic\LogicFlow"; ValueType: string; ValueName: "Publisher"; ValueData: "{#AppPublisher}"
Root: HKLM; Subkey: "SOFTWARE\DelgadoLogic\LogicFlow"; ValueType: dword; ValueName: "InstallDate"; ValueData: "{code:GetInstallDate}"
Root: HKLM; Subkey: "SOFTWARE\DelgadoLogic\LogicFlow"; ValueType: string; ValueName: "HWID"; ValueData: "{code:GetHWID}"

; App Paths registration (allows running "LogicFlow" from Run dialog)
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\LogicFlow.exe"; ValueType: string; ValueName: ""; ValueData: "{app}\{#AppExeName}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\LogicFlow.exe"; ValueType: string; ValueName: "Path"; ValueData: "{app}"

; App Paths for Enterprise CLI
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\lf.exe"; ValueType: string; ValueName: ""; ValueData: "{app}\CLI\lf.exe"; Components: cli; Flags: uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\lf.exe"; ValueType: string; ValueName: "Path"; ValueData: "{app}\CLI"; Components: cli

; === Aeon Browser registry entries ===
Root: HKLM; Subkey: "SOFTWARE\DelgadoLogic\Aeon"; ValueType: string; ValueName: "InstallPath"; ValueData: "{#AeonInstallDir}"; Components: aeon; Flags: uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\DelgadoLogic\Aeon"; ValueType: string; ValueName: "Version"; ValueData: "{#AeonVersion}"; Components: aeon
Root: HKLM; Subkey: "SOFTWARE\DelgadoLogic\Aeon"; ValueType: string; ValueName: "Publisher"; ValueData: "{#AppPublisher}"; Components: aeon
; TelemetryEnabled inherits from LogicFlow key (set earlier) — no duplicate needed
; ForceTier — not set here; IT admin sets this manually for specific overrides
; App Paths (allows running "Aeon" from Run dialog / Start search)
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Aeon.exe"; ValueType: string; ValueName: ""; ValueData: "{#AeonInstallDir}\{#AeonExeName}"; Components: aeon; Flags: uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Aeon.exe"; ValueType: string; ValueName: "Path"; ValueData: "{#AeonInstallDir}"; Components: aeon
; Default browser capability registration (allows setting Aeon as default)
Root: HKLM; Subkey: "SOFTWARE\Clients\StartMenuInternet\AeonBrowser"; ValueType: string; ValueName: ""; ValueData: "Aeon Browser by DelgadoLogic"; Components: aeon; Flags: uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\Clients\StartMenuInternet\AeonBrowser\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{#AeonInstallDir}\{#AeonExeName}"""; Components: aeon

; File association (.logicflow project files)
Root: HKCR; Subkey: ".logicflow"; ValueType: string; ValueName: ""; ValueData: "LogicFlow.ProjectFile"; Flags: uninsdeletekey
Root: HKCR; Subkey: "LogicFlow.ProjectFile"; ValueType: string; ValueName: ""; ValueData: "LogicFlow Project File"; Flags: uninsdeletekey
Root: HKCR; Subkey: "LogicFlow.ProjectFile\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\Assets\Icons\LogicFlow.ico,0"
Root: HKCR; Subkey: "LogicFlow.ProjectFile\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#AppExeName}"" ""%1"""

; Startup entry (optional)
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "LogicFlow"; ValueData: """{app}\{#AppExeName}"" --minimized"; Tasks: startupentry; Flags: uninsdeletevalue

[Run]
; Install Windows service
Filename: "sc.exe"; Parameters: "create LogicFlowAgent binPath= ""{app}\Agent\{#AgentExeName}"" start= auto DisplayName= ""LogicFlow Agent"""; StatusMsg: "Installing LogicFlow Agent service..."; Tasks: installservice; Flags: runhidden
Filename: "sc.exe"; Parameters: "description LogicFlowAgent ""LogicFlow Background Health Monitor — automated system scanning by DelgadoLogic.Tech"""; Tasks: installservice; Flags: runhidden
Filename: "sc.exe"; Parameters: "start LogicFlowAgent"; StatusMsg: "Starting LogicFlow Agent..."; Tasks: installservice; Flags: runhidden

; Add firewall rules (outbound HTTPS only — no inbound ports opened)
; Rule 1: Dashboard — update checks, Pulse telemetry, baseline upload, license validation
Filename: "netsh.exe"; Parameters: "advfirewall firewall add rule name=""LogicFlow Dashboard"" dir=out action=allow program=""{app}\{#AppExeName}"" protocol=tcp remoteport=443 description=""Allows LogicFlow Dashboard to communicate with delgadologic.tech for updates, telemetry, and licensing (HTTPS only)"""; Tasks: firewallrule; Flags: runhidden
; Rule 2: Agent — background health monitoring, driver index sync
Filename: "netsh.exe"; Parameters: "advfirewall firewall add rule name=""LogicFlow Agent"" dir=out action=allow program=""{app}\Agent\{#AgentExeName}"" protocol=tcp remoteport=443 description=""Allows LogicFlow Agent background service to sync health data and driver updates (HTTPS only)"""; Tasks: firewallrule; Flags: runhidden

; Add Windows Defender exclusions (prevents false positives common with system utilities)
Filename: "powershell.exe"; Parameters: "-NoProfile -Command Add-MpPreference -ExclusionPath '{app}'"; Tasks: defenderexclusion; Flags: runhidden
Filename: "powershell.exe"; Parameters: "-NoProfile -Command Add-MpPreference -ExclusionProcess '{#AppExeName}'"; Tasks: defenderexclusion; Flags: runhidden
Filename: "powershell.exe"; Parameters: "-NoProfile -Command Add-MpPreference -ExclusionProcess '{#AgentExeName}'"; Tasks: defenderexclusion; Flags: runhidden

; Write telemetry opt-in setting to registry (respected by PulseClient at runtime)
Filename: "reg.exe"; Parameters: "add HKLM\SOFTWARE\DelgadoLogic\LogicFlow /v TelemetryEnabled /t REG_DWORD /d 1 /f"; Tasks: telemetry; Flags: runhidden
Filename: "reg.exe"; Parameters: "add HKLM\SOFTWARE\DelgadoLogic\LogicFlow /v TelemetryEnabled /t REG_DWORD /d 0 /f"; Tasks: not telemetry; Flags: runhidden
; Mirror TelemetryEnabled to Aeon key (Aeon reads its own key first, then LogicFlow's — see PulseBridge.cpp)
Filename: "reg.exe"; Parameters: "add HKLM\SOFTWARE\DelgadoLogic\Aeon /v TelemetryEnabled /t REG_DWORD /d 1 /f"; Tasks: telemetry; Components: aeon; Flags: runhidden
Filename: "reg.exe"; Parameters: "add HKLM\SOFTWARE\DelgadoLogic\Aeon /v TelemetryEnabled /t REG_DWORD /d 0 /f"; Tasks: not telemetry; Components: aeon; Flags: runhidden

; Aeon Browser firewall rule (HTTPS outbound only)
Filename: "netsh.exe"; Parameters: "advfirewall firewall add rule name=""Aeon Browser"" dir=out action=allow program=""{#AeonInstallDir}\{#AeonExeName}"" protocol=tcp remoteport=443 description=""Allows Aeon Browser HTTPS communications: update.delgadologic.tech, Tor bootstrap, Gemini (TLS), telemetry (HTTPS only)"""; Tasks: aeonfirewallrule; Components: aeon; Flags: runhidden

; Defender exclusion for Aeon install dir (prevents false positives from wolfssl.dll / Tor)
Filename: "powershell.exe"; Parameters: "-NoProfile -Command Add-MpPreference -ExclusionPath '{#AeonInstallDir}'"; Tasks: defenderexclusion; Components: aeon; Flags: runhidden
Filename: "powershell.exe"; Parameters: "-NoProfile -Command Add-MpPreference -ExclusionProcess '{#AeonExeName}'"; Tasks: defenderexclusion; Components: aeon; Flags: runhidden

; Launch application (shellexec needed because app manifest requires admin elevation)
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(AppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent shellexec

[UninstallRun]
; Stop and remove service
Filename: "sc.exe"; Parameters: "stop LogicFlowAgent"; Flags: runhidden
Filename: "sc.exe"; Parameters: "delete LogicFlowAgent"; Flags: runhidden

; Remove firewall rules
Filename: "netsh.exe"; Parameters: "advfirewall firewall delete rule name=""LogicFlow Dashboard"""; Flags: runhidden
Filename: "netsh.exe"; Parameters: "advfirewall firewall delete rule name=""LogicFlow Agent"""; Flags: runhidden
; Legacy cleanup (from older installer versions)
Filename: "netsh.exe"; Parameters: "advfirewall firewall delete rule name=""LogicFlow Update Check"""; Flags: runhidden

; Remove Windows Defender exclusions
Filename: "powershell.exe"; Parameters: "-NoProfile -Command Remove-MpPreference -ExclusionPath '{app}'"; Flags: runhidden
Filename: "powershell.exe"; Parameters: "-NoProfile -Command Remove-MpPreference -ExclusionProcess '{#AppExeName}'"; Flags: runhidden
Filename: "powershell.exe"; Parameters: "-NoProfile -Command Remove-MpPreference -ExclusionProcess '{#AgentExeName}'"; Flags: runhidden

[UninstallDelete]
Type: filesandordirs; Name: "{app}"
Type: filesandordirs; Name: "{localappdata}\LogicFlow"
; Aeon Browser install directory (user data in %APPDATA% is preserved — bookmarks/history survive uninstall)
Type: filesandordirs; Name: "{#AeonInstallDir}"
Type: dirifempty; Name: "{autopf}\DelgadoLogic"

[Code]
function GetInstallDate(Param: String): String;
begin
  Result := GetDateTimeString('yyyymmdd', '-', ':');
end;

function GetHWID(Param: String): String;
begin
  Result := GetComputerNameString;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    // Clean LogicFlow registry entries
    RegDeleteKeyIncludingSubkeys(HKEY_LOCAL_MACHINE, 'SOFTWARE\DelgadoLogic\LogicFlow');
    RegDeleteKeyIncludingSubkeys(HKEY_CLASSES_ROOT, '.logicflow');
    RegDeleteKeyIncludingSubkeys(HKEY_CLASSES_ROOT, 'LogicFlow.ProjectFile');
    // Clean Aeon Browser registry entries
    RegDeleteKeyIncludingSubkeys(HKEY_LOCAL_MACHINE, 'SOFTWARE\DelgadoLogic\Aeon');
    RegDeleteKeyIncludingSubkeys(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Aeon.exe');
    RegDeleteKeyIncludingSubkeys(HKEY_LOCAL_MACHINE, 'SOFTWARE\Clients\StartMenuInternet\AeonBrowser');
    // Remove Aeon firewall rule
    Exec('netsh.exe', 'advfirewall firewall delete rule name="Aeon Browser"', '', SW_HIDE, ewNoWait, ResultCode);
    // Remove Aeon Defender exclusions
    Exec('powershell.exe', '-NoProfile -Command Remove-MpPreference -ExclusionProcess ''Aeon.exe''', '', SW_HIDE, ewNoWait, ResultCode);
    // NOTE: %APPDATA%\DelgadoLogic\Aeon is intentionally preserved (bookmarks, history, settings)
    // User must manually delete if they want to remove that data.
  end;
end;
