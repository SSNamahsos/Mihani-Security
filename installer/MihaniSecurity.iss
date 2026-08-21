; MihaniSecurity Inno Setup script
; Builds "MihaniSecurity Setup.exe" from the release binaries in build\bin.
;
; Layout installed:
;   {app}\MihaniSecurity.exe          Wails GUI
;   {app}\mihanisecurity-service.exe  Windows service binary
;   {app}\signatures\signatures.db    bundled signature pack
;   {app}\icon.png                    used by the GUI + toast notifications
;
; The service is registered as "MihaniSecurity" (LocalSystem, auto start)
; and unregistered on uninstall via sc.exe so the removal never depends on
; our own files still being on disk.

#define MyAppName "MihaniSecurity"
#define MyAppVersion "1.0.6"
#define MyAppPublisher "MihaniSecurity Project"
#define MyAppExeName "MihaniSecurity.exe"
#define MyServiceExe "mihanisecurity-service.exe"

[Setup]
AppId={{8A7C4E2F-6B9D-4F0E-9A5C-2D1B3E4F5A60}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppVerName={#MyAppName} {#MyAppVersion}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=..\dist
OutputBaseFilename=MihaniSecurity Setup
SetupIconFile=..\build\windows\icon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
MinVersion=10.0.17763
DisableWelcomePage=no
LicenseFile=..\LICENSE

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "..\build\bin\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\build\bin\{#MyServiceExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\assets\signatures\signatures.db"; DestDir: "{app}\signatures"; Flags: ignoreversion
Source: "..\icon.png"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\deploy\mihani-sign.cer"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked

[Run]
; Register the protection service (runs elevated like the installer).
Filename: "{app}\{#MyServiceExe}"; Parameters: "-mode install"; Flags: runhidden waituntilterminated
; Trust the self-signed code-signing root so Windows Security Center accepts the product.
Filename: "certutil.exe"; Parameters: "-addstore -f Root ""{app}\mihani-sign.cer"""; Flags: runhidden; StatusMsg: "Installing trusted certificate..."; Check: FileExists(ExpandConstant('{app}\mihani-sign.cer'))
; Launch the GUI once setup finishes.
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Stop and remove the service. Wrapped in cmd so the uninstaller never shows
; an error if the service is already gone (sc returns nonzero in that case).
Filename: "{cmd}"; Parameters: "/c sc stop MihaniSecurity & sc delete MihaniSecurity & exit /b 0"; Flags: runhidden; RunOnceId: "remove_service"

