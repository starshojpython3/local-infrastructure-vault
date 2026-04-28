#define MyAppName "Password Vault"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "Anton Pobyvanets"
#define MyAppExeName "PasswordVault.exe"

[Setup]
AppId={{C58EC6B9-E5A0-44E8-8A93-3E3D0A7BAE52}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\PasswordVault
DefaultGroupName=Password Vault
DisableProgramGroupPage=yes
OutputDir=dist
OutputBaseFilename=PasswordVault-Setup-win64
Compression=lzma
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
SetupIconFile=app\assets\app_icon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked

[Files]
Source: "dist\PasswordVault\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Password Vault"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\Password Vault"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch Password Vault"; Flags: nowait postinstall skipifsilent
