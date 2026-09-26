[Setup]
AppName=DNSentinel
AppVersion=1.0.1
DefaultDirName={pf}\DNSentinel
PrivilegesRequired=admin
OutputDir=dist-installer
OutputBaseFilename=DNSentinel-Setup-1.0.1
[Files]
Source: ..\dist\DNSentinel.exe; DestDir: {app}
Source: ..\config.yaml; DestDir: {app}; Flags: ignoreversion
Source: ..\blocklist.txt; DestDir: {app}; Flags: ignoreversion
Source: ..\README.md; DestDir: {app}; Flags: ignoreversion
[Icons]
Name: {group}\DNSentinel; Filename: {app}\DNSentinel.exe
Name: {commondesktop}\DNSentinel; Filename: {app}\DNSentinel.exe
