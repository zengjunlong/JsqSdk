cd /d %~dp0

rem Installing the network hooking driver build for 64-bit systems

rem Copy the driver to system folder
copy driver\tdi\std\amd64\netfilter2.sys %windir%\system32\drivers

rem Register the driver
release\win32\nfregdrv.exe netfilter2

pause