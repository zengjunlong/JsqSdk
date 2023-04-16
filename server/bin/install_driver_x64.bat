cd /d %~dp0

rem Installing the network hooking driver build for 64-bit systems

rem Copy the driver to system folder
copy driver\std\x64\nfsrvfilter.sys %windir%\system32\drivers

rem Register the driver
release\win32\nfsrvregdrv.exe nfsrvfilter

pause