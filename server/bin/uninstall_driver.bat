cd /d %~dp0

rem Uninstall the network hooking driver

rem Stop the driver
sc stop nfsrvfilter

rem Unregister the driver
release\win32\nfsrvregdrv.exe -u nfsrvfilter

rem Delete driver file
del %windir%\system32\drivers\nfsrvfilter.sys


pause