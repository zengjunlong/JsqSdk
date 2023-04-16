Overview
=====================================
This is the full sources of NetFilter SDK 2.0 Gateway Filter. 

Package contents
=====================================
bin\Release - x86 and x64 versions of APIs with C++ interface, pre-built samples and the driver registration utility.
bin\Release_c_api - x86 and x64 versions of APIs with C interface, pre-built samples and the driver registration utility.

bin\driver\std - the binaries of driver for x86 and x64 platforms.
bin\driver\wpp - the binaries of driver for x86 and x64 platforms with ETW tracing support. 

driver - the sources of driver.
nfsrvapi - the sources of driver API.

samples - the examples of using APIs in C/C++/Deplhi/.NET
samples\CSharp - .NET API and C# samples.
samples\Delphi - Delphi API and samples.
Help - API documentation.


Driver installation
=====================================
- Use the scripts bin\install_driver.bat and bin\install_driver_x64.bat for installing and registering the network hooking driver on x86 and x64 systems respectively. 
The driver starts immediately and reboot is not required.

- Run bin\uninstall_driver.bat to remove the driver from system.

Elevated administrative rights must be activated explicitly on Vista and later for registering the driver (run the scripts using "Run as administrator" context menu item in Windows Explorer). 

For Windows Vista x64 and later versions of the Windows family of operating systems, kernel-mode software must have a digital signature to load on x64-based computer systems. 
The included x64 version of the network hooking driver is not signed. In order to test it on Vista x64 you should press F8 during system boot and choose Disable Driver Signature Enforcement option. 
For the end-user software you have to obtain the Code Signing certificate and sign the driver.


Supported platforms: 
    Windows 8/2008/2012/10 x86/x64
