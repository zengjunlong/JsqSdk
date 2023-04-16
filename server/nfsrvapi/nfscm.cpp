//
// 	NetFilterSDK 
// 	Copyright (C) Vitaly Sidorov
//	All rights reserved.
//
//	This file is a part of the NetFilter SDK.
//	The code and information is provided "as-is" without
//	warranty of any kind, either expressed or implied.
//


#include "StdAfx.h"
#include "nfscm.h"
#include "nfsrvapi.h"

using namespace nfsrvapi;

#define DriverDevicePrefix "\\\\.\\CtrlNFSRV"

static bool disableTCPOffloading(bool disable);

static NF_STATUS nf_registerDriverInternal(const char * driverName)
{
	bool result = false;
	wchar_t drvName[MAX_PATH];
	wchar_t drvPath[MAX_PATH];
	SC_HANDLE schSCM = NULL;
	SC_HANDLE schService = NULL;

	disableTCPOffloading(true);

	_snwprintf(drvName, sizeof(drvName)/2, L"%S", driverName);
	_snwprintf(drvPath, sizeof(drvPath)/2, L"system32\\drivers\\%S.sys", driverName);

	schSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!schSCM)
	{
		return NF_STATUS_FAIL;
	}

	schService = CreateServiceW(schSCM,
				drvName,
				drvName,
				SERVICE_ALL_ACCESS,
				SERVICE_KERNEL_DRIVER,
				SERVICE_SYSTEM_START,
				SERVICE_ERROR_NORMAL,
				drvPath,
				L"PNP_TDI",
				NULL,
				NULL,
				NULL,
				NULL);

	HRESULT hr = HRESULT_FROM_WIN32(GetLastError());

	if (schService != NULL)
	{
		if (StartService(schService, 0, NULL))
		{
			result = true;
		}

		CloseServiceHandle(schService);
	} else
	{
		schService = OpenService(schSCM, driverName, SERVICE_START);
		if (schService != NULL)
		{
			if (StartService(schService, 0, NULL))
			{
				result = true;
			}

			CloseServiceHandle(schService);
		}
	}

	CloseServiceHandle(schSCM);

	return result? NF_STATUS_SUCCESS : NF_STATUS_FAIL;
}


HANDLE nfsrvapi::nf_srv_openDevice(const char * driverName)
{
	char	deviceName[MAX_PATH];
	HANDLE	hDevice = NULL;
	int		step = 0;

	_snprintf(deviceName, sizeof(deviceName), "%s%s", DriverDevicePrefix, driverName);

	for (;;)
	{
		hDevice = CreateFile(deviceName,
			GENERIC_READ | GENERIC_WRITE,
			0,
			NULL,
			OPEN_EXISTING,
			FILE_FLAG_OVERLAPPED,
			NULL);

		if (hDevice == INVALID_HANDLE_VALUE)
		{
			step++;

			switch (step)
			{
			case 1:
				nf_registerDriverInternal(driverName);
				continue;
			}
			
			return hDevice;
		}

		break;
	}	

	return hDevice;
}

NFSRVAPI_API NF_STATUS NFSRVAPI_NS 
nf_srv_registerDriver(const char * driverName)
{
	NF_STATUS status = nf_registerDriverInternal(driverName);
	return status;
}

NFSRVAPI_API NF_STATUS NFSRVAPI_NS 
nf_srv_unRegisterDriver(const char * driverName)
{
	bool bResult = false;
	SC_HANDLE schSCM = NULL;
	
	disableTCPOffloading(false);

	schSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (schSCM)
	{
		SC_HANDLE schService = OpenService(schSCM, driverName, DELETE);
		if (schService != NULL)
		{
			DeleteService(schService);
			CloseServiceHandle(schService);

			bResult = true;
		}

		CloseServiceHandle(schSCM);
	}

	return bResult? NF_STATUS_SUCCESS : NF_STATUS_FAIL;
}

static bool disableTCPOffloading(bool disable)
{
    HKEY	hkey;
    LONG	err;
    DWORD	dwValue;

	err = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
        0,
        KEY_SET_VALUE,
        &hkey
       );

    if ( ERROR_SUCCESS != err )
    {
        return false;
    }

	dwValue = disable? 1 : 0;

	err = RegSetValueExA(
					hkey,
					"DisableTaskOffload",
					NULL,
					REG_DWORD,
					(LPBYTE)&dwValue,
					sizeof(DWORD)
				   );

	RegCloseKey(hkey);

	return ERROR_SUCCESS == err;
}
