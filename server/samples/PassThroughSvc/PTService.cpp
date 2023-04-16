// SIFilterSvc.cpp : Defines the entry point for the application.
//

//#include "stdafx.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tchar.h>
#include <stdio.h>
#include <process.h>
#include <io.h>
#include <string>
#include <crtdbg.h>
#include "nfsrvapi.h"
#include "PTService.h"
#include "dbglogger.h"

using namespace nfapi;
using namespace nfsrvapi;

// Change this string after renaming and registering the driver under different name
#define NFDRIVER_NAME "nfsrvfilter"

#if !defined(_DEBUG) && !defined(_RELEASE_LOG)

void printConnInfo(bool connected, ENDPOINT_ID id, PNF_TCP_CONN_INFO pConnInfo)
{
}

void printAddrInfo(bool created, ENDPOINT_ID id, PNF_UDP_CONN_INFO pConnInfo)
{
}

#else

/**
* Print the connection information
**/
void printConnInfo(bool connected, ENDPOINT_ID id, PNF_TCP_CONN_INFO pConnInfo)
{
	char localAddr[MAX_PATH] = "";
	char remoteAddr[MAX_PATH] = "";
	DWORD dwLen;
	sockaddr * pAddr;
	char processName[MAX_PATH] = "";
	
	pAddr = (sockaddr*)pConnInfo->localAddress;
	dwLen = sizeof(localAddr);

	WSAAddressToString((LPSOCKADDR)pAddr, 
				(pAddr->sa_family == AF_INET6)? sizeof(sockaddr_in6) : sizeof(sockaddr_in), 
				NULL, 
				localAddr, 
				&dwLen);

	pAddr = (sockaddr*)pConnInfo->remoteAddress;
	dwLen = sizeof(remoteAddr);

	WSAAddressToString((LPSOCKADDR)pAddr, 
				(pAddr->sa_family == AF_INET6)? sizeof(sockaddr_in6) : sizeof(sockaddr_in), 
				NULL, 
				remoteAddr, 
				&dwLen);
	
	if (connected)
	{
		DbgPrint("tcpConnected id=%I64u flag=%d direction=%s src=%s dst=%s",
			id,
			pConnInfo->filteringFlag,
			(pConnInfo->direction == NF_D_IN)? "in" : ((pConnInfo->direction == NF_D_OUT)? "out" : "none"),
			localAddr, 
			remoteAddr);
	} else
	{
		DbgPrint("tcpClosed id=%I64u flag=%d direction=%s src=%s dst=%s",
			id,
			pConnInfo->filteringFlag,
			(pConnInfo->direction == NF_D_IN)? "in" : ((pConnInfo->direction == NF_D_OUT)? "out" : "none"),
			localAddr, 
			remoteAddr);
	}

}

void printAddrInfo(bool created, ENDPOINT_ID id, PNF_UDP_CONN_INFO pConnInfo)
{
	char localAddr[MAX_PATH] = "";
	sockaddr * pAddr;
	DWORD dwLen;
	
	pAddr = (sockaddr*)pConnInfo->localAddress;
	dwLen = sizeof(localAddr);

	WSAAddressToString((LPSOCKADDR)pAddr, 
				(pAddr->sa_family == AF_INET6)? sizeof(sockaddr_in6) : sizeof(sockaddr_in), 
				NULL, 
				localAddr, 
				&dwLen);
		
	if (created)
	{
		DbgPrint("udpCreated id=%I64u src=%s",
			id,
			localAddr);
	} else
	{
		DbgPrint("udpClosed id=%I64u src=%s",
			id,
			localAddr);
	}

}

#endif

//
//	API events handler
//
class EventHandler : public NF_EventHandler
{
	virtual void threadStart()
	{
		DbgPrint("threadStart");
		
		// Initialize thread specific stuff
	}

	virtual void threadEnd()
	{
		DbgPrint("threadEnd");

		// Uninitialize thread specific stuff
	}
	
	//
	// TCP events
	//

	virtual void tcpConnectRequest(ENDPOINT_ID id, PNF_TCP_CONN_INFO pConnInfo)
	{
		DbgPrint("tcpConnectRequest id=%I64u", id);
	}

	virtual void tcpConnected(ENDPOINT_ID id, PNF_TCP_CONN_INFO pConnInfo)
	{
		printConnInfo(true, id, pConnInfo);
	}

	virtual void tcpClosed(ENDPOINT_ID id, PNF_TCP_CONN_INFO pConnInfo)
	{
		printConnInfo(false, id, pConnInfo);
	}

	virtual void tcpReceive(ENDPOINT_ID id, const char * buf, int len)
	{	
		DbgPrint("tcpReceive id=%I64u len=%d", id, len);

		// Send the packet to application
		nf_srv_tcpPostReceive(id, buf, len);
	}

	virtual void tcpSend(ENDPOINT_ID id, const char * buf, int len)
	{
		DbgPrint("tcpSend id=%I64u len=%d", id, len);

		// Send the packet to server
		nf_srv_tcpPostSend(id, buf, len);
	}

	virtual void tcpCanReceive(ENDPOINT_ID id)
	{
		DbgPrint("tcpCanReceive id=%I64d", id);
	}

	virtual void tcpCanSend(ENDPOINT_ID id)
	{
		DbgPrint("tcpCanSend id=%I64d", id);
	}
	
	//
	// UDP events
	//

	virtual void udpCreated(ENDPOINT_ID id, PNF_UDP_CONN_INFO pConnInfo)
	{
		printAddrInfo(true, id, pConnInfo);
	}

	virtual void udpConnectRequest(ENDPOINT_ID id, PNF_UDP_CONN_REQUEST pConnReq)
	{
		DbgPrint("udpConnectRequest id=%I64u", id);
	}

	virtual void udpClosed(ENDPOINT_ID id, PNF_UDP_CONN_INFO pConnInfo)
	{
		printAddrInfo(false, id, pConnInfo);
	}

	virtual void udpReceive(ENDPOINT_ID id, const unsigned char * remoteAddress, const char * buf, int len, PNF_UDP_OPTIONS options)
	{	
		char remoteAddr[MAX_PATH];
		DWORD dwLen;
		
		dwLen = sizeof(remoteAddr);
		WSAAddressToString((sockaddr*)remoteAddress, 
				(((sockaddr*)remoteAddress)->sa_family == AF_INET6)? sizeof(sockaddr_in6) : sizeof(sockaddr_in), 
				NULL, 
				remoteAddr, 
				&dwLen);

		DbgPrint("udpReceive id=%I64u len=%d dst=%s", id, len, remoteAddr);

		// Send the packet to application
		nf_srv_udpPostReceive(id, remoteAddress, buf, len, options);
	}

	virtual void udpSend(ENDPOINT_ID id, const unsigned char * remoteAddress, const char * buf, int len, PNF_UDP_OPTIONS options)
	{
		char remoteAddr[MAX_PATH];
		DWORD dwLen;
		
		dwLen = sizeof(remoteAddr);
		WSAAddressToString((sockaddr*)remoteAddress, 
				(((sockaddr*)remoteAddress)->sa_family == AF_INET6)? sizeof(sockaddr_in6) : sizeof(sockaddr_in), 
				NULL, 
				remoteAddr, 
				&dwLen);

		DbgPrint("udpSend id=%I64u len=%d dst=%s", id, len, remoteAddr);

		// Send the packet to server
		nf_srv_udpPostSend(id, remoteAddress, buf, len, options);
	}

	virtual void udpCanReceive(ENDPOINT_ID id)
	{
		DbgPrint("udpCanReceive id=%I64d", id);
	}

	virtual void udpCanSend(ENDPOINT_ID id)
	{
		DbgPrint("udpCanSend id=%I64d", id);
	}
};

ServiceModule _Module;

HINSTANCE g_hInstance = NULL;

#if defined(_DEBUG) || defined(_RELEASE_LOG)
DBGLogger DBGLogger::dbgLog;
#endif


LPCTSTR FindOneOf(LPCTSTR p1, LPCTSTR p2)
{
    while (p1 != NULL && *p1 != NULL)
    {
        LPCTSTR p = p2;
        while (p != NULL && *p != NULL)
        {
            if (*p1 == *p)
                return CharNext(p1);
            p = CharNext(p);
        }
        p1 = CharNext(p1);
    }
    return NULL;
}

inline void ServiceModule::Init(HINSTANCE h)
{
    m_hInstance = h;
    m_bService = TRUE;

    strcpy(m_szServiceName, "passthroughsvc");

    // set up the initial service status 
    m_hServiceStatus = NULL;

    RtlZeroMemory(&m_status, sizeof (m_status));

    m_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    m_status.dwCurrentState = SERVICE_STOPPED;
    m_status.dwControlsAccepted = SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_STOP;
}


BOOL ServiceModule::IsInstalled()
{
    BOOL bResult = FALSE;

    SC_HANDLE hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

    if ( hSCM != NULL )
    {
        SC_HANDLE hService = ::OpenServiceA(hSCM, m_szServiceName, SERVICE_QUERY_CONFIG);
        if ( hService != NULL )
        {
            bResult = TRUE;
            ::CloseServiceHandle(hService);
        }
        ::CloseServiceHandle(hSCM);
    }

    return bResult;
}

inline std::string get_ModuleFileNameA(HINSTANCE hInstance = NULL)
{
    std::string result;
    result.resize(MAX_PATH + 1);
    GetModuleFileNameA( hInstance, &*result.begin() , (DWORD)result.size() );
    result.resize(strlen(result.c_str()));
    return result;
}

inline BOOL ServiceModule::Install()
{
    SC_HANDLE hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if ( hSCM == NULL )
    {
//        MessageBoxA(NULL, "Couldn't open service manager", m_szServiceName, MB_OK);
//        LogEvent(EVENTLOG_ERROR_TYPE, _T("Couldn't open service manager"));
        return FALSE;
    }

    // Get the executable file path
    const std::string filePath(get_ModuleFileNameA());

    SC_HANDLE hService = ::CreateServiceA(
        hSCM, m_szServiceName, m_szServiceName,
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        filePath.c_str(), NULL, NULL, "RPCSS\0", NULL, NULL);

    if ( hService == NULL )
    {
        ::CloseServiceHandle(hSCM);
//        MessageBoxA(NULL, "Couldn't create service", m_szServiceName, MB_OK);
//        LogEvent(EVENTLOG_ERROR_TYPE, _T("Couldn't create service %s"), m_szServiceName);
        return FALSE;
    }

    // The service should be restarted in case of crashes

    HMODULE hModule = LoadLibraryW(L"advapi32.dll");
    if ( hModule )
    {
        typedef BOOL (WINAPI *pChangeServiceConfig2)(
          SC_HANDLE hService,
          DWORD dwInfoLevel,
          LPVOID lpInfo
        );

        pChangeServiceConfig2 pChangeServiceConfig2_proc = 
            (pChangeServiceConfig2)GetProcAddress(hModule, "ChangeServiceConfig2A");

        if ( pChangeServiceConfig2_proc )
        {
            // Set the failure actions

            SC_ACTION sa[4] = {
                { SC_ACTION_RESTART, 1000 },
                { SC_ACTION_RESTART, 1000 },
                { SC_ACTION_RESTART, 1000 },
                { SC_ACTION_NONE, 1000 }
            };

            SERVICE_FAILURE_ACTIONS sfa;

            memset(&sfa, 0, sizeof(sfa));
            sfa.dwResetPeriod = 10;
            sfa.lpRebootMsg = NULL;
            sfa.lpCommand = NULL;
            sfa.lpsaActions = sa;
            sfa.cActions = (DWORD)(sizeof(sa) / sizeof(sa[0]));

            pChangeServiceConfig2_proc(hService, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa);

            SERVICE_DESCRIPTION sd;

            std::string s = m_szServiceName;

            sd.lpDescription = (LPSTR)s.c_str();

            pChangeServiceConfig2_proc(hService, SERVICE_CONFIG_DESCRIPTION, &sd);
        }
        FreeLibrary(hModule);
    }

    ::CloseServiceHandle(hService);
    ::CloseServiceHandle(hSCM);

    return TRUE;
}

inline BOOL ServiceModule::Uninstall()
{
    if ( !IsInstalled() )
        return TRUE;

    SC_HANDLE hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

    if ( hSCM == NULL )
    {
//        MessageBoxA(NULL, "Couldn't open service manager", m_szServiceName, MB_OK);
//        LogEvent(EVENTLOG_ERROR_TYPE, _T("Couldn't open service manager"));
        return FALSE;
    }

    SC_HANDLE hService = ::OpenServiceA(hSCM, m_szServiceName, SERVICE_USER_DEFINED_CONTROL | DELETE);

    if ( hService == NULL )
    {
        ::CloseServiceHandle(hSCM);
//        MessageBoxA(NULL, "Couldn't open service", m_szServiceName, MB_OK);
//        LogEvent(EVENTLOG_ERROR_TYPE, _T("Couldn't open service %s"), m_szServiceName);
        return FALSE;
    }
    SERVICE_STATUS status;
    ::ControlService(hService, SERVICE_CONTROL_STOP, &status);

    BOOL bDelete = ::DeleteService(hService);
    ::CloseServiceHandle(hService);
    ::CloseServiceHandle(hSCM);

    if ( bDelete )
        return TRUE;

//    MessageBoxA(NULL, "Service could not be deleted", m_szServiceName, MB_OK);
//    LogEvent(EVENTLOG_ERROR_TYPE, _T("Service %s could not be deleted"), m_szServiceName);

    return FALSE;
}

static void Quit(DWORD Status)
{
    TerminateProcess(GetCurrentProcess(), Status);
    __debugbreak();
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Service startup and registration
inline void ServiceModule::Start()
{
    SERVICE_TABLE_ENTRYA st[] =
    {
        { m_szServiceName, _ServiceMain },
        { NULL, NULL }
    };
    if ( m_bService && !::StartServiceCtrlDispatcherA(st) )
    {
        m_bService = FALSE;

        #if !defined (_DEBUG)
            Quit(0xC0000022); // STATUS_ACCESS_DENIED.
        #endif
    }
    if (m_bService == FALSE)
        Run();
}

inline void ServiceModule::ServiceMain(DWORD /* dwArgc */, LPSTR* /* lpszArgv */)
{
    //
    // Initializing.
    // Do not call anything until SetServiceStatus(SERVICE_RUNNING),
    // it may cause a deadlock or other negative side effects.
    //

    _Module.dwThreadID = GetCurrentThreadId();

    //
    // Register service control handler.
    //

    m_hServiceStatus = RegisterServiceCtrlHandlerExA(m_szServiceName, _Handler, NULL);
    if ( !m_hServiceStatus )
    {
        DbgPrint("[E] RegisterServiceCtrlHandlerEx failed, err = 0x%.8lx.", GetLastError());
        Quit(0xC0000001); // STATUS_UNSUCCESSFUL.
    }

    //
    // Notify service running.
    //

    m_status.dwWin32ExitCode = S_OK;
    m_status.dwCheckPoint = 0;
    m_status.dwWaitHint = 0;

    SetServiceStatus(SERVICE_RUNNING);

    Run();

    //
    // Stop service and exit.
    //

    SetServiceStatus(SERVICE_STOPPED);

    //
    // Do not place any code here. MSDN says (SetServiceStatus):
    //
    //  If the status is SERVICE_STOPPED, perform all necessary cleanup
    //  and call SetServiceStatus one time only. This function makes an
    //  LRPC call to the SCM. The first call to the function in the
    //  SERVICE_STOPPED state closes the RPC context handle and any
    //  subsequent calls can cause the process to crash.
    //
    //  Do not attempt to perform any additional work after calling
    //  SetServiceStatus with SERVICE_STOPPED, because the service
    //  process can be terminated at any time.
    //
}

inline void ServiceModule::Handler(DWORD dwOpcode, DWORD dwEventType)
{
    DbgPrint("ServiceModule::Handler code=%lu, type=%lu", dwOpcode, dwEventType);

    switch (dwOpcode)
    {
    case SERVICE_CONTROL_STOP:
        DbgPrint("ServiceModule::Handler manual stop");
		PostThreadMessage(dwThreadID, WM_QUIT, 0, 0);
        break;
    case SERVICE_CONTROL_PAUSE:
        DbgPrint("ServiceModule::Handler pause");
        break;
    case SERVICE_CONTROL_CONTINUE:
        DbgPrint("ServiceModule::Handler continue");
        break;
    case SERVICE_CONTROL_INTERROGATE:
        DbgPrint("ServiceModule::Handler interrogage");
        break;

    case SERVICE_CONTROL_SHUTDOWN:
		{
			DWORD timeout;
			//
			// Maximum timeout for service shutdown is 20 seconds.
			// This value can be changed via 'WaitToKillServiceTimeout' registry settings.
			// We give only 10 seconds to global hosts for made all necessary
			// cleanup operations and exit.
			//

			DbgPrint("ServiceModule::Handler shutdown, timeout = 10 seconds.");
			timeout = 10 * 5;

			SetServiceStatus(SERVICE_STOP_PENDING);

			PostThreadMessage(dwThreadID, WM_QUIT, 0, 0);
		}
	    break;
    }
}

void WINAPI ServiceModule::_ServiceMain(DWORD dwArgc, LPSTR* lpszArgv)
{
    _Module.ServiceMain(dwArgc, lpszArgv);
}

DWORD WINAPI ServiceModule::_Handler(DWORD dwOpcode, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext)
{
    _Module.Handler(dwOpcode, dwEventType);
    return NO_ERROR;
}

void ServiceModule::SetServiceStatus(DWORD dwState)
{
    m_status.dwCurrentState = dwState;
    ::SetServiceStatus(m_hServiceStatus, &m_status);
}

void ServiceModule::PostMessage(UINT msg)
{
    PostThreadMessage(dwThreadID, msg, 0, 0);
}


void ServiceModule::Run()
{
    DbgPrint("ServiceModule::Run()");

//    LogEvent(EVENTLOG_INFORMATION_TYPE, _T("Service started"));

	EventHandler eh;
	WSADATA wsaData;

	// This call is required for WSAAddressToString
    ::WSAStartup(MAKEWORD(2, 2), &wsaData);

#ifdef _DEBUG
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
	_CrtSetReportMode( _CRT_ERROR, _CRTDBG_MODE_DEBUG);
#endif

	NF_SRV_OPTIONS options;

	memset(&options, 0, sizeof(options));
	options.defaultProxyPort = htons(10080);
	options.proxyThreadCount = 0;

	// Initialize the library and start filtering thread
	if (nf_srv_init(NFDRIVER_NAME, &eh, &options) != NF_STATUS_SUCCESS)
	{
		DbgPrint("Failed to connect to driver");
		return;
	}

	// Filter TCP/UDP
	NF_SRV_RULE rule;

	memset(&rule, 0, sizeof(rule));

//	rule.protocol = IPPROTO_TCP;
	rule.action.filteringFlag = NF_FILTER;

	nf_srv_addRule(&rule, FALSE);

	if (m_bService)
    {
        DbgPrint("entering message loop");

        MSG msg;

        while (GetMessage(&msg, 0, 0, 0))
        {
            DispatchMessage(&msg);
        }
    }
    else
    {
#if defined(_DEBUG) || defined(_RELEASE_LOG)
        MessageBox(NULL, "Press OK to stop the executable", m_szServiceName, MB_OK);
#endif
    }

	// Free the library
	nf_srv_free();

	::WSACleanup();

    DbgPrint("stopped");
}


/////////////////////////////////////////////////////////////////////////////
//
extern "C" int WINAPI _tWinMain(HINSTANCE hInstance, 
    HINSTANCE /*hPrevInstance*/, LPTSTR lpCmdLine, int /*nShowCmd*/)
{
#ifdef _DEBUG
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
    _CrtSetReportMode( _CRT_ERROR, _CRTDBG_MODE_DEBUG);
#endif

#if defined(_DEBUG) || defined(_RELEASE_LOG)
    {
        DBGLogger::instance().init("PassThroughSvc.log");
    }
#endif

    lpCmdLine = GetCommandLine(); //this line necessary for _ATL_MIN_CRT

    _Module.Init(hInstance);
    _Module.m_bService = TRUE;

    TCHAR szTokens[] = _T("-/");

    LPCTSTR lpszToken = FindOneOf(lpCmdLine, szTokens);
    while (lpszToken != NULL)
    {
        if (lstrcmpi(lpszToken, _T("Unregister"))==0)
            return _Module.Uninstall();

        // Register as Service
        if (lstrcmpi(lpszToken, _T("Register"))==0)
            return _Module.Install();

        // Run as a regular executable
        if (_strnicmp(lpszToken, _T("Run"), 3)==0)
        {
            _Module.m_bService = FALSE;
        }

        lpszToken = FindOneOf(lpszToken, szTokens);
    }

    _Module.Start();

    _Module.Install();

#if defined(_DEBUG) || defined(_RELEASE_LOG)
    DBGLogger::instance().free();
#endif

    // When we get here, the service has been stopped
    return _Module.m_status.dwWin32ExitCode;
}
