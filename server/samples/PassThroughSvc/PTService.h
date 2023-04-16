// Service class 

#pragma once

class ServiceModule
{
public:
    ServiceModule()
    {
    }
    void Init(HINSTANCE h);
    void Start();
    void ServiceMain(DWORD dwArgc, LPSTR* lpszArgv);
    void Handler(DWORD dwOpcode, DWORD dwEventType);
    void Run();
    BOOL IsInstalled();
    BOOL Install();
    BOOL Uninstall();
    void SetServiceStatus(DWORD dwState);
    void PostMessage(UINT msg);

//Implementation
private:
    static void WINAPI _ServiceMain(DWORD dwArgc, LPSTR* lpszArgv);
    static DWORD WINAPI _Handler(DWORD dwOpcode, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext);

// data members
public:
    HINSTANCE m_hInstance;
    char m_szServiceName[256];
    SERVICE_STATUS_HANDLE m_hServiceStatus;
    SERVICE_STATUS m_status;
    DWORD dwThreadID;
    BOOL m_bService;
};

extern ServiceModule _Module;

