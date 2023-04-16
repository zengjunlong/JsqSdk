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

#define _NF_INTERNALS

#include <iphlpapi.h>
#include "nfsrvapi.h"
#include "nfscm.h"
#include "sync.h"
#include "TcpProxy.h"
#include "SrvUdpProxy.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib,"ws2_32.lib")

using namespace nfsrvapi;

static bool g_initialized = false;
static AutoHandle g_hDevice;
static AutoCriticalSection	g_cs;

static NFAPI_NS NF_EventHandler * g_pEventHandler = NULL;
static NF_SRV_OPTIONS g_options;

static AutoEventHandle		g_stopEvent;
static AutoHandle			g_hWorkThread;

#if defined(_DEBUG) || defined(_RELEASE_LOG)
DBGLogger DBGLogger::dbgLog;
#endif

NF_SRV_FLAGS nf_srv_getFlags()
{
	return (NF_SRV_FLAGS)g_options.flags;
}

static unsigned WINAPI nf_workThread(void* );
static void updateInterfaceAddresses();

class ServerTCPProxy : public TcpProxy::TCPProxy
{
public:
	virtual bool getRemoteAddress(sockaddr * pRemoteAddr, NFAPI_NS PNF_TCP_CONN_INFO pConnInfo)
	{
		NF_ADDRESS srcAddr = {0}, dstAddr = {0};

		if (pRemoteAddr->sa_family == AF_INET)
		{
			srcAddr.ipFamily = AF_INET;
			srcAddr.ip.v4 = ((sockaddr_in*)pRemoteAddr)->sin_addr.S_un.S_addr;
			srcAddr.port = ((sockaddr_in*)pRemoteAddr)->sin_port;
		} else
		{
			srcAddr.ipFamily = AF_INET6;
			memcpy(&srcAddr.ip.v6, &((sockaddr_in6*)pRemoteAddr)->sin6_addr, 16);
			srcAddr.port = ((sockaddr_in6*)pRemoteAddr)->sin6_port;
		}

		NF_STATUS status = nf_srv_getDestinationAddress(&srcAddr, &dstAddr, IPPROTO_TCP);
		if (status != NF_STATUS_SUCCESS)
		{
			DbgPrint("nf_srv_getDestinationAddress failed\n");
			return false;
		}

		if (pRemoteAddr->sa_family == AF_INET)
		{
			sockaddr_in * pAddr = (sockaddr_in *)pConnInfo->remoteAddress;
			memset(pAddr, 0, sizeof(*pAddr));
			pAddr->sin_family = AF_INET;
			pAddr->sin_port = dstAddr.port;
			pAddr->sin_addr.S_un.S_addr = dstAddr.ip.v4;
		} else
		{
			sockaddr_in6 * pAddr = (sockaddr_in6 *)pConnInfo->remoteAddress;
			memset(pAddr, 0, sizeof(*pAddr));
			pAddr->sin6_family = AF_INET;
			pAddr->sin6_port = dstAddr.port;
			memcpy(&pAddr->sin6_addr, &dstAddr.ip.v6, 16);
		}

		return true;
	}
};

static ServerTCPProxy g_tcpProxy;
static SrvUdpProxy::UDPProxy g_udpProxy;


/**
* Initialize the driver with specified name
* @return NF_STATUS 
* @param driverName - driver service name
* @param options - initialization parameters
**/
NFSRVAPI_API NF_STATUS NFSRVAPI_NS 
nf_srv_init(const char * driverName, NFAPI_NS NF_EventHandler * pEventHandler, PNF_SRV_OPTIONS options)
{
	HANDLE hDevice;

	if (g_initialized)
		return NF_STATUS_SUCCESS;

	if (options)
	{
		g_options = *options;
	} else
	{
		memset(&g_options, 0, sizeof(g_options));
	}

	g_pEventHandler = pEventHandler;

	WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		return NF_STATUS_FAIL;
	}

#if defined(_DEBUG) || defined(_RELEASE_LOG)
	DBGLogger::instance().init("nfsrvapilog.txt");
#endif

	hDevice = nf_srv_openDevice(driverName);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		return NF_STATUS_FAIL;
	} else
	{
		g_hDevice.Attach(hDevice);
	}

	g_initialized = true;

	unsigned int threadId;
	HANDLE hThread;

	hThread = (HANDLE)_beginthreadex(0, 0,
                     nf_workThread,
                     (LPVOID)NULL,
                     0,
                     &threadId);
	
	if (hThread == 0)
	{
		g_hWorkThread.Attach(INVALID_HANDLE_VALUE);
		nf_srv_free();
		return NF_STATUS_FAIL;
	} else
	{
		g_hWorkThread.Attach(hThread);
	}

	updateInterfaceAddresses();

	if (!(g_options.flags & NSF_DONT_START_LOCAL_TCP_PROXY))
	{
		if (g_options.defaultProxyPort == 0)
		{
			g_options.defaultProxyPort = htons(10080);
		}

		g_tcpProxy.setEventHandler(g_pEventHandler);

		bool result = false;
		
		for (int i=0; i<10; i++)
		{
			if (g_tcpProxy.init(g_options.defaultProxyPort+i, false, g_options.proxyThreadCount))
			{
				result = true;
				break;
			}
		}

		if (!result)
		{
			nf_srv_free();
			return NF_STATUS_FAIL;
		}
	}

	if (!(g_options.flags & NSF_DONT_START_LOCAL_UDP_PROXY))
	{
		if (g_options.defaultProxyPort == 0)
		{
			g_options.defaultProxyPort = htons(10080);
		}

		g_udpProxy.setEventHandler(g_pEventHandler);

		if (!g_udpProxy.init(g_options.proxyThreadCount))
		{
			nf_srv_free();
			return NF_STATUS_FAIL;
		}
	}

	return NF_STATUS_SUCCESS;
}

/**
* Free the driver
* @return void 
**/
NFSRVAPI_API void NFSRVAPI_NS 
nf_srv_free()
{
	if (!g_initialized)
		return;

	g_initialized = false;

	g_tcpProxy.free();
	g_udpProxy.free();

	SetEvent(g_stopEvent);

	if (g_hWorkThread != INVALID_HANDLE_VALUE)
	{
		WaitForSingleObject(g_hWorkThread.m_h, INFINITE);
		g_hWorkThread.Close();
	}

#if defined(_DEBUG) || defined(_RELEASE_LOG)
	DBGLogger::instance().free();
#endif

	g_hDevice.Close();

	::WSACleanup();
}

NFSRVAPI_API NF_STATUS NFSRVAPI_NS 
nf_srv_addRule(PNF_SRV_RULE pRule, int toHead)
{
	DWORD	dwBytesReturned;
	AutoLock lock(g_cs);

	if (g_hDevice == INVALID_HANDLE_VALUE)
		return NF_STATUS_NOT_INITIALIZED;

	if (pRule->action.tcpRedirectTo.port == 0)
	{
		pRule->action.tcpRedirectTo.port = g_tcpProxy.getPort();
	}

	if (DeviceIoControl(g_hDevice,
		toHead? NF_SRV_RULE_ADD_TO_HEAD : NF_SRV_RULE_ADD_TO_TAIL,
		(LPVOID)pRule, sizeof(*pRule),
		(LPVOID)NULL, 0,
		&dwBytesReturned, NULL))
	{
		return NF_STATUS_SUCCESS;
	}

	return NF_STATUS_FAIL;
}

NFSRVAPI_API NF_STATUS NFSRVAPI_NS 
nf_srv_deleteRules()
{
	DWORD	dwBytesReturned;
	AutoLock lock(g_cs);

	if (g_hDevice == INVALID_HANDLE_VALUE)
		return NF_STATUS_NOT_INITIALIZED;

	if (DeviceIoControl(g_hDevice,
		NF_SRV_RULE_CLEAR,
		(LPVOID)NULL, 0,
		(LPVOID)NULL, 0,
		&dwBytesReturned, NULL))
	{
		return NF_STATUS_SUCCESS;
	}

	return NF_STATUS_FAIL;
}

NFSRVAPI_API NF_STATUS NFSRVAPI_NS 
nf_srv_setRules(PNF_SRV_RULE pRules, int count)
{
	DWORD	dwBytesReturned;
	AutoLock lock(g_cs);

	if (g_hDevice == INVALID_HANDLE_VALUE)
		return NF_STATUS_NOT_INITIALIZED;

	if (!DeviceIoControl(g_hDevice,
		NF_SRV_CLEAR_TEMP_RULES,
		(LPVOID)NULL, 0,
		(LPVOID)NULL, 0,
		&dwBytesReturned, NULL))
	{
		return NF_STATUS_FAIL;
	}

	for (int i=0; i<count; i++)
	{
		if (pRules[i].action.tcpRedirectTo.port == 0)
		{
			pRules[i].action.tcpRedirectTo.port = g_tcpProxy.getPort();
		}

		if (!DeviceIoControl(g_hDevice,
			NF_SRV_ADD_TEMP_RULE,
			(LPVOID)&pRules[i], sizeof(NF_SRV_RULE),
			(LPVOID)NULL, 0,
			&dwBytesReturned, NULL))
		{
			return NF_STATUS_FAIL;
		}
	}

	if (!DeviceIoControl(g_hDevice,
		NF_SRV_SET_TEMP_RULES,
		(LPVOID)NULL, 0,
		(LPVOID)NULL, 0,
		&dwBytesReturned, NULL))
	{
		return NF_STATUS_FAIL;
	}

	return NF_STATUS_SUCCESS;
}



NFSRVAPI_API NF_STATUS NFSRVAPI_NS
nf_srv_addFlowCtl(NFSRVAPI_NS PNF_SRV_FLOWCTL_DATA pData, unsigned int * pFcHandle)
{
	DWORD	dwBytesReturned;
	AutoLock lock(g_cs);

	if (g_hDevice == INVALID_HANDLE_VALUE)
		return NF_STATUS_NOT_INITIALIZED;

	if (!pFcHandle || !pData)
		return NF_STATUS_FAIL;

	if (DeviceIoControl(g_hDevice,
		NF_SRV_ADD_FLOW_CTL,
		(LPVOID)pData, sizeof(*pData),
		(LPVOID)pFcHandle, sizeof(*pFcHandle),
		&dwBytesReturned, NULL) && (dwBytesReturned > 0))
	{
		if (*pFcHandle != 0)
		{
			return NF_STATUS_SUCCESS;
		}
	}

	return NF_STATUS_FAIL;
}

NFSRVAPI_API NF_STATUS NFSRVAPI_NS
nf_srv_deleteFlowCtl(unsigned int fcHandle)
{
	DWORD	dwBytesReturned;
	AutoLock lock(g_cs);

	if (g_hDevice == INVALID_HANDLE_VALUE)
		return NF_STATUS_NOT_INITIALIZED;

	if (DeviceIoControl(g_hDevice,
		NF_SRV_DELETE_FLOW_CTL,
		(LPVOID)&fcHandle, sizeof(fcHandle),
		(LPVOID)NULL, 0,
		&dwBytesReturned, NULL))
	{
		return NF_STATUS_SUCCESS;
	}

	return NF_STATUS_FAIL;
}

NFSRVAPI_API NF_STATUS NFSRVAPI_NS
nf_srv_modifyFlowCtl(unsigned int fcHandle, NFSRVAPI_NS PNF_SRV_FLOWCTL_DATA pData)
{
	DWORD	dwBytesReturned;
	NFSRVAPI_NS NF_SRV_FLOWCTL_MODIFY_DATA data;
	AutoLock lock(g_cs);

	if (!fcHandle || !pData)
		return NF_STATUS_FAIL;

	data.fcHandle = fcHandle;
	data.data = *pData;

	if (g_hDevice == INVALID_HANDLE_VALUE)
		return NF_STATUS_NOT_INITIALIZED;

	if (DeviceIoControl(g_hDevice,
		NF_SRV_MODIFY_FLOW_CTL,
		(LPVOID)&data, sizeof(data),
		(LPVOID)NULL, 0,
		&dwBytesReturned, NULL)) 
	{
		return NF_STATUS_SUCCESS;
	}

	return NF_STATUS_FAIL;
}

NFSRVAPI_API NF_STATUS NFSRVAPI_NS
nf_srv_getFlowCtlStat(unsigned int fcHandle, NFSRVAPI_NS PNF_SRV_FLOWCTL_STAT pStat)
{
	DWORD	dwBytesReturned;
	AutoLock lock(g_cs);

	if (g_hDevice == INVALID_HANDLE_VALUE)
		return NF_STATUS_NOT_INITIALIZED;

	if (!fcHandle || !pStat)
		return NF_STATUS_FAIL;

	if (DeviceIoControl(g_hDevice,
		NF_SRV_GET_FLOW_CTL_STAT,
		(LPVOID)&fcHandle, sizeof(fcHandle),
		(LPVOID)pStat, sizeof(*pStat),
		&dwBytesReturned, NULL) && (dwBytesReturned > 0))
	{
		return NF_STATUS_SUCCESS;
	}

	return NF_STATUS_FAIL;
}

NFSRVAPI_API NF_STATUS NFSRVAPI_NS
nf_srv_getDestinationAddress(PNF_ADDRESS srcAddress, PNF_ADDRESS dstAddress, char protocol)
{
	DWORD	dwBytesReturned;
	AutoLock lock(g_cs);

	if (g_hDevice == INVALID_HANDLE_VALUE)
		return NF_STATUS_NOT_INITIALIZED;

	if (!srcAddress || !dstAddress)
		return NF_STATUS_FAIL;

	if (protocol == IPPROTO_UDP)
	{
		NF_SRV_UDP_ADDRESSES addresses;
		addresses.srcAddress = *srcAddress;
		addresses.dstAddress = *dstAddress;

		if (DeviceIoControl(g_hDevice,
			NF_SRV_GET_UDP_DST_ADDRESS,
			(LPVOID)&addresses, sizeof(addresses),
			(LPVOID)dstAddress, sizeof(NF_ADDRESS),
			&dwBytesReturned, NULL) && (dwBytesReturned > 0))
		{
			return NF_STATUS_SUCCESS;
		}
	} else
	{
		if (DeviceIoControl(g_hDevice,
			NF_SRV_GET_TCP_DST_ADDRESS,
			(LPVOID)srcAddress, sizeof(NF_ADDRESS),
			(LPVOID)dstAddress, sizeof(NF_ADDRESS),
			&dwBytesReturned, NULL) && (dwBytesReturned > 0))
		{
			return NF_STATUS_SUCCESS;
		}
	}

	return NF_STATUS_FAIL;
}

NFSRVAPI_API NF_STATUS NFSRVAPI_NS
nf_srv_updateUDPDestinationAddress(PNF_ADDRESS srcAddress, PNF_ADDRESS dstAddress, PNF_ADDRESS newDstAddress)
{
	DWORD	dwBytesReturned;
	AutoLock lock(g_cs);

	if (g_hDevice == INVALID_HANDLE_VALUE)
		return NF_STATUS_NOT_INITIALIZED;

	if (!srcAddress || !dstAddress || !newDstAddress)
		return NF_STATUS_FAIL;

	NF_SRV_UDP_ADDRESSES_UPDATE addresses;
	addresses.srcAddress = *srcAddress;
	addresses.dstAddress = *dstAddress;
	addresses.newDstAddress = *newDstAddress;

	if (DeviceIoControl(g_hDevice,
		NF_SRV_UPDATE_UDP_DST_ADDRESS,
		(LPVOID)&addresses, sizeof(addresses),
		(LPVOID)NULL, 0,
		&dwBytesReturned, NULL))
	{
		return NF_STATUS_SUCCESS;
	}

	return NF_STATUS_FAIL;
}

NFSRVAPI_API NF_STATUS NFSRVAPI_NS
nf_srv_tcpSetConnectionState(NFAPI_NS ENDPOINT_ID id, int suspended)
{
	return g_tcpProxy.tcpSetState(id, suspended != 0)? NF_STATUS_SUCCESS : NF_STATUS_FAIL;
}

NFSRVAPI_API NF_STATUS NFSRVAPI_NS 
nf_srv_tcpPostSend(NFAPI_NS ENDPOINT_ID id, const char * buf, int len)
{
	return g_tcpProxy.tcpPostSend(id, buf, len)? NF_STATUS_SUCCESS : NF_STATUS_FAIL;
}

NFSRVAPI_API NF_STATUS NFSRVAPI_NS 
nf_srv_tcpPostReceive(NFAPI_NS ENDPOINT_ID id, const char * buf, int len)
{
	return g_tcpProxy.tcpPostReceive(id, buf, len)? NF_STATUS_SUCCESS : NF_STATUS_FAIL;
}

NFSRVAPI_API NF_STATUS NFSRVAPI_NS 
nf_srv_tcpClose(NFAPI_NS ENDPOINT_ID id)
{
	return g_tcpProxy.tcpClose(id)? NF_STATUS_SUCCESS : NF_STATUS_FAIL;
}

NFSRVAPI_API NF_STATUS NFSRVAPI_NS
nf_srv_tcpSetProxy(NFAPI_NS ENDPOINT_ID id, SRV_PROXY_TYPE proxyType, const char * proxyAddress, int proxyAddressLen, const char * userName, const char * userPassword)
{
	return g_tcpProxy.setProxy(id, (TcpProxy::PROXY_TYPE)proxyType, proxyAddress, proxyAddressLen, userName, userPassword)? NF_STATUS_SUCCESS : NF_STATUS_FAIL;
}

NFSRVAPI_API NF_STATUS NFSRVAPI_NS
nf_srv_getTCPConnInfo(NFAPI_NS ENDPOINT_ID id, NFAPI_NS PNF_TCP_CONN_INFO pConnInfo)
{
	return g_tcpProxy.getTCPConnInfo(id, pConnInfo)? NF_STATUS_SUCCESS : NF_STATUS_FAIL;
}

NFSRVAPI_API NF_STATUS NFSRVAPI_NS 
nf_srv_udpSetConnectionState(NFAPI_NS ENDPOINT_ID id, int suspended)
{
	return g_udpProxy.udpSetState(id, suspended != 0)? NF_STATUS_SUCCESS : NF_STATUS_FAIL;
}

NFSRVAPI_API NF_STATUS NFSRVAPI_NS 
nf_srv_udpPostSend(NFAPI_NS ENDPOINT_ID id, const unsigned char * remoteAddress, const char * buf, int len, NFAPI_NS PNF_UDP_OPTIONS options)
{
	return g_udpProxy.udpPostSend(id, remoteAddress, buf, len)? NF_STATUS_SUCCESS : NF_STATUS_FAIL;
}

NFSRVAPI_API NF_STATUS NFSRVAPI_NS 
nf_srv_udpPostReceive(NFAPI_NS ENDPOINT_ID id, const unsigned char * remoteAddress, const char * buf, int len, NFAPI_NS PNF_UDP_OPTIONS options)
{
	return g_udpProxy.udpPostReceive(id, remoteAddress, buf, len)? NF_STATUS_SUCCESS : NF_STATUS_FAIL;
}

NFSRVAPI_API NF_STATUS NFSRVAPI_NS
nf_srv_getUDPConnInfo(NFAPI_NS ENDPOINT_ID id, NFAPI_NS PNF_UDP_CONN_INFO pConnInfo)
{
	return g_udpProxy.getUDPConnInfo(id, pConnInfo)? NF_STATUS_SUCCESS : NF_STATUS_FAIL;
}

NFSRVAPI_API NF_STATUS NFSRVAPI_NS 
nf_srv_getUDPRemoteAddress(NFAPI_NS ENDPOINT_ID id, unsigned char * remoteAddress, int remoteAddressLen)
{
	return g_udpProxy.getUDPRemoteAddress(id, remoteAddress, remoteAddressLen)? NF_STATUS_SUCCESS : NF_STATUS_FAIL;
}

NFSRVAPI_API NF_STATUS NFSRVAPI_NS
nf_srv_udpSetProxy(NFAPI_NS ENDPOINT_ID id, SRV_PROXY_TYPE proxyType, 
		const char * proxyAddress, int proxyAddressLen,
		const char * userName, const char * userPassword)
{
	return g_udpProxy.setProxy(id, (SrvUdpProxy::PROXY_TYPE)proxyType, proxyAddress, proxyAddressLen, userName, userPassword)? NF_STATUS_SUCCESS : NF_STATUS_FAIL;
}

NFSRVAPI_API NF_STATUS NFSRVAPI_NS
nf_srv_setTimeout(NF_SRV_TIMEOUT_TYPE type, DWORD value)
{
	DWORD	dwBytesReturned;
	AutoLock lock(g_cs);

	if (g_hDevice == INVALID_HANDLE_VALUE)
		return NF_STATUS_NOT_INITIALIZED;

	if (type == NSTT_NAT_TCP_CLOSE)
	{
		g_tcpProxy.setTimeout(value);
	} else
	if (type == NSTT_NAT_UDP)
	{
		g_udpProxy.setTimeout(value);
	}

	NF_SRV_TIMEOUT nst;
	nst.type = type;
	nst.value = value;

	if (DeviceIoControl(g_hDevice,
		NF_SRV_SET_TIMEOUT,
		(LPVOID)&nst, sizeof(nst),
		(LPVOID)NULL, 0,
		&dwBytesReturned, NULL))
	{
		return NF_STATUS_SUCCESS;
	}

	return NF_STATUS_FAIL;
}

bool interfacesAdd(unsigned __int64 interfaceLuid, PNF_ADDRESS pAddress)
{
	DWORD	dwBytesReturned;
	AutoLock lock(g_cs);

	if (g_hDevice == INVALID_HANDLE_VALUE)
		return false;

	NF_SRV_INTERFACE_IP itf;
	itf.interfaceLuid = interfaceLuid;
	itf.address = *pAddress;

	if (DeviceIoControl(g_hDevice,
		NF_SRV_INTERFACE_ADD,
		(LPVOID)&itf, sizeof(itf),
		(LPVOID)NULL, 0,
		&dwBytesReturned, NULL))
	{
		return true;
	}

	return false;
}

bool interfacesClear(unsigned __int64 interfaceLuid, PNF_ADDRESS pAddress)
{
	DWORD	dwBytesReturned;
	AutoLock lock(g_cs);

	if (g_hDevice == INVALID_HANDLE_VALUE)
		return false;

	if (DeviceIoControl(g_hDevice,
		NF_SRV_INTERFACE_CLEAR,
		(LPVOID)NULL, 0,
		(LPVOID)NULL, 0,
		&dwBytesReturned, NULL))
	{
		return true;
	}

	return false;
}

static void updateInterfaceAddresses()
{
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;
    unsigned int i = 0;
    ULONG flags = 0;
    ULONG family = AF_UNSPEC;
    LPVOID lpMsgBuf = NULL;
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    ULONG outBufLen = 0;
    ULONG Iterations = 0;
    PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
    PIP_ADAPTER_UNICAST_ADDRESS pUnicast = NULL;

    outBufLen = 16 * 1024;

    do {

        pAddresses = (IP_ADAPTER_ADDRESSES *) malloc(outBufLen);
        if (pAddresses == NULL) 
		{
			return;
        }

        dwRetVal = GetAdaptersAddresses(family, flags, NULL, pAddresses, &outBufLen);

        if (dwRetVal == ERROR_BUFFER_OVERFLOW) 
		{
            free(pAddresses);
            pAddresses = NULL;
        } else 
		{
            break;
        }

        Iterations++;

    } while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (Iterations < 3));

    if (dwRetVal == NO_ERROR) 
	{
        pCurrAddresses = pAddresses;

		while (pCurrAddresses) 
		{
            pUnicast = pCurrAddresses->FirstUnicastAddress;

			while (pUnicast != NULL)
			{
				NF_ADDRESS addr = {0};
				addr.ipFamily = (unsigned char)pUnicast->Address.lpSockaddr->sa_family;
				addr.port = 0;
				if (addr.ipFamily == AF_INET)
				{
					addr.ip.v4 = ((sockaddr_in*)pUnicast->Address.lpSockaddr)->sin_addr.S_un.S_addr;
				} else
				{
					memcpy(addr.ip.v6, ((sockaddr_in6*)pUnicast->Address.lpSockaddr)->sin6_addr.u.Byte, 16);
				}

				interfacesAdd(pCurrAddresses->Luid.Value, &addr);

				pUnicast = pUnicast->Next;
			}

            pCurrAddresses = pCurrAddresses->Next;
        }
    }

    if (pAddresses) 
	{
        free(pAddresses);
    }
}

bool udpPortAdd(unsigned short port, int ipFamily)
{
	DWORD	dwBytesReturned;
	AutoLock lock(g_cs);

	if (g_hDevice == INVALID_HANDLE_VALUE)
		return false;

	if (DeviceIoControl(g_hDevice,
		(ipFamily == AF_INET)? NF_SRV_ADD_UDP_PORT_IPv4 : NF_SRV_ADD_UDP_PORT_IPv6,
		(LPVOID)&port, sizeof(port),
		(LPVOID)NULL, 0,
		&dwBytesReturned, NULL))
	{
		return true;
	}

	return false;
}

bool udpPortsClear()
{
	DWORD	dwBytesReturned;
	AutoLock lock(g_cs);

	if (g_hDevice == INVALID_HANDLE_VALUE)
		return false;

	if (DeviceIoControl(g_hDevice,
		NF_SRV_CLEAR_UDP_PORTS,
		(LPVOID)NULL, 0,
		(LPVOID)NULL, 0,
		&dwBytesReturned, NULL))
	{
		return true;
	}

	return false;
}



static unsigned WINAPI nf_workThread(void* )
{
	OVERLAPPED overlap;
	DWORD ret;
	HANDLE hand = NULL;

	overlap.hEvent = WSACreateEvent();

	for (;;)
	{
		ret = NotifyAddrChange(&hand, &overlap);

		if (ret != NO_ERROR)
		{
			if (WSAGetLastError() != WSA_IO_PENDING)
			{
				break;
			}
		}

		for (;;)
		{
			HANDLE events[] = { overlap.hEvent, g_stopEvent };
		
			ret = WaitForMultipleObjects(
							sizeof(events) / sizeof(events[0]),
							events, 
							FALSE,
							INFINITE);


			if (ret == WAIT_OBJECT_0 )
			{
				break;
			} else
			{
				CancelIPChangeNotify(&overlap);
				return 0;
			}
		}

		updateInterfaceAddresses();
	}

	return 0;
}

