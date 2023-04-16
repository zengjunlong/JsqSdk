//
// 	NetFilterSDK 
// 	Copyright (C) 2017 Vitaly Sidorov
//	All rights reserved.
//
//	This file is a part of the NetFilter SDK.
//	The code and information is provided "as-is" without
//	warranty of any kind, either expressed or implied.
//


#ifndef _NFSRVAPI_H
#define _NFSRVAPI_H

#include "nfevents.h"

#ifdef _NFSRVAPI_STATIC_LIB
	#define NFSRVAPI_API
#else
	#ifdef NFSRVAPI_EXPORTS
	#define NFSRVAPI_API __declspec(dllexport) 
	#else
	#define NFSRVAPI_API __declspec(dllimport) 
	#endif
#endif

#ifndef _C_API
	namespace nfsrvapi
	{
		#define NFSRVAPI_NS	nfsrvapi::
		#define NFSRVAPI_CC	
	
#else // _C_API
	#define NFSRVAPI_CC __cdecl
	#define NFSRVAPI_NS
	#ifdef __cplusplus
	extern "C" 
	{
	#endif
#endif // _C_API

#include "nfsrvext.h"

typedef enum _NF_SRV_FLAGS
{
	NSF_NONE = 0,
	NSF_DONT_START_LOCAL_TCP_PROXY = 1,
	NSF_DONT_START_LOCAL_UDP_PROXY = 2,
	NSF_USE_REAL_UDP_RECV_ADDRESS = 4
} NF_SRV_FLAGS;

typedef struct _NF_SRV_OPTIONS
{
	unsigned int		flags;
	unsigned short		defaultProxyPort;
	unsigned int		proxyThreadCount;
} NF_SRV_OPTIONS, *PNF_SRV_OPTIONS;

enum SRV_PROXY_TYPE
{
	SRVPROXY_NONE,
	SRVPROXY_SOCKS5
};


NFSRVAPI_API NF_STATUS NFSRVAPI_CC 
nf_srv_init(const char * driverName, NFAPI_NS NF_EventHandler * pEventHandler, PNF_SRV_OPTIONS options);

NFSRVAPI_API void NFSRVAPI_CC 
nf_srv_free();

NFSRVAPI_API NF_STATUS NFSRVAPI_CC
nf_srv_registerDriver(const char * driverName);

NFSRVAPI_API NF_STATUS NFSRVAPI_CC
nf_srv_unRegisterDriver(const char * driverName);

NFSRVAPI_API NF_STATUS NFSRVAPI_CC 
nf_srv_addRule(PNF_SRV_RULE pRule, int toHead);

NFSRVAPI_API NF_STATUS NFSRVAPI_CC 
nf_srv_deleteRules();

NFSRVAPI_API NF_STATUS NFSRVAPI_CC 
nf_srv_setRules(PNF_SRV_RULE pRules, int count);

NFSRVAPI_API NF_STATUS NFSRVAPI_CC
nf_srv_getDestinationAddress(NFSRVAPI_NS PNF_ADDRESS srcAddress, NFSRVAPI_NS PNF_ADDRESS dstAddress, char protocol);

NFSRVAPI_API NF_STATUS NFSRVAPI_CC
nf_srv_updateUDPDestinationAddress(PNF_ADDRESS srcAddress, PNF_ADDRESS dstAddress, PNF_ADDRESS newDstAddress);

NFSRVAPI_API NF_STATUS NFSRVAPI_CC
nf_srv_addFlowCtl(NFSRVAPI_NS PNF_SRV_FLOWCTL_DATA pData, unsigned int * pFcHandle);

NFSRVAPI_API NF_STATUS NFSRVAPI_CC
nf_srv_deleteFlowCtl(unsigned int fcHandle);

NFSRVAPI_API NF_STATUS NFSRVAPI_CC
nf_srv_modifyFlowCtl(unsigned int fcHandle, NFSRVAPI_NS PNF_SRV_FLOWCTL_DATA pData);

NFSRVAPI_API NF_STATUS NFSRVAPI_CC
nf_srv_getFlowCtlStat(unsigned int fcHandle, NFSRVAPI_NS PNF_SRV_FLOWCTL_STAT pStat);

NFSRVAPI_API NF_STATUS NFSRVAPI_CC 
nf_srv_tcpSetConnectionState(NFAPI_NS ENDPOINT_ID id, int suspended);

NFSRVAPI_API NF_STATUS NFSRVAPI_CC 
nf_srv_tcpPostSend(NFAPI_NS ENDPOINT_ID id, const char * buf, int len);

NFSRVAPI_API NF_STATUS NFSRVAPI_CC 
nf_srv_tcpPostReceive(NFAPI_NS ENDPOINT_ID id, const char * buf, int len);

NFSRVAPI_API NF_STATUS NFSRVAPI_CC 
nf_srv_tcpClose(NFAPI_NS ENDPOINT_ID id);

NFSRVAPI_API NF_STATUS NFSRVAPI_CC 
nf_srv_tcpSetProxy(NFAPI_NS ENDPOINT_ID id, SRV_PROXY_TYPE proxyType, const char * proxyAddress, int proxyAddressLen, const char * userName, const char * userPassword);

NFSRVAPI_API NF_STATUS NFSRVAPI_CC 
nf_srv_getTCPConnInfo(NFAPI_NS ENDPOINT_ID id, NFAPI_NS PNF_TCP_CONN_INFO pConnInfo);

NFSRVAPI_API NF_STATUS NFSRVAPI_CC 
nf_srv_udpSetConnectionState(NFAPI_NS ENDPOINT_ID id, int suspended);

NFSRVAPI_API NF_STATUS NFSRVAPI_CC 
nf_srv_udpPostSend(NFAPI_NS ENDPOINT_ID id, const unsigned char * remoteAddress, const char * buf, int len, NFAPI_NS PNF_UDP_OPTIONS options);

NFSRVAPI_API NF_STATUS NFSRVAPI_CC 
nf_srv_udpPostReceive(NFAPI_NS ENDPOINT_ID id, const unsigned char * remoteAddress, const char * buf, int len, NFAPI_NS PNF_UDP_OPTIONS options);

NFSRVAPI_API NF_STATUS NFSRVAPI_CC 
nf_srv_getUDPConnInfo(NFAPI_NS ENDPOINT_ID id, NFAPI_NS PNF_UDP_CONN_INFO pConnInfo);

NFSRVAPI_API NF_STATUS NFSRVAPI_CC 
nf_srv_getUDPRemoteAddress(NFAPI_NS ENDPOINT_ID id, unsigned char * remoteAddress, int remoteAddressLen);

NFSRVAPI_API NF_STATUS NFSRVAPI_CC
nf_srv_udpSetProxy(NFAPI_NS ENDPOINT_ID id, SRV_PROXY_TYPE proxyType, 
		const char * proxyAddress, int proxyAddressLen,
		const char * userName, const char * userPassword);

NFSRVAPI_API NF_STATUS NFSRVAPI_CC 
nf_srv_setTimeout(NF_SRV_TIMEOUT_TYPE type, DWORD value);



#ifdef __cplusplus
}
#endif


#endif // _NFSRVAPI_H