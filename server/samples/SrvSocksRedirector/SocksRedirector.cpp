/**
*	The sample redirects TCP and UDP to the specified SOCKS5 proxy
**/

#include "stdafx.h"
#include <crtdbg.h>
#include <string>
#include "nfsrvapi.h"

using namespace nfapi;
using namespace nfsrvapi;

// Change this string after renaming and registering the driver under different name
#define NFDRIVER_NAME "nfsrvfilter"

// Forward declarations
void printConnInfo(bool connected, ENDPOINT_ID id, PNF_TCP_CONN_INFO pConnInfo);
void printAddrInfo(bool created, ENDPOINT_ID id, PNF_UDP_CONN_INFO pConnInfo);

unsigned char	g_proxyAddress[NF_MAX_ADDRESS_LENGTH];
std::string g_userName;
std::string g_userPassword;

struct IPSubNet
{
	DWORD ip;
	DWORD mask;
};

IPSubNet privateSubNets[] = {
	{ inet_addr("192.168.0.0"), inet_addr("255.255.0.0") },
	{ inet_addr("172.16.0.0"), inet_addr("255.240.0.0") },
	{ inet_addr("10.0.0.0"), inet_addr("255.0.0.0") },
};

bool isPrivateNetworkAddress(sockaddr * pAddress)
{
	if (pAddress->sa_family == AF_INET)
	{
		DWORD ipAddr = ((sockaddr_in *)pAddress)->sin_addr.S_un.S_addr;
		
		for (int i=0; i<sizeof(privateSubNets)/sizeof(privateSubNets[0]); i++)
		{
			if ((ipAddr & privateSubNets[i].mask) == privateSubNets[i].ip)
			{
				return true;
			}
		}
	} else
	{
		sockaddr_in6 * pAddr = (sockaddr_in6 *)pAddress;
		if (pAddr->sin6_addr.u.Byte[0] == 0xFC)
			return true;
	}

	return false;
}

//
//	API events handler
//
class EventHandler : public NF_EventHandler
{
	virtual void threadStart()
	{
		printf("threadStart\n");
		fflush(stdout);

		// Initialize thread specific stuff
	}

	virtual void threadEnd()
	{
		printf("threadEnd\n");

		// Uninitialize thread specific stuff
	}
	
	//
	// TCP events
	//

	virtual void tcpConnectRequest(ENDPOINT_ID id, PNF_TCP_CONN_INFO pConnInfo)
	{
		printf("tcpConnectRequest id=%I64u\n", id);

		if (isPrivateNetworkAddress((sockaddr*)pConnInfo->remoteAddress))
			return;

		nf_srv_tcpSetProxy(id, SRV_PROXY_TYPE::SRVPROXY_SOCKS5, 
			(char*)g_proxyAddress, 
			(((sockaddr*)g_proxyAddress)->sa_family == AF_INET6)? sizeof(sockaddr_in6) : sizeof(sockaddr_in),
			g_userName.c_str(),
			g_userPassword.c_str());
	}

	virtual void tcpConnected(ENDPOINT_ID id, PNF_TCP_CONN_INFO pConnInfo)
	{
		printConnInfo(true, id, pConnInfo);
		fflush(stdout);
	}

	virtual void tcpClosed(ENDPOINT_ID id, PNF_TCP_CONN_INFO pConnInfo)
	{
		printConnInfo(false, id, pConnInfo);
		fflush(stdout);
	}

	virtual void tcpReceive(ENDPOINT_ID id, const char * buf, int len)
	{	
		printf("tcpReceive id=%I64u len=%d\n", id, len);
		fflush(stdout);

		// Send the packet to application
		nf_srv_tcpPostReceive(id, buf, len);
	}

	virtual void tcpSend(ENDPOINT_ID id, const char * buf, int len)
	{
		printf("tcpSend id=%I64u len=%d\n", id, len);
		fflush(stdout);

		// Send the packet to server
		nf_srv_tcpPostSend(id, buf, len);
	}

	virtual void tcpCanReceive(ENDPOINT_ID id)
	{
		printf("tcpCanReceive id=%I64d\n", id);
		fflush(stdout);
	}

	virtual void tcpCanSend(ENDPOINT_ID id)
	{
		printf("tcpCanSend id=%I64d\n", id);
		fflush(stdout); 
	}
	
	//
	// UDP events
	//

	virtual void udpCreated(ENDPOINT_ID id, PNF_UDP_CONN_INFO pConnInfo)
	{
		printAddrInfo(true, id, pConnInfo);
		fflush(stdout);

		unsigned char remoteAddress[NF_MAX_ADDRESS_LENGTH];

		if (!nf_srv_getUDPRemoteAddress(id, remoteAddress, sizeof(remoteAddress)) == NF_STATUS_SUCCESS)
			return;

		if (isPrivateNetworkAddress((sockaddr*)remoteAddress))
			return;

		nf_srv_udpSetProxy(id, SRV_PROXY_TYPE::SRVPROXY_SOCKS5, 
			(char*)g_proxyAddress, 
			(((sockaddr*)g_proxyAddress)->sa_family == AF_INET6)? sizeof(sockaddr_in6) : sizeof(sockaddr_in),
			g_userName.c_str(),
			g_userPassword.c_str());

	}

	virtual void udpConnectRequest(ENDPOINT_ID id, PNF_UDP_CONN_REQUEST pConnReq)
	{
		printf("udpConnectRequest id=%I64u\n", id);
	}

	virtual void udpClosed(ENDPOINT_ID id, PNF_UDP_CONN_INFO pConnInfo)
	{
		printAddrInfo(false, id, pConnInfo);
		fflush(stdout);
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

		printf("udpReceive id=%I64u len=%d dst=%s\n", id, len, remoteAddr);
		fflush(stdout);

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

		printf("udpSend id=%I64u len=%d dst=%s\n", id, len, remoteAddr);
		fflush(stdout);

		// Send the packet to server
		nf_srv_udpPostSend(id, remoteAddress, buf, len, options);
	}

	virtual void udpCanReceive(ENDPOINT_ID id)
	{
		printf("udpCanReceive id=%I64d\n", id);
		fflush(stdout);
	}

	virtual void udpCanSend(ENDPOINT_ID id)
	{
		printf("udpCanSend id=%I64d\n", id);
		fflush(stdout);
	}
};

void usage()
{
	printf("Usage: SrvSocksRedirector.exe -r IP:port [-user <proxy user name>] [-password <proxy user password>]\n" \
		"IP:port : tunnel TCP/UDP traffic via SOCKS proxy using specified IP:port\n" \
		"user, password : optional proxy login and password\n" \
		);
	exit(0);
}

int main(int argc, char* argv[])
{
	EventHandler eh;
	WSADATA wsaData;

	// This call is required for WSAAddressToString
    ::WSAStartup(MAKEWORD(2, 2), &wsaData);

#ifdef _DEBUG
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
	_CrtSetReportMode( _CRT_ERROR, _CRTDBG_MODE_DEBUG);
#endif

	if (argc < 2)
		usage();

	for (int i=1; i < argc; i += 2)
	{
		if (stricmp(argv[i], "-r") == 0)
		{
			int err, addrLen;

			addrLen = sizeof(g_proxyAddress);
			err = WSAStringToAddress(argv[i+1], AF_INET, NULL, (LPSOCKADDR)&g_proxyAddress, &addrLen);
			if (err < 0)
			{
				addrLen = sizeof(g_proxyAddress);
				err = WSAStringToAddress(argv[i+1], AF_INET6, NULL, (LPSOCKADDR)&g_proxyAddress, &addrLen);
				if (err < 0)
				{
					printf("WSAStringToAddress failed, err=%d", WSAGetLastError());
					usage();
				}
			}

			printf("Redirect to: %s\n", argv[i+1]);
		} else
		if (stricmp(argv[i], "-user") == 0)
		{
			g_userName = argv[i+1];

			printf("User name: %s\n", argv[i+1]);
		} else
		if (stricmp(argv[i], "-password") == 0)
		{
			g_userPassword = argv[i+1];

			printf("User password: %s\n", argv[i+1]);
		} else
		{
			usage();
		}
	}

	NF_SRV_OPTIONS options;

	memset(&options, 0, sizeof(options));
	options.defaultProxyPort = htons(10080);
	options.proxyThreadCount = 0;

	// Initialize the library and start filtering thread
	if (nf_srv_init(NFDRIVER_NAME, &eh, &options) != NF_STATUS_SUCCESS)
	{
		printf("Failed to connect to driver");
		return -1;
	}

	// Filter TCP/UDP
	NF_SRV_RULE rule;

	memset(&rule, 0, sizeof(rule));

	rule.action.filteringFlag = NF_FILTER;

	nf_srv_addRule(&rule, FALSE);

	printf("Press enter to stop...\n\n");

	getchar();

	// Free the library
	nf_srv_free();

	::WSACleanup();

	return 0;
}

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
		printf("tcpConnected id=%I64u flag=%d direction=%s src=%s dst=%s\n",
			id,
			pConnInfo->filteringFlag,
			(pConnInfo->direction == NF_D_IN)? "in" : ((pConnInfo->direction == NF_D_OUT)? "out" : "none"),
			localAddr, 
			remoteAddr);
	} else
	{
		printf("tcpClosed id=%I64u flag=%d direction=%s src=%s dst=%s\n",
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
		printf("udpCreated id=%I64u src=%s\n",
			id,
			localAddr);
	} else
	{
		printf("udpClosed id=%I64u src=%s\n",
			id,
			localAddr);
	}

}
