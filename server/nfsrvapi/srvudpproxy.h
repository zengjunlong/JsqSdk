//
// 	NetFilterSDK 
// 	Copyright (C) Vitaly Sidorov
//	All rights reserved.
//
//	This file is a part of the NetFilter SDK.
//	The code and information is provided "as-is" without
//	warranty of any kind, either expressed or implied.
//

#pragma once

#include <set>
#include <map>
#include <vector>
#include <list>
#include <mswsock.h>
#include "sync.h"
#include "socksdefs.h"
#include "iocp.h"
#include "nfsrvapi.h"

NFSRVAPI_NS NF_SRV_FLAGS nf_srv_getFlags();
bool udpPortAdd(unsigned short port, int ipFamily);
bool udpPortsClear();

namespace SrvUdpProxy
{

#define UDP_PACKET_SIZE 65536
#define IN_SOCKET true
#define OUT_SOCKET false

struct DATA_PACKET
{
	DATA_PACKET()
	{
		buffer.len = 0;
		buffer.buf = NULL;
	}
	DATA_PACKET(char * buf, int len)
	{
		if (len > 0)
		{
			buffer.buf = new char[len];
			buffer.len = len;

			if (buf)
			{
				memcpy(buffer.buf, buf, len);
			}
		} else
		{
			buffer.buf = NULL;
			buffer.len = 0;
		}	
	}
	
	WSABUF & operator ()()
	{
		return buffer;
	}

	void free()
	{
		if (buffer.buf)
		{
			delete[] buffer.buf;
			buffer.buf = NULL;
			buffer.len = 0;
		}
	}

	WSABUF	buffer;
};

typedef std::vector<DATA_PACKET> tPacketList;

enum OV_TYPE
{
	OVT_CONNECT,
	OVT_TCP_SEND,
	OVT_TCP_RECEIVE,
	OVT_UDP_LISTEN,
	OVT_UDP_SEND,
	OVT_UDP_RECEIVE,
	OVT_UDP_CLOSE
};

struct OV_DATA
{
	OV_DATA()
	{
		memset(&ol, 0, sizeof(ol));
	}
	~OV_DATA()
	{
		for (tPacketList::iterator it = packetList.begin(); it != packetList.end(); it++)
		{
			it->free();
		}
 	}

	OVERLAPPED	ol;
	LIST_ENTRY	entry;
	LIST_ENTRY	entryEventList;
	NFAPI_NS ENDPOINT_ID id;
	OV_TYPE		type;
	tPacketList packetList;

	char		remoteAddress[NF_MAX_ADDRESS_LENGTH];
	int			remoteAddressLen;

	SOCKET	socket;
	DWORD	dwTransferred;
	int		error;
};

enum PROXY_STATE
{
	PS_NONE,
	PS_AUTH,
	PS_AUTH_NEGOTIATION,
	PS_UDP_ASSOC,
	PS_CONNECT,
	PS_CONNECTED,
	PS_ERROR,
	PS_CLOSED
};

enum PROXY_TYPE
{
	PROXY_NONE,
	PROXY_SOCKS5
};

struct UDP_SOCKET_DATA
{
	UDP_SOCKET_DATA()
	{
		socket = INVALID_SOCKET;
		receiveInProgress = false;
	}
	~UDP_SOCKET_DATA()
	{
		if (socket != INVALID_SOCKET)
		{
			closesocket(socket);
		}
	}

	SOCKET	socket;
	bool	receiveInProgress;
};

struct UDP_FLOW_INFO
{
	UDP_FLOW_INFO()
	{
		memset(remoteAddress, 0, sizeof(remoteAddress));
	}
	~UDP_FLOW_INFO()
	{
	}

	char		remoteAddress[NF_MAX_ADDRESS_LENGTH];
	int			remoteAddressLen;
};


struct UDP_FLOW
{
	UDP_FLOW()
	{
	}
	~UDP_FLOW()
	{
		for (tPacketList::iterator it = udpSendPackets.begin(); it != udpSendPackets.end(); it++)
		{
			it->free();
		}
	}

	UDP_FLOW_INFO	info;
	UDP_SOCKET_DATA	inUdpSocket;
	tPacketList		udpSendPackets;
};

struct PROXY_DATA
{
	PROXY_DATA()
	{
		id = 0;
		proxyState = PS_NONE;
		proxyType = PROXY_NONE;
		suspended = false;
		offline = false;
		memset(&udpConnInfo, 0, sizeof(udpConnInfo));
		tcpSocket = INVALID_SOCKET;
		refCount = 1;
	}
	~PROXY_DATA()
	{
		if (tcpSocket != INVALID_SOCKET)
		{
			shutdown(tcpSocket, SD_BOTH);
			closesocket(tcpSocket);
		}

		for (tFlowList::iterator it = flowList.begin(); it != flowList.end(); it++)
		{
			delete *it;
		}
	}

	bool getUdpFlow(const char * remoteAddress, int remoteAddressLen, UDP_FLOW ** pFlow)
	{
		for (tFlowList::iterator it = flowList.begin(); it != flowList.end(); it++)
		{
			if (memcmp((*it)->info.remoteAddress, remoteAddress, remoteAddressLen) == 0)
			{
				*pFlow = *it;
				return true;
			}
		}
		return false;
	}

	bool getUdpFlow(SOCKET s, UDP_FLOW ** pFlow)
	{
		for (tFlowList::iterator it = flowList.begin(); it != flowList.end(); it++)
		{
			if ((*it)->inUdpSocket.socket == s)
			{
				*pFlow = *it;
				return true;
			}
		}
		return false;
	}

	NFAPI_NS ENDPOINT_ID id;

	UDP_SOCKET_DATA		outUdpSocket;

	SOCKET				tcpSocket;

	NFAPI_NS NF_UDP_CONN_INFO udpConnInfo;

	PROXY_STATE			proxyState;
	PROXY_TYPE			proxyType;

	char		proxyAddress[NF_MAX_ADDRESS_LENGTH];
	int			proxyAddressLen;

	std::string	userName;
	std::string	userPassword;

	typedef std::list<UDP_FLOW*> tFlowList;
	tFlowList	flowList;

	bool	suspended;
	bool	offline;
	
	DWORD	ts;

	int		refCount;
	AutoCriticalSection lock;
};


class UDPProxy : public IOCPHandler, public ThreadJobSource
{
public:
	UDPProxy()
	{
		m_pPFEventHandler = NULL;
		m_ipv4Available = false;
		m_ipv6Available = false;
		m_udpListenSocketsPoolSize = 20;
	}

	~UDPProxy()
	{
	}

	bool isIPFamilyAvailable(int ipFamily)
	{
		switch (ipFamily)
		{
		case AF_INET:
			return m_ipv4Available;
		case AF_INET6:
			return m_ipv6Available;
		}
		return false;
	}

	bool init(int threadCount = 0)
	{
		if (!initExtensions())
			return false;

		if (!m_service.init(this))
			return false;

		if (!m_pool.init(threadCount, this))
			return false;

		m_timeout = 20 * 1000;

		InitializeListHead(&m_ovDataList);
		m_ovDataCounter = 0;

		InitializeListHead(&m_eventList);
		InitializeListHead(&m_listenEventList);

		m_connId = 0;

		if (!initUdpSocketPool())
		{
			DbgPrint("UDPProxy::init Unable to add UDP listening sockets");
			free();
			return false;
		}

		ResetEvent(m_stopEvent);

		HANDLE hThread = (HANDLE)_beginthreadex(0, 0,
						 _workerThread,
						 (LPVOID)this,
						 0,
						 NULL);
	
		if (hThread != 0)
		{
			m_workerThread.Attach(hThread);
		}

		return true;
	}

	void free()
	{
		if (m_workerThread != INVALID_HANDLE_VALUE)
		{
			SetEvent(m_stopEvent);
			WaitForSingleObject(m_workerThread, INFINITE);
			m_workerThread.Close();
		}

		m_service.free();
		m_pool.free();

		InitializeListHead(&m_eventList);
		InitializeListHead(&m_listenEventList);

		PLIST_ENTRY p;
		OV_DATA * pov;
		while (!IsListEmpty(&m_ovDataList))
		{
			p = RemoveHeadList(&m_ovDataList);
			pov = CONTAINING_RECORD(p, OV_DATA, entry);
			deleteOV_DATA(pov);
		}

		while (!m_socketMap.empty())
		{
			tSocketMap::iterator it = m_socketMap.begin();
			delete it->second;
			m_socketMap.erase(it);
		}

		udpPortsClear();

		while (!m_listenSocketsIPv4.empty())
		{
			tUdpListenSockets::iterator it = m_listenSocketsIPv4.begin();
			closesocket(*it);
			m_listenSocketsIPv4.erase(it);
		}

		while (!m_listenSocketsIPv6.empty())
		{
			tUdpListenSockets::iterator it = m_listenSocketsIPv6.begin();
			closesocket(*it);
			m_listenSocketsIPv6.erase(it);
		}

		m_pPFEventHandler = NULL;
		m_ipv4Available = false;
		m_ipv6Available = false;
	}

	void setEventHandler(NFAPI_NS NF_EventHandler * pEventHandler)
	{
		m_pPFEventHandler = pEventHandler;
	}

	void setTimeout(DWORD value)
	{
		AutoLock lock(m_cs);

		if (value < 5)
			value = 5;

		m_timeout = value * 1000;
	}

	bool setProxy(NFAPI_NS ENDPOINT_ID id, PROXY_TYPE proxyType, 
		const char * proxyAddress, int proxyAddressLen,
		const char * userName = NULL, const char * userPassword = NULL)
	{
		DbgPrint("UDPProxy::setProxy[%I64u], type=%d", id, proxyType);

		if (id == 0)
		{
			if (proxyAddress)
			{
				memcpy(m_proxyAddress, proxyAddress, 
					(proxyAddressLen < sizeof(m_proxyAddress))? proxyAddressLen : sizeof(m_proxyAddress));
				m_proxyAddressLen = proxyAddressLen;
				m_proxyType = proxyType;
				
				if (userName)
				{
					m_userName = userName;
				}
				if (userPassword)
				{
					m_userPassword = userPassword;
				}
			} else
			{
				m_proxyType = PROXY_NONE;
				m_proxyAddressLen = 0;
				m_userName = "";
				m_userPassword = "";
			}

			return true;
		}

		AutoProxyData pd(this, id);
		if (!pd)
			return false;

		if (proxyAddress)
		{
			memcpy(pd->proxyAddress, proxyAddress, 
				(proxyAddressLen < sizeof(pd->proxyAddress))? proxyAddressLen : sizeof(pd->proxyAddress));
			pd->proxyAddressLen = proxyAddressLen;
			pd->proxyType = proxyType;

			if (userName)
			{
				pd->userName = userName;
			}
			if (userPassword)
			{
				pd->userPassword = userPassword;
			}
		} else
		{
			pd->proxyType = PROXY_NONE;
			pd->proxyAddressLen = 0;
			pd->userName = "";
			pd->userPassword = "";
		}

		return true;
	}

	bool udpPostSend(NFAPI_NS ENDPOINT_ID id, const unsigned char * remoteAddress, const char * buf, int len)
	{
		DbgPrint("UDPProxy::udpPostSend[%I64u], len=%d", id, len);

		AutoProxyData pd(this, id);
		if (!pd)
			return false;

		if (pd->offline)
		{
			return true;
		}

		if (pd->proxyType != PROXY_NONE &&
			pd->proxyState != PS_CONNECTED)
		{
			if (len > 0)
			{
				UDP_FLOW * pFlow = NULL;

				if (!pd->getUdpFlow((char*)remoteAddress, 
					(((sockaddr*)remoteAddress)->sa_family == AF_INET)? sizeof(sockaddr_in) : sizeof(sockaddr_in6),
					&pFlow))
				{
					return false;
				}

				pFlow->udpSendPackets.push_back(DATA_PACKET((char*)buf, len));
			}
			return true;
		}

		tPacketList packetList;
		packetList.push_back(DATA_PACKET((char*)buf, len));

		startUdpSendOut(pd, packetList,
			(char*)remoteAddress, 
			(((sockaddr*)remoteAddress)->sa_family == AF_INET)? sizeof(sockaddr_in) : sizeof(sockaddr_in6));

		startUdpReceiveOut(pd);

		return true;
	}

	bool udpPostReceive(NFAPI_NS ENDPOINT_ID id, const unsigned char * remoteAddress, const char * buf, int len)
	{
		DbgPrint("UDPProxy::udpPostReceive[%I64u], len=%d", id, len);
		AutoProxyData pd(this, id);
		if (!pd)
			return false;

		UDP_FLOW * pFlow = NULL;

		if (!pd->getUdpFlow((char*)remoteAddress, 
			(((sockaddr*)remoteAddress)->sa_family == AF_INET)? sizeof(sockaddr_in) : sizeof(sockaddr_in6),
			&pFlow))
		{
			return false;
		}

		if (nf_srv_getFlags() & NFSRVAPI_NS NSF_USE_REAL_UDP_RECV_ADDRESS)
		if (memcmp(pFlow->info.remoteAddress, remoteAddress, NF_MAX_ADDRESS_LENGTH) != 0)
		{
			NFSRVAPI_NS NF_ADDRESS srcAddress = {0}, 
				dstAddress = {0},
				newDstAddress = {0};
			
			if (pd->udpConnInfo.ip_family == AF_INET)
			{
				sockaddr_in * pAddr;
				
				pAddr = (sockaddr_in *)pd->udpConnInfo.localAddress;

				srcAddress.ipFamily = AF_INET;
				srcAddress.ip.v4 = pAddr->sin_addr.S_un.S_addr;
				srcAddress.port = pAddr->sin_port;

				pAddr = (sockaddr_in *)pFlow->info.remoteAddress;

				dstAddress.ipFamily = AF_INET;
				dstAddress.ip.v4 = pAddr->sin_addr.S_un.S_addr;
				dstAddress.port = pAddr->sin_port;

				pAddr = (sockaddr_in *)remoteAddress;

				newDstAddress.ipFamily = AF_INET;
				newDstAddress.ip.v4 = pAddr->sin_addr.S_un.S_addr;
				newDstAddress.port = pAddr->sin_port;
			} else
			{
				sockaddr_in6 * pAddr;
				
				pAddr = (sockaddr_in6 *)pd->udpConnInfo.localAddress;

				srcAddress.ipFamily = AF_INET6;
				memcpy(srcAddress.ip.v6, &pAddr->sin6_addr, NF_MAX_IP_ADDRESS_LENGTH);
				srcAddress.port = pAddr->sin6_port;

				pAddr = (sockaddr_in6 *)pFlow->info.remoteAddress;

				dstAddress.ipFamily = AF_INET6;
				memcpy(dstAddress.ip.v6, &pAddr->sin6_addr, NF_MAX_IP_ADDRESS_LENGTH);
				dstAddress.port = pAddr->sin6_port;

				pAddr = (sockaddr_in6 *)remoteAddress;

				newDstAddress.ipFamily = AF_INET6;
				memcpy(newDstAddress.ip.v6, &pAddr->sin6_addr, NF_MAX_IP_ADDRESS_LENGTH);
				newDstAddress.port = pAddr->sin6_port;
			}

			if (nf_srv_updateUDPDestinationAddress(&srcAddress, &dstAddress, &newDstAddress) == NF_STATUS_SUCCESS)
			{
				memcpy(pFlow->info.remoteAddress, remoteAddress, NF_MAX_ADDRESS_LENGTH);
			}
		}

		tPacketList packetList;
		packetList.push_back(DATA_PACKET((char*)buf, len));

		startUdpSendIn(pd, packetList,
			(char*)pd->udpConnInfo.localAddress, 
			(((sockaddr*)remoteAddress)->sa_family == AF_INET)? sizeof(sockaddr_in) : sizeof(sockaddr_in6),
			pFlow);

		startUdpReceiveOut(pd);

		return true;
	}

	bool udpSetState(NFAPI_NS ENDPOINT_ID id, bool suspended)
	{
		DbgPrint("UDPProxy::udpSetState[%I64u], suspended=%d", id, suspended);

		AutoProxyData pd(this, id);
		if (!pd)
			return false;

		pd->suspended = suspended;

		if (!suspended)
		{
			if (pd->proxyState == PS_CONNECTED)
			{
				startUdpReceiveIn(pd, NULL);
				
				if (!pd->offline)
				{
					startUdpReceiveOut(pd);
				}
			}
		}

		return true;
	}

	bool getUDPConnInfo(NFAPI_NS ENDPOINT_ID id, NFAPI_NS PNF_UDP_CONN_INFO pConnInfo)
	{
		AutoProxyData pd(this, id);
		if (!pd)
			return false;

		*pConnInfo = pd->udpConnInfo;
		return true;
	}

	bool getUDPRemoteAddress(NFAPI_NS ENDPOINT_ID id, unsigned char * remoteAddress, int remoteAddressLen)
	{
		AutoProxyData pd(this, id);
		if (!pd)
			return false;

		if (pd->flowList.empty())
			return false;

		AutoLock lock(m_cs);

		UDP_FLOW * pFlow = *(pd->flowList.begin());

		if (remoteAddressLen < pFlow->info.remoteAddressLen)
			return false;

		memcpy(remoteAddress, pFlow->info.remoteAddress, pFlow->info.remoteAddressLen);

		return true;
	}

protected:

	OV_DATA * newOV_DATA()
	{
		OV_DATA * pov = new OV_DATA();
		AutoLock lock(m_cs);
		InsertTailList(&m_ovDataList, &pov->entry);
		m_ovDataCounter++;
		return pov;
	}

	void deleteOV_DATA(OV_DATA * pov)
	{
		AutoLock lock(m_cs);
		RemoveEntryList(&pov->entry);
		InitializeListHead(&pov->entry);
		delete pov;
		m_ovDataCounter--;
		DbgPrint("UDPProxy::deleteOV_DATA ov set size=%d", m_ovDataCounter);
	}

	class AutoProxyData
	{
	public:
		AutoProxyData(UDPProxy * pThis, NFAPI_NS ENDPOINT_ID id)
		{
			thisClass = pThis;
			ptr = pThis->findProxyData(id);
			if (ptr)
			{
				ptr->lock.Lock();
			}
		}
		~AutoProxyData()
		{
			if (ptr)
			{
				ptr->lock.Unlock();
				thisClass->releaseProxyData(ptr);
			}
		}
		PROXY_DATA * operator ->()
		{
			return ptr;
		}
		operator PROXY_DATA*()
		{
			return ptr;
		}
		UDPProxy * thisClass;
		PROXY_DATA * ptr;
	};

	PROXY_DATA * findProxyData(NFAPI_NS ENDPOINT_ID id)
	{
		AutoLock lock(m_cs);

		tSocketMap::iterator it = m_socketMap.find(id);
		if (it == m_socketMap.end())
			return NULL;

		it->second->refCount++;

		return it->second;
	}

	PROXY_DATA * findProxyDataBySrcAddr(const char * srcAddr, int addrLen)
	{
		AutoLock lock(m_cs);

		tSocketMap::iterator it;
		
		for (it = m_socketMap.begin(); it != m_socketMap.end(); it++)
		{
			if (memcmp(it->second->udpConnInfo.localAddress, srcAddr, addrLen) == 0)
			{
				it->second->refCount++;
				return it->second;
			}
		}

		return NULL;
	}

	int releaseProxyData(PROXY_DATA * pd)
	{
		AutoLock lock(m_cs);
		
		if (pd->refCount > 0)
		{
			pd->refCount--;
		}
		
		if (pd->refCount == 0)
		{
			DbgPrint("UDPProxy::releaseProxyData[%I64u] delete", pd->id);

			if (m_pPFEventHandler)
			{
				m_pPFEventHandler->udpClosed(pd->id, &pd->udpConnInfo);
			}

			m_socketMap.erase(pd->id);
			delete pd;

			DbgPrint("UDPProxy::releaseProxyData socket map size=%d", m_socketMap.size());

			return 0;
		}
		return pd->refCount;
	}

	void * getExtensionFunction(SOCKET s, const GUID *which_fn)
	{
		void *ptr = NULL;
		DWORD bytes=0;
		WSAIoctl(s, 
			SIO_GET_EXTENSION_FUNCTION_POINTER,
			(GUID*)which_fn, sizeof(*which_fn),
			&ptr, sizeof(ptr),
			&bytes, 
			NULL, 
			NULL);
		return ptr;
	}

	bool initExtensions()
	{
		const GUID connectex = WSAID_CONNECTEX;

		SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
		if (s == INVALID_SOCKET)
			return false;

		m_pConnectEx = (LPFN_CONNECTEX)getExtensionFunction(s, &connectex);
		
		closesocket(s);	

		return m_pConnectEx != NULL;
	}

	bool addUdpSocket(int ipFamily)
	{
		SOCKET s;
		bool result = false;

		s = createUdpSocket(ipFamily);
		if (s == INVALID_SOCKET)
			return false;

		for (;;)
		{
			if (ipFamily == AF_INET)
			{
				sockaddr_in addr;
				int addrLen = sizeof(addr);
				unsigned short port = 0;
			
				if (getsockname(s, (sockaddr*)&addr, &addrLen) == 0)
				{
					port = addr.sin_port;
				} else
				{
					DbgPrint("UDPProxy::addUdpSocket getsockname failed, err=%d", WSAGetLastError());
					break;
				}

				{
					AutoLock lock(m_cs);

					m_service.registerSocket(s);

					if (!startUdpListen(s))
					{
						break;
					}

					if (!udpPortAdd(port, ipFamily))
					{
						DbgPrint("UDPProxy::addUdpSocket udpPortAdd failed, err=%d", WSAGetLastError());
						break;
					}

					m_listenSocketsIPv4.insert(s);
				}
			} else
			{
				sockaddr_in6 addr;
				int addrLen = sizeof(addr);
				unsigned short port = 0;
			
				if (getsockname(s, (sockaddr*)&addr, &addrLen) == 0)
				{
					port = addr.sin6_port;
				} else
				{
					DbgPrint("UDPProxy::addUdpSocket getsockname failed, err=%d", WSAGetLastError());
					break;
				}

				{
					AutoLock lock(m_cs);

					m_service.registerSocket(s);

					if (!startUdpListen(s))
					{
						break;
					}

					if (!udpPortAdd(port, ipFamily))
					{
						DbgPrint("UDPProxy::addUdpSocket udpPortAdd failed, err=%d", WSAGetLastError());
						break;
					}

					m_listenSocketsIPv6.insert(s);
				}
			}

			result = true;

			break;
		}

		if (!result)
		{
			closesocket(s);
		}

		return result;
	}

	bool initUdpSocketPool()
	{
		if (!addUdpSocket(AF_INET))
		{
			m_ipv4Available = false;
			return false;
		} else
		{
			m_ipv4Available = true;
		}

		if (!addUdpSocket(AF_INET6))
		{
			m_ipv6Available = false;
		} else
		{
			m_ipv6Available = true;
		}

		for (unsigned int i=0; i<m_udpListenSocketsPoolSize-1; i++)
		{
			addUdpSocket(AF_INET);
			
			if (m_ipv6Available)
				addUdpSocket(AF_INET6);
		}

		return true;
	}

	bool createProxyConnection(PROXY_DATA * pd)
	{
		bool result = false;

		DbgPrint("UDPProxy::createProxyConnection %I64u", pd->id);

		for (;;)
		{
			SOCKET tcpSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);  
			if (tcpSocket == INVALID_SOCKET)
				return false;  

			pd->tcpSocket = tcpSocket;

			if (!m_service.registerSocket(tcpSocket))
				break;

			if (!startTcpConnect(tcpSocket, (sockaddr*)pd->proxyAddress, pd->proxyAddressLen, pd->id))
				break;
 
			result = true;

			break;
		}

		return result;
	}

	bool startTcpConnect(SOCKET socket, sockaddr * pAddr, int addrLen, unsigned __int64 id)
	{
		OV_DATA * pov = newOV_DATA();
		pov->type = OVT_CONNECT;
		pov->id = id;

		DbgPrint("UDPProxy::startTcpConnect %I64u, socket=%d", id, socket);

		{
			struct sockaddr_in addr;
			ZeroMemory(&addr, sizeof(addr));
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = INADDR_ANY;
			addr.sin_port = 0;
			
			bind(socket, (SOCKADDR*) &addr, sizeof(addr));
		}		

		if (!m_pConnectEx(socket, pAddr, addrLen, NULL, 0, NULL, &pov->ol))
		{
			int err = WSAGetLastError();
			if (err != ERROR_IO_PENDING)
			{
				DbgPrint("UDPProxy::startTcpConnect %I64u failed, err=%d", id, err);
				deleteOV_DATA(pov);
				return false;
			}
		} 

		return true;
	}

	bool startTcpReceive(SOCKET socket, unsigned __int64 id)
	{
		DWORD dwBytes, dwFlags;
		OV_DATA * pov;

		pov = newOV_DATA();
		pov->type = OVT_TCP_RECEIVE;
		pov->id = id;
		pov->packetList.push_back(DATA_PACKET(NULL, TCP_PACKET_SIZE));

		dwFlags = 0;

		if (WSARecv(socket, &pov->packetList[0](), 1, &dwBytes, &dwFlags, &pov->ol, NULL) != 0)
		{
			int err = WSAGetLastError();
			if (err != ERROR_IO_PENDING)
			{
				if (!m_service.postCompletion(socket, 0, &pov->ol))
				{
					deleteOV_DATA(pov);
				}
				return true;
			}
		} 
	
		return true;
	}

	bool startTcpSend(SOCKET socket, char * buf, int len, unsigned __int64 id)
	{
		OV_DATA * pov = newOV_DATA();
		DWORD dwBytes;

		DbgPrint("UDPProxy::startTcpSend %I64u bytes=%d", id, len);

		pov->id = id;
		pov->type = OVT_TCP_SEND;

		if (len > 0)
		{
			pov->packetList.push_back(DATA_PACKET(buf, len));
		}

		if (WSASend(socket, &pov->packetList[0](), 1, &dwBytes, 0, 
			&pov->ol, NULL) != 0)
		{
			int err = WSAGetLastError();
			if (err != ERROR_IO_PENDING)
			{
				DbgPrint("UDPProxy::startTcpSend %I64u failed, err=%d", id, err);
				pov->type = OVT_TCP_RECEIVE;
				if (!m_service.postCompletion(socket, 0, &pov->ol))
				{
					deleteOV_DATA(pov);
				}
				return false;
			}
		} 
	
		return true;
	}

	void setKeepAliveVals(SOCKET s)
	{
		tcp_keepalive tk;
		DWORD dwRet;

		{
			AutoLock lock(m_cs);

			tk.onoff = 1;
			tk.keepalivetime = m_timeout;
			tk.keepaliveinterval = 1000;
		}

		int err = WSAIoctl(s, SIO_KEEPALIVE_VALS,
		  (LPVOID) &tk,    
		  (DWORD) sizeof(tk), 
		  NULL,         
		  0,       
		  (LPDWORD) &dwRet,
		  NULL,
		  NULL);	
		if (err != 0)
		{
			DbgPrint("TCPProxy::setKeepAliveVals WSAIoctl err=%d", WSAGetLastError());
		}
	}

	void onTcpConnectComplete(SOCKET socket, DWORD dwTransferred, OV_DATA * pov, int error)
	{
		if (error != 0)
		{
			DbgPrint("TCPProxy::onTcpConnectComplete[%I64u] failed, err=%d", pov->id, error);
			OV_DATA * pov2 = newOV_DATA();
			pov2->type = OVT_UDP_CLOSE;
			pov2->id = pov->id;
			if (!m_service.postCompletion(pov2->socket, 0, &pov2->ol))
			{
				deleteOV_DATA(pov2);
			}
			return;
		}

		DbgPrint("TCPProxy::onConnectComplete[%I64u] err=%d", pov->id, error);

		AutoProxyData pd(this, pov->id);
		if (!pd)
			return;

		BOOL val = 1;
		setsockopt(socket, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
		setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, (char*)&val, sizeof(val));
		setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, (char*)&val, sizeof(val));

		setKeepAliveVals(socket);

		SOCKS5_AUTH_REQUEST authReq;

		authReq.version = SOCKS_5;
		authReq.nmethods = 1;

		if (!pd->userName.empty())
		{
			authReq.methods[0] = S5AM_UNPW;
		} else
		{
			authReq.methods[0] = S5AM_NONE;
		}

		if (startTcpSend(pd->tcpSocket, (char*)&authReq, sizeof(authReq), pov->id))
		{
			pd->proxyState = PS_AUTH;
		}
			
		startTcpReceive(pd->tcpSocket, pov->id);
	}

	void onTcpSendComplete(SOCKET socket, DWORD dwTransferred, OV_DATA * pov, int error)
	{
//		DbgPrint("UDPProxy::onTcpSendComplete %I64u bytes=%d, err=%d", pov->id, dwTransferred, error);
	}

	void onTcpReceiveComplete(SOCKET socket, DWORD dwTransferred, OV_DATA * pov, int error)
	{
		DbgPrint("UDPProxy::onTcpReceiveComplete[%I64u] bytes=%d, err=%d", pov->id, dwTransferred, error);

		if (dwTransferred == 0)
		{
			return;
		}

		{
			AutoProxyData pd(this, pov->id);
			if (!pd)
				return;

			DbgPrint("UDPProxy::onTcpReceiveComplete[%I64u] proxyState=%d", pov->id, pd->proxyState);
	
			AutoLock lock(m_cs);
			
			{
				switch (pd->proxyState)
				{
				case PS_NONE:
					break;

				case PS_AUTH:
					{
						if (dwTransferred < sizeof(SOCK5_AUTH_RESPONSE))
							break;

						SOCK5_AUTH_RESPONSE * pr = (SOCK5_AUTH_RESPONSE *)pov->packetList[0]().buf;
						
						if (pr->version != SOCKS_5)
						{
							break;
						}

						if (pr->method == S5AM_UNPW && !pd->userName.empty())
						{
							std::vector<char> authReq;

							authReq.push_back(1);
							authReq.push_back((char)pd->userName.length());
							authReq.insert(authReq.end(), pd->userName.begin(), pd->userName.end());
							authReq.push_back((char)pd->userPassword.length());
							
							if (!pd->userPassword.empty())
								authReq.insert(authReq.end(), pd->userPassword.begin(), pd->userPassword.end());

							if (startTcpSend(pd->tcpSocket, (char*)&authReq[0], (int)authReq.size(), pov->id))
							{
								pd->proxyState = PS_AUTH_NEGOTIATION;
							}

							break;
						}

						SOCKS5_REQUEST_IPv4 req;

						req.version = SOCKS_5;
						req.command = S5C_UDP_ASSOCIATE;
						req.reserved = 0;
						req.address_type = SOCKS5_ADDR_IPV4;
						req.address = 0;
						req.port = 0;

						if (startTcpSend(pd->tcpSocket, (char*)&req, sizeof(req), pov->id))
						{
							pd->proxyState = PS_UDP_ASSOC;
						}		

					}
					break;

				case PS_AUTH_NEGOTIATION:
					{
						if (dwTransferred < sizeof(SOCK5_AUTH_RESPONSE))
							break;

						SOCK5_AUTH_RESPONSE * pr = (SOCK5_AUTH_RESPONSE *)pov->packetList[0]().buf;
						
						if (pr->version != 0x01 || pr->method != 0x00)
						{
							break;
						}

						SOCKS5_REQUEST_IPv4 req;

						req.version = SOCKS_5;
						req.command = S5C_UDP_ASSOCIATE;
						req.reserved = 0;
						req.address_type = SOCKS5_ADDR_IPV4;
						req.address = 0;
						req.port = 0;

						if (startTcpSend(pd->tcpSocket, (char*)&req, sizeof(req), pov->id))
						{
							pd->proxyState = PS_UDP_ASSOC;
						}		

					}
					break;

				case PS_UDP_ASSOC:
					{
						if (dwTransferred < sizeof(SOCKS5_RESPONSE))
							break;

						SOCKS5_RESPONSE * pr = (SOCKS5_RESPONSE *)pov->packetList[0]().buf;
						
						if (pr->version != SOCKS_5 || pr->res_code != 0)
							break;
						
						if (pr->address_type == SOCKS5_ADDR_IPV4)
						{
							SOCKS5_RESPONSE_IPv4 * prIPv4 = (SOCKS5_RESPONSE_IPv4 *)pov->packetList[0]().buf;
							sockaddr_in * pAddr = (sockaddr_in *)pd->proxyAddress;
							pAddr->sin_port = prIPv4->port;
						} else
						if (pr->address_type == SOCKS5_ADDR_IPV6)
						{
							SOCKS5_RESPONSE_IPv6 * prIPv6 = (SOCKS5_RESPONSE_IPv6 *)pov->packetList[0]().buf;
							sockaddr_in6 * pAddr = (sockaddr_in6 *)pd->proxyAddress;
							pAddr->sin6_port = prIPv6->port;
						} else
						{
							break;
						}

						pd->proxyState = PS_CONNECTED;

						for (PROXY_DATA::tFlowList::iterator itf = pd->flowList.begin(); itf != pd->flowList.end(); itf++)
						{
							while (!(*itf)->udpSendPackets.empty())
							{
								tPacketList::iterator itp = (*itf)->udpSendPackets.begin();
							
								{
									tPacketList packetList;
									packetList.push_back(DATA_PACKET(itp->buffer.buf, itp->buffer.len));

									startUdpSendOut(pd, packetList,
										(char*)(*itf)->info.remoteAddress, 
										(((sockaddr*)(*itf)->info.remoteAddress)->sa_family == AF_INET)? sizeof(sockaddr_in) : sizeof(sockaddr_in6));
								}
							
								itp->free();

								(*itf)->udpSendPackets.erase(itp);
							}
						}

						startUdpReceiveOut(pd);
						startUdpReceiveIn(pd, NULL);
					}
					break;
				}

			}
		}

		startTcpReceive(socket, pov->id);
	}
	 

	bool startUdpSendOut(PROXY_DATA * pd,
		tPacketList & packetList, 
		char * dstAddress,
		int addressLen)
	{
		DbgPrint("UDPProxy::startUdpSendOut[%I64u]", pd->id);

		UDP_SOCKET_DATA * psd = NULL;

		if (packetList.size() == 0)
		{
			return false;
		}

		psd = &pd->outUdpSocket;

		OV_DATA * pov;
		DWORD dwBytes;

		pov = newOV_DATA();

		pov->type = OVT_UDP_SEND;
		pov->id = pd->id;
		pov->packetList = packetList;

		packetList.clear();

		if (pd->proxyType == PROXY_SOCKS5)
		{
			if (pov->packetList[0]().len > 0)
			{
				if (((sockaddr*)dstAddress)->sa_family == AF_INET)
				{
					DATA_PACKET packet(NULL, pov->packetList[0]().len + sizeof(SOCKS5_UDP_REQUEST_IPv4));
					SOCKS5_UDP_REQUEST_IPv4 * pReq = (SOCKS5_UDP_REQUEST_IPv4*)packet().buf;
					pReq->reserved = 0;
					pReq->frag = 0;
					pReq->address_type = SOCKS5_ADDR_IPV4;
					pReq->address = ((sockaddr_in*)dstAddress)->sin_addr.S_un.S_addr;
					pReq->port = ((sockaddr_in*)dstAddress)->sin_port;

					memcpy(packet().buf + sizeof(SOCKS5_UDP_REQUEST_IPv4), pov->packetList[0]().buf, pov->packetList[0]().len);

					pov->packetList[0].free();
					pov->packetList[0] = packet;
				} else
				{
					DATA_PACKET packet(NULL, pov->packetList[0]().len + sizeof(SOCKS5_UDP_REQUEST_IPv6));
					SOCKS5_UDP_REQUEST_IPv6 * pReq = (SOCKS5_UDP_REQUEST_IPv6*)packet().buf;
					pReq->reserved = 0;
					pReq->frag = 0;
					pReq->address_type = SOCKS5_ADDR_IPV6;
					memcpy(pReq->address, &((sockaddr_in6*)dstAddress)->sin6_addr, 16);
					pReq->port = ((sockaddr_in6*)dstAddress)->sin6_port;

					memcpy(packet().buf + sizeof(SOCKS5_UDP_REQUEST_IPv6), pov->packetList[0]().buf, pov->packetList[0]().len);
					pov->packetList[0].free();
					pov->packetList[0] = packet;
				}


				if (WSASendTo(psd->socket, 
						&pov->packetList[0](), 1, 
						&dwBytes, 0,
						(sockaddr*)pd->proxyAddress, pd->proxyAddressLen,
						&pov->ol, NULL) != 0)
				{
					int err = WSAGetLastError();
					if (err != ERROR_IO_PENDING)
					{
						DbgPrint("UDPProxy::startUdpSendOut[%I64u] failed, err=%d", pd->id, err);
						deleteOV_DATA(pov);
						return false;
					}
				}

			}
		} else
		if (WSASendTo(psd->socket, 
				&pov->packetList[0](), 1, 
				&dwBytes, 0,
				(sockaddr*)dstAddress, addressLen,
				&pov->ol, NULL) != 0)
		{
			int err = WSAGetLastError();
			if (err != ERROR_IO_PENDING)
			{
				DbgPrint("UDPProxy::startUdpSendOut[%I64u] failed, err=%d", pd->id, err);
				deleteOV_DATA(pov);
				return false;
			}
		}

		return true;
	}

	bool startUdpSendIn(PROXY_DATA * pd, 
		tPacketList & packetList, 
		char * dstAddress,
		int addressLen,
		UDP_FLOW * pFlow)
	{
		DbgPrint("UDPProxy::startUdpSendIn[%I64u]", pd->id);

		UDP_SOCKET_DATA * psd = NULL;

		if (packetList.size() == 0)
		{
			return false;
		}

		psd = &pFlow->inUdpSocket;

		OV_DATA * pov;
		DWORD dwBytes;

		pov = newOV_DATA();

		pov->type = OVT_UDP_SEND;
		pov->id = pd->id;
		pov->packetList = packetList;

		packetList.clear();

		if (WSASendTo(psd->socket, 
				&pov->packetList[0](), 1, 
				&dwBytes, 0,
				(sockaddr*)dstAddress, addressLen,
				&pov->ol, NULL) != 0)
		{
			int err = WSAGetLastError();
			if (err != ERROR_IO_PENDING)
			{
				DbgPrint("UDPProxy::startUdpSendIn[%I64u] failed, err=%d", pd->id, err);
				deleteOV_DATA(pov);
				return false;
			}
		}

		return true;
	}

	bool startUdpReceiveOut(PROXY_DATA * pd)
	{
		DbgPrint("UDPProxy::startUdpReceiveOut[%I64u]", pd->id);

		UDP_SOCKET_DATA * psd = NULL;

		psd = &pd->outUdpSocket;

		if (psd->socket == INVALID_SOCKET)
		{
			return false;
		}

		if (psd->receiveInProgress)
		{
			return true;
		}

		if (pd->suspended && 
			pd->proxyState == PS_CONNECTED)
		{
			return true;
		}

		OV_DATA * pov;
		DWORD dwBytes, dwFlags;

		pov = newOV_DATA();
		pov->type = OVT_UDP_RECEIVE;
		pov->id = pd->id;
		pov->packetList.push_back(DATA_PACKET(NULL, UDP_PACKET_SIZE));

		dwFlags = 0;

		psd->receiveInProgress = true;

		pov->remoteAddressLen = sizeof(pov->remoteAddress);

		if (WSARecvFrom(psd->socket, 
				&pov->packetList[0](), 1, 
				&dwBytes, &dwFlags, 
				(sockaddr*)pov->remoteAddress, &pov->remoteAddressLen,
				&pov->ol, NULL) != 0)
		{
			int err = WSAGetLastError();
			if (err != ERROR_IO_PENDING)
			{
				DbgPrint("UDPProxy::startUdpReceiveOut[%I64u] failed, err=%d", pd->id, err);
				deleteOV_DATA(pov);
				return false;
			}
		} 
		return true;
	}

	bool startUdpReceiveIn(PROXY_DATA * pd, UDP_FLOW * pFlow)
	{
		DbgPrint("UDPProxy::startUdpReceiveIn[%I64u]", pd->id);

		if (pFlow)
		{
			startUdpReceiveInSocket(pd, &pFlow->inUdpSocket);
		} else
		{
			for (PROXY_DATA::tFlowList::iterator it = pd->flowList.begin();
				it != pd->flowList.end(); it++)
			{
				startUdpReceiveInSocket(pd, &(*it)->inUdpSocket);
			}
		}

		return true;
	}

	bool startUdpReceiveInSocket(PROXY_DATA * pd, UDP_SOCKET_DATA * psd)
	{
		DbgPrint("UDPProxy::startUdpReceiveIn[%I64u]", pd->id);

		if (psd->socket == INVALID_SOCKET)
		{
			return false;
		}

		if (psd->receiveInProgress)
		{
			return true;
		}

		if (pd->suspended && 
			pd->proxyState == PS_CONNECTED)
		{
			return true;
		}

		OV_DATA * pov;
		DWORD dwBytes, dwFlags;

		pov = newOV_DATA();
		pov->type = OVT_UDP_RECEIVE;
		pov->id = pd->id;
		pov->packetList.push_back(DATA_PACKET(NULL, UDP_PACKET_SIZE));

		dwFlags = 0;

		psd->receiveInProgress = true;

		pov->remoteAddressLen = sizeof(pov->remoteAddress);

		if (WSARecvFrom(psd->socket, 
				&pov->packetList[0](), 1, 
				&dwBytes, &dwFlags, 
				(sockaddr*)pov->remoteAddress, &pov->remoteAddressLen,
				&pov->ol, NULL) != 0)
		{
			int err = WSAGetLastError();
			if (err != ERROR_IO_PENDING)
			{
				DbgPrint("UDPProxy::startUdpReceive[%I64u] failed, err=%d", pd->id, err);
				deleteOV_DATA(pov);
				return false;
			}
		} 
		return true;
	}

	bool startUdpListen(SOCKET socket)
	{
		DbgPrint("UDPProxy::startUdpListen");

		OV_DATA * pov;
		DWORD dwBytes, dwFlags;

		pov = newOV_DATA();
		pov->type = OVT_UDP_LISTEN;
		pov->id = 0;
		pov->packetList.push_back(DATA_PACKET(NULL, UDP_PACKET_SIZE));

		dwFlags = 0;

		pov->remoteAddressLen = sizeof(pov->remoteAddress);

		if (WSARecvFrom(socket, 
				&pov->packetList[0](), 1, 
				&dwBytes, &dwFlags, 
				(sockaddr*)pov->remoteAddress, &pov->remoteAddressLen,
				&pov->ol, NULL) != 0)
		{
			int err = WSAGetLastError();
			if (err != ERROR_IO_PENDING)
			{
				DbgPrint("UDPProxy::startUdpListen failed, err=%d", err);
				deleteOV_DATA(pov);
				return false;
			}
		} 
		return true;
	}

	void onUdpReceiveComplete(SOCKET socket, DWORD dwTransferred, OV_DATA * pov, int error)
	{
		DbgPrint("UDPProxy::onUdpReceiveComplete[%I64u] socket=%d, bytes=%d", pov->id, socket, dwTransferred);

		AutoProxyData pd(this, pov->id);
		if (!pd)
			return;

		UDP_SOCKET_DATA * psd = NULL;
		UDP_FLOW * pFlow = NULL;
		bool isInSocket;

		pd->ts = GetTickCount();

		if (pd->outUdpSocket.socket == socket)
		{
			isInSocket = false;
			psd = &pd->outUdpSocket;
		} else
		{
			isInSocket = true;

			if (!pd->getUdpFlow(socket, &pFlow))
			{
				DbgPrint("UDPProxy::onUdpReceiveComplete[%I64u] socket=%d, unable to find flow data", pov->id, socket);
				return;
			}

			psd = &pFlow->inUdpSocket;
		}

		psd->receiveInProgress = false;

		if (dwTransferred == 0)
		{
			OV_DATA * pov = newOV_DATA();
			pov->type = OVT_UDP_CLOSE;
			pov->id = pd->id;
			m_service.postCompletion(pd->outUdpSocket.socket, 0, &pov->ol);

			DbgPrint("UDPProxy::onUdpReceiveComplete[%I64u] socket=%d, error=%d", pov->id, socket, error);
			return;
		}

		if (isInSocket == IN_SOCKET)
		{
			{
				AutoLock lock(m_cs);

				if (pd->proxyType != PROXY_NONE &&
					pd->proxyState != PS_CONNECTED)
				{
					pFlow->udpSendPackets.push_back(DATA_PACKET(pov->packetList[0].buffer.buf, dwTransferred));
					return;
				}
			}

			if (m_pPFEventHandler)
			{
				m_pPFEventHandler->udpSend(pov->id, 
						(unsigned char*)pFlow->info.remoteAddress,
						pov->packetList[0].buffer.buf, 
						dwTransferred,
						NULL);
			} else
			{
				tPacketList packetList;
					
				packetList.push_back(DATA_PACKET(
					pov->packetList[0].buffer.buf, 
					dwTransferred));

				startUdpSendOut(pd,
					packetList,
					(char*)pFlow->info.remoteAddress, 
					pFlow->info.remoteAddressLen);
			}
		} else
		// OUT_SOCKET
		{
			if (pd->proxyType == PROXY_SOCKS5)
			{
				if (pov->packetList[0]().len > sizeof(SOCKS5_UDP_REQUEST))
				{
					SOCKS5_UDP_REQUEST * pReq = (SOCKS5_UDP_REQUEST*)pov->packetList[0]().buf;
					if (pReq->address_type == SOCKS5_ADDR_IPV4)
					{
						SOCKS5_UDP_REQUEST_IPv4 * pReqIPv4 = (SOCKS5_UDP_REQUEST_IPv4*)pov->packetList[0]().buf;
				
						sockaddr_in * pAddr = (sockaddr_in*)pov->remoteAddress;
						pAddr->sin_addr.S_un.S_addr = pReqIPv4->address;
						pAddr->sin_port = pReqIPv4->port;

						DATA_PACKET packet(pov->packetList[0]().buf + sizeof(SOCKS5_UDP_REQUEST_IPv4), dwTransferred - sizeof(SOCKS5_UDP_REQUEST_IPv4));

						pov->packetList[0].free();
						pov->packetList[0] = packet;

						dwTransferred = dwTransferred - sizeof(SOCKS5_UDP_REQUEST_IPv4);
					} else
					if (pReq->address_type == SOCKS5_ADDR_IPV6)
					{
						SOCKS5_UDP_REQUEST_IPv6 * pReqIPv6 = (SOCKS5_UDP_REQUEST_IPv6*)pov->packetList[0]().buf;
				
						sockaddr_in6 * pAddr = (sockaddr_in6*)pov->remoteAddress;
						memcpy(&pAddr->sin6_addr, pReqIPv6->address, 16);
						pAddr->sin6_port = pReqIPv6->port;

						DATA_PACKET packet(pov->packetList[0]().buf + sizeof(SOCKS5_UDP_REQUEST_IPv6), dwTransferred - sizeof(SOCKS5_UDP_REQUEST_IPv6));

						pov->packetList[0].free();
						pov->packetList[0] = packet;

						dwTransferred = dwTransferred - sizeof(SOCKS5_UDP_REQUEST_IPv6);
					}
				}
			}

			if (m_pPFEventHandler)
			{
				m_pPFEventHandler->udpReceive(pov->id, 
						(unsigned char*)pov->remoteAddress,
						pov->packetList[0].buffer.buf, 
						dwTransferred,
						NULL);
			} else
			{
				tPacketList packetList;
					
				packetList.push_back(DATA_PACKET(
					pov->packetList[0].buffer.buf, 
					dwTransferred));

				if (nf_srv_getFlags() & NFSRVAPI_NS NSF_USE_REAL_UDP_RECV_ADDRESS)
					if (memcmp(pFlow->info.remoteAddress, pov->remoteAddress, NF_MAX_ADDRESS_LENGTH) != 0)
				{
					NFSRVAPI_NS NF_ADDRESS srcAddress = {0}, 
						dstAddress = {0},
						newDstAddress = {0};
			
					if (pd->udpConnInfo.ip_family == AF_INET)
					{
						sockaddr_in * pAddr;
				
						pAddr = (sockaddr_in *)pd->udpConnInfo.localAddress;

						srcAddress.ipFamily = AF_INET;
						srcAddress.ip.v4 = pAddr->sin_addr.S_un.S_addr;
						srcAddress.port = pAddr->sin_port;

						pAddr = (sockaddr_in *)pFlow->info.remoteAddress;

						dstAddress.ipFamily = AF_INET;
						dstAddress.ip.v4 = pAddr->sin_addr.S_un.S_addr;
						dstAddress.port = pAddr->sin_port;

						pAddr = (sockaddr_in *)pov->remoteAddress;

						newDstAddress.ipFamily = AF_INET;
						newDstAddress.ip.v4 = pAddr->sin_addr.S_un.S_addr;
						newDstAddress.port = pAddr->sin_port;
					} else
					{
						sockaddr_in6 * pAddr;
				
						pAddr = (sockaddr_in6 *)pd->udpConnInfo.localAddress;

						srcAddress.ipFamily = AF_INET6;
						memcpy(srcAddress.ip.v6, &pAddr->sin6_addr, NF_MAX_IP_ADDRESS_LENGTH);
						srcAddress.port = pAddr->sin6_port;

						pAddr = (sockaddr_in6 *)pFlow->info.remoteAddress;

						dstAddress.ipFamily = AF_INET6;
						memcpy(dstAddress.ip.v6, &pAddr->sin6_addr, NF_MAX_IP_ADDRESS_LENGTH);
						dstAddress.port = pAddr->sin6_port;

						pAddr = (sockaddr_in6 *)pov->remoteAddress;

						newDstAddress.ipFamily = AF_INET6;
						memcpy(newDstAddress.ip.v6, &pAddr->sin6_addr, NF_MAX_IP_ADDRESS_LENGTH);
						newDstAddress.port = pAddr->sin6_port;
					}

					if (nf_srv_updateUDPDestinationAddress(&srcAddress, &dstAddress, &newDstAddress) == NF_STATUS_SUCCESS)
					{
						memcpy(pFlow->info.remoteAddress, pov->remoteAddress, NF_MAX_ADDRESS_LENGTH);
					}
				}

				startUdpSendIn(pd,
					packetList,
					(char*)pFlow->info.remoteAddress, 
					pFlow->info.remoteAddressLen, 
					pFlow);
			}
		}

		startUdpReceiveOut(pd);
		startUdpReceiveIn(pd, pFlow);
	}

	SOCKET createUdpSocket(int ipFamily)
	{
		SOCKET socket = WSASocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED);  
		if (socket == INVALID_SOCKET)
			return INVALID_SOCKET;

		sockaddr_in addr;
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;

		if (bind(socket, (SOCKADDR*)&addr, sizeof(addr)) != 0)
		{
			DbgPrint("UDPProxy::createSocket bind failed, err=%d", WSAGetLastError());
			closesocket(socket);
			return INVALID_SOCKET;
		}

		return socket;
	}

	void onUdpListenComplete(SOCKET socket, DWORD dwTransferred, OV_DATA * pov, int error)
	{
		DbgPrint("UDPProxy::onUdpListenComplete socket=%d, bytes=%d", socket, dwTransferred);
		
		int ipFamily = 0;

		{
			tUdpListenSockets::iterator it;
			AutoLock lock(m_cs);

			it = m_listenSocketsIPv4.find(socket);
			if (it != m_listenSocketsIPv4.end())
			{
				ipFamily = AF_INET;
				m_listenSocketsIPv4.erase(it);
			} else
			{
				it = m_listenSocketsIPv6.find(socket);
				if (it != m_listenSocketsIPv6.end())
				{
					ipFamily = AF_INET6;
					m_listenSocketsIPv6.erase(it);
				} else
				{
					DbgPrint("UDPProxy::onUdpListenComplete socket=%d, unable to find socket", socket);
					return;
				}
			} 
		}

		if (dwTransferred == 0)
		{
			if (error == 0)
			{
				startUdpListen(socket);
			} else
			{
				DbgPrint("UDPProxy::onUdpListenComplete socket=%d, error=%d", socket, error);
			}
			return;
		}

		NFSRVAPI_NS NF_ADDRESS srcAddress = {0}, dstAddress = {0};
		SOCKET inSocket = INVALID_SOCKET;
		bool result = false;
		PROXY_DATA * pd = NULL;
		bool isNewProxyData = false;

		for (;;)
		{
			if (ipFamily == AF_INET)
			{
				sockaddr_in * pAddr = (sockaddr_in *)pov->remoteAddress;
				srcAddress.ipFamily = AF_INET;
				srcAddress.port = pAddr->sin_port;
				srcAddress.ip.v4 = pAddr->sin_addr.S_un.S_addr;

				inSocket = socket;

				sockaddr_in addr;
				int addrLen = sizeof(addr);
				if (getsockname(inSocket, (sockaddr*)&addr, &addrLen) == 0)
				{
					dstAddress.ipFamily = AF_INET;
					dstAddress.port = addr.sin_port;
					dstAddress.ip.v4 = addr.sin_addr.S_un.S_addr;
				} else
				{
					DbgPrint("UDPProxy::onUdpListenComplete getsockname failed, err=%d", WSAGetLastError());
					break;
				}
			} else
			{
				sockaddr_in6 * pAddr = (sockaddr_in6 *)pov->remoteAddress;
				srcAddress.ipFamily = AF_INET6;
				srcAddress.port = pAddr->sin6_port;
				memcpy(srcAddress.ip.v6, pAddr->sin6_addr.u.Byte, 16);

				inSocket = socket;  

				sockaddr_in6 addr;
				int addrLen = sizeof(addr);
				if (getsockname(inSocket, (sockaddr*)&addr, &addrLen) == 0)
				{
					dstAddress.ipFamily = AF_INET6;
					dstAddress.port = addr.sin6_port;
					memcpy(dstAddress.ip.v6, addr.sin6_addr.u.Byte, 16);
				} else
				{
					DbgPrint("UDPProxy::onUdpListenComplete getsockname failed, err=%d", WSAGetLastError());
					break;
				}
			}

			{
#if defined(_DEBUG) || defined(_RELEASE_LOG)
				char remoteAddr[MAX_PATH] = "";
				DWORD dwLen;
				sockaddr * pAddr;
	
				pAddr = (sockaddr*)pov->remoteAddress;
				dwLen = sizeof(remoteAddr);

				WSAAddressToString((LPSOCKADDR)pAddr, 
							(pAddr->sa_family == AF_INET6)? sizeof(sockaddr_in6) : sizeof(sockaddr_in), 
							NULL, 
							remoteAddr, 
							&dwLen);

				DbgPrint("UDPProxy::onUdpListenComplete x:%d <- %s", 
					dstAddress.port,
					remoteAddr);
#endif
				bool haveDestinationAddress = false;

				if (nf_srv_getDestinationAddress(&srcAddress, &dstAddress, IPPROTO_UDP) == NF_STATUS_SUCCESS)
				{
					haveDestinationAddress = true;
					DbgPrint("UDPProxy::onUdpListenComplete found destination address");
				}

				pd = findProxyDataBySrcAddr(pov->remoteAddress, (ipFamily == AF_INET)? sizeof(sockaddr_in) : sizeof(sockaddr_in6));
				if (pd)
				{
					DbgPrint("UDPProxy::onUdpListenComplete found existing endpoint");
				} else
				{
					AutoLock lock(m_cs);

					pd = new PROXY_DATA();

					m_connId++;
					
					pd->id = m_connId;

					pd->ts = GetTickCount();

					pd->proxyState = PS_ERROR;

					pd->outUdpSocket.socket = createUdpSocket(ipFamily);
					if (pd->outUdpSocket.socket == INVALID_SOCKET)
					{
						DbgPrint("UDPProxy::onUdpListenComplete WSASocket failed");
						break;  
					}

					if (!m_service.registerSocket(pd->outUdpSocket.socket))
					{
						DbgPrint("UDPProxy::onUdpListenComplete registerSocket (out) failed");
						break;
					}

					memcpy(pd->udpConnInfo.localAddress, pov->remoteAddress, pov->remoteAddressLen);

					pd->udpConnInfo.ip_family = ipFamily;
					pd->udpConnInfo.processId = 0;
			
					pd->refCount++;

					m_socketMap[pd->id] = pd;

					if (m_proxyType != PROXY_NONE)
					{
						pd->proxyType = m_proxyType;
						memcpy(pd->proxyAddress, m_proxyAddress, sizeof(pd->proxyAddress));
						pd->proxyAddressLen = m_proxyAddressLen;
						pd->userName = m_userName;
						pd->userPassword = m_userPassword;
					}

					isNewProxyData = true;
				}

				AutoLock lock(pd->lock);

				UDP_FLOW * pFlow = NULL;

				if (haveDestinationAddress)
				{
					pFlow = new UDP_FLOW();

					if (ipFamily == AF_INET)
					{
						sockaddr_in * pAddr = (sockaddr_in *)pFlow->info.remoteAddress;
						memset(pFlow->info.remoteAddress, 0, sizeof(pFlow->info.remoteAddress));
						pAddr->sin_family = AF_INET;
						pAddr->sin_port = dstAddress.port;
						pAddr->sin_addr.S_un.S_addr = dstAddress.ip.v4;

						pFlow->info.remoteAddressLen = sizeof(sockaddr_in);
					} else
					{
						sockaddr_in6 * pAddr = (sockaddr_in6 *)pFlow->info.remoteAddress;
						memset(pFlow->info.remoteAddress, 0, sizeof(pFlow->info.remoteAddress));
						pAddr->sin6_family = AF_INET6;
						pAddr->sin6_port = dstAddress.port;
						memcpy(pAddr->sin6_addr.u.Byte, dstAddress.ip.v6, 16);

						pFlow->info.remoteAddressLen = sizeof(sockaddr_in6);
					}

					pFlow->inUdpSocket.socket = inSocket;
					inSocket = INVALID_SOCKET;

					pd->flowList.push_back(pFlow);
				}

				if (!pFlow)
				{
					DbgPrint("UDPProxy::onUdpListenComplete() no flow");
					break;
				}

				if (m_pPFEventHandler)
				{
					if (isNewProxyData)
					{
						m_pPFEventHandler->udpCreated(pd->id, &pd->udpConnInfo);

						if (pd->proxyType == PROXY_NONE)
						{
							pd->proxyState = PS_CONNECTED;
						}
					}

					m_pPFEventHandler->udpSend(pd->id, (unsigned char*)pFlow->info.remoteAddress, 
						pov->packetList[0].buffer.buf, dwTransferred, NULL);
				} else
				{
					if (pd->proxyType != PROXY_NONE &&
						pd->proxyState != PS_CONNECTED)
					{
						if (dwTransferred > 0)
						{
							pFlow->udpSendPackets.push_back(DATA_PACKET(pov->packetList[0].buffer.buf, dwTransferred));								
						}
					} else
					{
						tPacketList packetList;

						packetList = pov->packetList;
						pov->packetList.clear();

						packetList[0].buffer.len = dwTransferred;

						startUdpSendOut(pd, packetList,
							(char*)pFlow->info.remoteAddress, pFlow->info.remoteAddressLen);
					}
				}

				if (isNewProxyData && pd->proxyType != PROXY_NONE)
				{
					createProxyConnection(pd);
				} else
				{
					startUdpReceiveOut(pd);
					startUdpReceiveIn(pd, pFlow);
				}

				result = true;
			}

			break;
		}

		if (pd)
		{
			releaseProxyData(pd);
		}

		if (!result)
		{
			if (pd && isNewProxyData)
			{
				releaseProxyData(pd);
			}

			if (inSocket != INVALID_SOCKET)
			{
				closesocket(inSocket);
				inSocket = INVALID_SOCKET;
			}
		}

		{
			AutoLock lock(m_cs);
			if (m_listenSocketsIPv4.size() < m_udpListenSocketsPoolSize)
			{
				addUdpSocket(AF_INET);
			}
			if (m_listenSocketsIPv6.size() < m_udpListenSocketsPoolSize)
			{
				addUdpSocket(AF_INET6);
			}
		}
	}

	void onUdpClose(SOCKET socket, DWORD dwTransferred, OV_DATA * pov, int error)
	{
		DbgPrint("UDPProxy::onUdpClose id=%I64u", pov->id);

		AutoProxyData pd(this, pov->id);
		if (!pd)
			return;

		if (pd->proxyState != PS_CLOSED)
		{
			pd->proxyState = PS_CLOSED;
			releaseProxyData(pd);
		}
	}

	virtual void onComplete(SOCKET socket, DWORD dwTransferred, OVERLAPPED * pOverlapped, int error)
	{
		OV_DATA * pov = (OV_DATA*)pOverlapped;

		pov->socket = socket;
		pov->dwTransferred = dwTransferred;
		pov->error = error;

		AutoLock lock(m_csEventList);
		InsertTailList(&m_eventList, &pov->entryEventList);
		m_pool.jobAvailable();
	}

	virtual void execute()
	{
		OV_DATA * pov;

		{
			AutoLock lock(m_csEventList);
			
			if (IsListEmpty(&m_eventList))
				return;

			pov = CONTAINING_RECORD(m_eventList.Flink, OV_DATA, entryEventList);

			RemoveEntryList(&pov->entryEventList);
			InitializeListHead(&pov->entryEventList);
		}

		if (pov)
		{
			switch (pov->type)
			{
			case OVT_CONNECT:
				onTcpConnectComplete(pov->socket, pov->dwTransferred, pov, pov->error);
				break;
			case OVT_TCP_SEND:
				onTcpSendComplete(pov->socket, pov->dwTransferred, pov, pov->error);
				break;
			case OVT_TCP_RECEIVE:
				onTcpReceiveComplete(pov->socket, pov->dwTransferred, pov, pov->error);
				break;
			case OVT_UDP_RECEIVE:
				onUdpReceiveComplete(pov->socket, pov->dwTransferred, pov, pov->error);
				break;
			case OVT_UDP_CLOSE:
				onUdpClose(pov->socket, pov->dwTransferred, pov, pov->error);
				break;
			case OVT_UDP_LISTEN:
				onUdpListenComplete(pov->socket, pov->dwTransferred, pov, pov->error);
				break;
			}

			deleteOV_DATA(pov);
		}

		{
			AutoLock lock(m_csEventList);
			if (!IsListEmpty(&m_eventList))
			{
				m_pool.jobAvailable();
			}
		}
	}

	virtual void threadStarted()
	{
		if (m_pPFEventHandler)
		{
			m_pPFEventHandler->threadStart();
		}
	}

	virtual void threadStopped()
	{
		if (m_pPFEventHandler)
		{
			m_pPFEventHandler->threadEnd();
		}
	}

	void cleanup()
	{
		AutoLock lock(m_cs);

		DWORD ts = GetTickCount();

		for (tSocketMap::iterator it = m_socketMap.begin();
			it != m_socketMap.end(); it++)
		{
			if ((ts - it->second->ts) > m_timeout)
			{
				OV_DATA * pov = newOV_DATA();
				pov->type = OVT_UDP_CLOSE;
				pov->id = it->second->id;
				m_service.postCompletion(it->second->outUdpSocket.socket, 0, &pov->ol);
			}
		}
	}

	void workerThread()
	{
		for (;;)
		{
			if (WaitForSingleObject(m_stopEvent.m_h, 5 * 1000) == WAIT_OBJECT_0)
			{
				break;
			}

			cleanup();
		}
	}

	static unsigned int WINAPI _workerThread(void * pThis)
	{
		((UDPProxy*)pThis)->workerThread();
		return 0;
	}

private:
	IOCPService m_service;
	
	LIST_ENTRY	m_ovDataList;
	int m_ovDataCounter;

	typedef std::map<NFAPI_NS ENDPOINT_ID, PROXY_DATA*> tSocketMap;
	tSocketMap m_socketMap;

	typedef std::set<SOCKET> tUdpListenSockets;

	tUdpListenSockets m_listenSocketsIPv4;
	tUdpListenSockets m_listenSocketsIPv6;

	unsigned int m_udpListenSocketsPoolSize;

	NFAPI_NS ENDPOINT_ID m_connId;

	bool	m_ipv4Available;
	bool	m_ipv6Available;

	LPFN_CONNECTEX m_pConnectEx;

	NFAPI_NS NF_EventHandler * m_pPFEventHandler;

	LIST_ENTRY	m_eventList;
	LIST_ENTRY	m_listenEventList;
	AutoCriticalSection m_csEventList;
	
	ThreadPool m_pool;

	AutoEventHandle m_stopEvent;
	AutoEventHandle m_listenCompleteEvent;
	AutoHandle		m_workerThread;

	DWORD	m_timeout;

	PROXY_TYPE m_proxyType;

	char		m_proxyAddress[NF_MAX_ADDRESS_LENGTH];
	int			m_proxyAddressLen;

	std::string m_userName;
	std::string m_userPassword;

	AutoCriticalSection m_cs;
};

}