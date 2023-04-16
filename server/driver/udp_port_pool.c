//
// 	NetFilterSDK 
// 	Copyright (C) Vitaly Sidorov
//	All rights reserved.
//
//	This file is a part of the NetFilter SDK.
//	The code and information is provided "as-is" without
//	warranty of any kind, either expressed or implied.
//

#include "stdinc.h"
#include "udp_port_pool.h"

typedef struct _NF_UDP_PORT
{
	LIST_ENTRY	entry;
	unsigned short port;
} NF_UDP_PORT, *PNF_UDP_PORT;

static LIST_ENTRY g_lPortsIPv4;
static LIST_ENTRY g_lPortsIPv6;
static KSPIN_LOCK g_slPorts;
static BOOLEAN	  g_initialized = FALSE;

BOOLEAN udp_port_pool_init()
{
	InitializeListHead(&g_lPortsIPv4);
	InitializeListHead(&g_lPortsIPv6);
	KeInitializeSpinLock(&g_slPorts);

	g_initialized = TRUE;
	return TRUE;
}

void udp_port_pool_free()
{
	if (g_initialized)
	{
		udp_port_pool_clear();
		g_initialized = FALSE;
	}
}

BOOLEAN udp_port_pool_add(int ipFamily, unsigned short port)
{
	PNF_UDP_PORT pPort;
    KLOCK_QUEUE_HANDLE lh;

	if (!g_initialized)
		return FALSE;

	pPort = (PNF_UDP_PORT)malloc_np(sizeof(NF_UDP_PORT));
	if (!pPort)
	{
		return FALSE;
	}

	pPort->port = port;

	sl_lock(&g_slPorts, &lh);	
	if (ipFamily == AF_INET)
	{
		InsertTailList(&g_lPortsIPv4, &pPort->entry);
	} else
	{
		InsertTailList(&g_lPortsIPv6, &pPort->entry);
	}
	sl_unlock(&lh);	

	return TRUE;
}

void udp_port_pool_clear()
{
	PNF_UDP_PORT pPort;
    KLOCK_QUEUE_HANDLE lh;

	if (!g_initialized)
		return;

	sl_lock(&g_slPorts, &lh);	

	while (!IsListEmpty(&g_lPortsIPv4))
	{
		pPort = (PNF_UDP_PORT)RemoveHeadList(&g_lPortsIPv4);
		free_np(pPort);
	}

	while (!IsListEmpty(&g_lPortsIPv6))
	{
		pPort = (PNF_UDP_PORT)RemoveHeadList(&g_lPortsIPv6);
		free_np(pPort);
	}

	sl_unlock(&lh);	
}

unsigned short udp_port_pool_get(int ipFamily)
{
	PNF_UDP_PORT pPort;
    KLOCK_QUEUE_HANDLE lh;

	if (!g_initialized)
		return 0;

	sl_lock(&g_slPorts, &lh);	

	if (ipFamily == AF_INET)
	{
		if (IsListEmpty(&g_lPortsIPv4))
			pPort = NULL;
		else
			pPort = (PNF_UDP_PORT)RemoveHeadList(&g_lPortsIPv4);
	} else
	{
		if (IsListEmpty(&g_lPortsIPv6))
			pPort = NULL;
		else
			pPort = (PNF_UDP_PORT)RemoveHeadList(&g_lPortsIPv6);
	}

	sl_unlock(&lh);	

	if (pPort)
	{
		unsigned short port = pPort->port;
		free_np(pPort);
		return port;
	}

	return 0;
}
