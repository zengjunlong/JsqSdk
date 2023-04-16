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
#include "interfaces.h"

typedef struct _NF_INTERFACE_IP
{
	LIST_ENTRY	entry;
	ULONG64		luid;
	NF_ADDRESS	address;
} NF_INTERFACE_IP, *PNF_INTERFACE_IP;

static LIST_ENTRY g_lInterfaces;
static KSPIN_LOCK g_slInterfaces;
static BOOLEAN	  g_initialized = FALSE;

BOOLEAN interfaces_init()
{
	InitializeListHead(&g_lInterfaces);
	KeInitializeSpinLock(&g_slInterfaces);

	g_initialized = TRUE;
	return TRUE;
}

void interfaces_free()
{
	if (g_initialized)
	{
		interfaces_clear();
		g_initialized = FALSE;
	}
}

void interfaces_add(ULONG64 luid, PNF_ADDRESS pAddress)
{
	PNF_INTERFACE_IP pItf;
    KLOCK_QUEUE_HANDLE lh;

	if (!g_initialized)
		return;

    sl_lock(&g_slInterfaces, &lh);	

	for (pItf = (PNF_INTERFACE_IP)g_lInterfaces.Flink;
		pItf != (PNF_INTERFACE_IP)&g_lInterfaces;
		pItf = (PNF_INTERFACE_IP)pItf->entry.Flink)
	{
		if (pItf->luid == luid &&
			pItf->address.ipFamily == pAddress->ipFamily)
		{
			pItf->address = *pAddress;
			sl_unlock(&lh);	
			return;
		}
	}

	pItf = (PNF_INTERFACE_IP)malloc_np(sizeof(NF_INTERFACE_IP));
	if (pItf)
	{
		pItf->luid = luid;
		pItf->address = *pAddress;
		InsertTailList(&g_lInterfaces, &pItf->entry);
	}

	sl_unlock(&lh);	
}

void interfaces_clear()
{
	PNF_INTERFACE_IP pItf;
    KLOCK_QUEUE_HANDLE lh;

	if (!g_initialized)
		return;

	sl_lock(&g_slInterfaces, &lh);	

	while (!IsListEmpty(&g_lInterfaces))
	{
		pItf = (PNF_INTERFACE_IP)RemoveHeadList(&g_lInterfaces);
		free_np(pItf);
	}

	sl_unlock(&lh);	
}

BOOLEAN interfaces_get(ULONG64 luid, int ipFamily, PNF_ADDRESS pAddress)
{
	PNF_INTERFACE_IP pItf;
    KLOCK_QUEUE_HANDLE lh;

	if (!g_initialized)
		return FALSE;

	sl_lock(&g_slInterfaces, &lh);	

	for (pItf = (PNF_INTERFACE_IP)g_lInterfaces.Flink;
		pItf != (PNF_INTERFACE_IP)&g_lInterfaces;
		pItf = (PNF_INTERFACE_IP)pItf->entry.Flink)
	{
		if (pItf->luid == luid &&
			pItf->address.ipFamily == ipFamily)
		{
			*pAddress = pItf->address;
			sl_unlock(&lh);	
			return TRUE;
		}
	}

	sl_unlock(&lh);	

	return FALSE;
}

BOOLEAN interfaces_isLocalAddress(ULONG64 luid, int ipFamily, PNF_ADDRESS pAddress)
{
	PNF_INTERFACE_IP pItf;
    KLOCK_QUEUE_HANDLE lh;

	if (!g_initialized)
		return FALSE;

	sl_lock(&g_slInterfaces, &lh);	

	for (pItf = (PNF_INTERFACE_IP)g_lInterfaces.Flink;
		pItf != (PNF_INTERFACE_IP)&g_lInterfaces;
		pItf = (PNF_INTERFACE_IP)pItf->entry.Flink)
	{
		if (pItf->luid == luid &&
			pItf->address.ipFamily == ipFamily &&
			(memcmp(&pItf->address.ip, &pAddress->ip, sizeof(pAddress->ip)) == 0))
		{
			sl_unlock(&lh);	
			return TRUE;
		}
	}

	sl_unlock(&lh);	

	return FALSE;
}
