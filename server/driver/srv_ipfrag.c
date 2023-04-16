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
#include "srv_ipfrag.h"
#include "hashtable.h"

#ifdef _WPPTRACE
#include "srv_ipfrag.tmh"
#endif

typedef unsigned __int64 uint64_t;

#define NANOSECONDS_PER_SECOND		(LONGLONG)(10 * 1000 * 1000)
#define IPFRAG_TIMEOUT	(60 * NANOSECONDS_PER_SECOND)

#pragma pack(push, 1)

typedef struct _NF_FRAG_INFO
{
	UCHAR			ipFamily;
	UCHAR			protocol;
	UINT			fragId;
	NF_IP_ADDRESS	srcIP;
	NF_IP_ADDRESS	dstIP;
} NF_FRAG_INFO, *PNF_FRAG_INFO;

#pragma pack(pop)

typedef struct _NF_IPFRAG_ENTRY
{
	LIST_ENTRY			entry;

	HASH_ID				id;
	PHASH_TABLE_ENTRY	next;

	LIST_ENTRY			fragOffsetList;
	NF_FRAG_INFO		fragInfo;
	NF_PORTS			ports;

	NF_SRV_RULE_ACTION	action;

	BOOLEAN				haveLastFragment;
	
	uint64_t			ts;			// Last activity time
} NF_IPFRAG_ENTRY, *PNF_IPFRAG_ENTRY;

typedef struct _NF_IPFRAG_OFFSET
{
	LIST_ENTRY	entry;
	UINT		length;
	UINT		offset;
} NF_IPFRAG_OFFSET, *PNF_IPFRAG_OFFSET;

static LIST_ENTRY g_lFrag;
static PHASH_TABLE	g_fragTable;
static KSPIN_LOCK g_slFrag;
static NPAGED_LOOKASIDE_LIST g_fragLAList;
static NPAGED_LOOKASIDE_LIST g_fragOffsetLAList;
static BOOLEAN	  g_initialized = FALSE;

BOOLEAN ipfrag_init()
{
	KdPrint(("ipfrag_init\n"));

	InitializeListHead(&g_lFrag);
	KeInitializeSpinLock(&g_slFrag);

	g_fragTable = hash_table_new(DEFAULT_HASH_SIZE);
	if (!g_fragTable)
		return FALSE;

	ExInitializeNPagedLookasideList( &g_fragLAList,
                                     NULL,
                                     NULL,
                                     0,
									 sizeof( NF_IPFRAG_ENTRY ),
                                     MEM_TAG_FRAG,
                                     0 );

	ExInitializeNPagedLookasideList( &g_fragOffsetLAList,
                                     NULL,
                                     NULL,
                                     0,
                                     sizeof( NF_IPFRAG_OFFSET ),
                                     MEM_TAG_FRAG,
                                     0 );
	g_initialized = TRUE;

	return TRUE;
}

void ipfrag_deleteEntry(PNF_IPFRAG_ENTRY pEntry)
{
	PNF_IPFRAG_OFFSET pFragOffset;

	ht_remove_entryByPointer(g_fragTable, (PHASH_TABLE_ENTRY)&pEntry->id);

	while (!IsListEmpty(&pEntry->fragOffsetList))
	{
		pFragOffset = (PNF_IPFRAG_OFFSET)RemoveHeadList(&pEntry->fragOffsetList);
		ExFreeToNPagedLookasideList( &g_fragOffsetLAList, pFragOffset );
	}

	ExFreeToNPagedLookasideList( &g_fragLAList, pEntry );
}

void ipfrag_removeAll()
{
	PNF_IPFRAG_ENTRY pEntry;
    KLOCK_QUEUE_HANDLE lh;

	KdPrint(("ipfrag_removeAll\n"));

	sl_lock(&g_slFrag, &lh);	

	while (!IsListEmpty(&g_lFrag))
	{
		pEntry = (PNF_IPFRAG_ENTRY)RemoveHeadList(&g_lFrag);
		ipfrag_deleteEntry(pEntry);
	}

	sl_unlock(&lh);	
}

void ipfrag_free()
{
	KdPrint((DPREFIX"ipfrag_free\n"));

	if (g_initialized)
	{
		ipfrag_removeAll();
		ExDeleteNPagedLookasideList( &g_fragLAList );
		ExDeleteNPagedLookasideList( &g_fragOffsetLAList );

		if (g_fragTable)
		{
			hash_table_free(g_fragTable);
			g_fragTable = NULL;
		}
		
		g_initialized = FALSE;
	}
}

static uint64_t 
ipfrag_getTickCount()
{
	LARGE_INTEGER li;

	KeQuerySystemTime(&li);

	return li.QuadPart;
}


static HASH_ID 
ipfrag_getHash(const char * key, int length) 
{
	int i = 0;
	HASH_ID hash = 0;
  
	while (i != length) 
	{
		hash += key[i++];
		hash += hash << 10;
		hash ^= hash >> 6;
	}
	hash += hash << 3;
	hash ^= hash >> 11;
	hash += hash << 15;
	return hash;
}

static PNF_IPFRAG_ENTRY 
ipfrag_findEntry(PNF_FRAG_INFO pFragInfo)
{
	HASH_ID id;
	PHASH_TABLE_ENTRY phte;
	PNF_IPFRAG_ENTRY pEntry;

	id = ipfrag_getHash((char*)pFragInfo, sizeof(NF_FRAG_INFO));

	KdPrint(("ipfrag_findEntry entry id %I64u\n", id));

	phte = ht_find_entry(g_fragTable, id);
	if (!phte)
	{
		return NULL;
	}

	do {
		pEntry = (PNF_IPFRAG_ENTRY)CONTAINING_RECORD(phte, NF_IPFRAG_ENTRY, id);

		if (memcmp(&pEntry->fragInfo, pFragInfo, sizeof(*pFragInfo)) == 0)
		{
			return pEntry;
		}

		phte = phte->pNext;
	} while (phte != NULL);

	return NULL;
}

BOOLEAN
ipfrag_lookup(PSRV_PACKET_INFO pPacketInfo, PNF_PORTS pPorts, PNF_SRV_RULE_ACTION pAction)
{
	PNF_IPFRAG_ENTRY	pEntry = NULL;
	NF_FRAG_INFO		fragInfo;
	PNF_IPFRAG_OFFSET	pOffset = NULL;
	PLIST_ENTRY			p;
    KLOCK_QUEUE_HANDLE	lh;

	KdPrint(("ipfrag_lookup\n"));

	if (!pPacketInfo->isFragment)
	{
		return FALSE;
	}
	
	fragInfo.ipFamily = pPacketInfo->ipFamily;
	fragInfo.protocol = pPacketInfo->protocol;
	fragInfo.srcIP = pPacketInfo->srcAddress.ip;
	fragInfo.dstIP = pPacketInfo->dstAddress.ip;
	fragInfo.fragId = pPacketInfo->fragId;

    sl_lock(&g_slFrag, &lh);	

	for (;;)
	{
		pEntry = ipfrag_findEntry(&fragInfo);
		if (!pEntry)
		{
			break;
		}

		if (pAction)
		{
			*pAction = pEntry->action;
		}

		if (pPorts)
		{
			*pPorts = pEntry->ports;
		}

		pEntry->ts = ipfrag_getTickCount();

		pOffset = (PNF_IPFRAG_OFFSET)ExAllocateFromNPagedLookasideList( &g_fragOffsetLAList );
		if (!pOffset)
		{
			KdPrint(("ipfrag_lookup memory alloc error\n"));
			break;
		}

		pOffset->length = pPacketInfo->payloadLength;
		pOffset->offset = pPacketInfo->fragOffset;

		if (pPacketInfo->isLastFragment)
		{
			pEntry->haveLastFragment = TRUE;
			InsertTailList(&pEntry->fragOffsetList, &pOffset->entry);
			KdPrint(("ipfrag_lookup last segment arrived\n"));
		} else
		{
			InitializeListHead(&pOffset->entry);

			for (p = pEntry->fragOffsetList.Flink;
				p != &pEntry->fragOffsetList;
				p = p->Flink)
			{
				if (((PNF_IPFRAG_OFFSET)p)->offset > pOffset->offset)
				{
					pOffset->entry.Flink = p;
					pOffset->entry.Blink = p->Blink;
					p->Blink->Flink = &pOffset->entry;
					p->Blink = &pOffset->entry;
					break;
				}
			}

			if (IsListEmpty(&pOffset->entry))
			{
				InsertTailList(&pEntry->fragOffsetList, &pOffset->entry);
			}
		}

		if (pEntry->haveLastFragment)
		{
			UINT curOffset = 0;

			for (p = pEntry->fragOffsetList.Flink;
				p != &pEntry->fragOffsetList;
				p = p->Flink)
			{
				if (((PNF_IPFRAG_OFFSET)p)->offset != curOffset)
				{
					break;
				}
				curOffset += ((PNF_IPFRAG_OFFSET)p)->length;
			}

			if (p == &pEntry->fragOffsetList)
			{
				RemoveEntryList(&pEntry->entry);
				ipfrag_deleteEntry(pEntry);
				KdPrint(("ipfrag_lookup entry deleted\n"));
			}
		}

		sl_unlock(&lh);	

		return TRUE;
	}

	if (pOffset)
	{
		ExFreeToNPagedLookasideList( &g_fragOffsetLAList, pOffset );
	}

	sl_unlock(&lh);	

	return FALSE;
}

BOOLEAN 
ipfrag_add(PSRV_PACKET_INFO pPacketInfo, PNF_SRV_RULE_ACTION pAction)
{
	PNF_IPFRAG_ENTRY	pEntry = NULL;
	NF_FRAG_INFO		fragInfo;
	PNF_IPFRAG_OFFSET	pOffset = NULL;
    KLOCK_QUEUE_HANDLE	lh;

	KdPrint(("ipfrag_add\n"));

	if (!pPacketInfo->isFragment)
	{
		return FALSE;
	}
	
	fragInfo.ipFamily = pPacketInfo->ipFamily;
	fragInfo.protocol = pPacketInfo->protocol;
	fragInfo.srcIP = pPacketInfo->srcAddress.ip;
	fragInfo.dstIP = pPacketInfo->dstAddress.ip;
	fragInfo.fragId = pPacketInfo->fragId;

    sl_lock(&g_slFrag, &lh);	

	for (;;)
	{
		if (pPacketInfo->fragOffset != 0 ||
			pPacketInfo->isLastFragment)
		{
			KdPrint(("ipfrag_add it is not a first segment\n"));
			break;
		}

		pEntry = ipfrag_findEntry(&fragInfo);
		if (pEntry)
		{
			RemoveEntryList(&pEntry->entry);
			ipfrag_deleteEntry(pEntry);
		}

		pEntry = (PNF_IPFRAG_ENTRY)ExAllocateFromNPagedLookasideList( &g_fragLAList );
		if (!pEntry)
		{
			KdPrint(("ipfrag_add memory alloc error\n"));
			break;
		}

		memset(pEntry, 0, sizeof(NF_IPFRAG_ENTRY));

		pEntry->fragInfo = fragInfo;
		pEntry->action = *pAction;

		pEntry->ports.srcPort = pPacketInfo->srcAddress.port;
		pEntry->ports.dstPort = pPacketInfo->dstAddress.port;
		
		pEntry->ts = ipfrag_getTickCount();

		InitializeListHead(&pEntry->fragOffsetList);

		pOffset = (PNF_IPFRAG_OFFSET)ExAllocateFromNPagedLookasideList( &g_fragOffsetLAList );
		if (!pOffset)
		{
			KdPrint(("ipfrag_add memory alloc error\n"));
			break;
		}

		pOffset->length = pPacketInfo->payloadLength;
		pOffset->offset = pPacketInfo->fragOffset;

		InsertTailList(&pEntry->fragOffsetList, &pOffset->entry);

		InsertTailList(&g_lFrag, &pEntry->entry);

		pEntry->id = ipfrag_getHash((char*)&fragInfo, sizeof(NF_FRAG_INFO));

		ht_add_entry(g_fragTable, (PHASH_TABLE_ENTRY)&pEntry->id);

		KdPrint(("ipfrag_add entry added\n"));

		sl_unlock(&lh);	

		return TRUE;
	}

	if (pEntry)
	{
		ExFreeToNPagedLookasideList( &g_fragLAList, pEntry );
	}

	if (pOffset)
	{
		ExFreeToNPagedLookasideList( &g_fragOffsetLAList, pOffset );
	}

	sl_unlock(&lh);	

	return FALSE;
}

void
ipfrag_deleteExpiredEntries()
{
	PLIST_ENTRY	p;
	uint64_t curTs;
    KLOCK_QUEUE_HANDLE	lh;

	curTs = ipfrag_getTickCount();

    sl_lock(&g_slFrag, &lh);	

	for (p = g_lFrag.Flink; p != &g_lFrag; )
	{
		if ((curTs - ((PNF_IPFRAG_ENTRY)p)->ts) > IPFRAG_TIMEOUT)
		{
			PNF_IPFRAG_ENTRY pEntry = (PNF_IPFRAG_ENTRY)p;

			p = p->Flink;

			RemoveEntryList(&pEntry->entry);
			ipfrag_deleteEntry(pEntry);

			KdPrint(("ipfrag_deleteExpiredEntries entry deleted\n"));
		} else
		{
			p = p->Flink;
		}
	}

	sl_unlock(&lh);	
}
