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
#include "nfsrvext.h"
#include "srv_rules.h"
#include "devctrl.h"

typedef UNALIGNED union _gen_addr
{
    struct in_addr sin_addr;
    struct in6_addr sin6_addr;
} gen_addr;

typedef struct _SRV_RULE_ENTRY
{
	LIST_ENTRY		entry;
	NF_SRV_RULE		rule;
} SRV_RULE_ENTRY, *PSRV_RULE_ENTRY; 

static NPAGED_LOOKASIDE_LIST g_rulesLAList;
static LIST_ENTRY g_lRules;
static KSPIN_LOCK g_slRules;
static BOOLEAN	  g_initialized = FALSE;

static LIST_ENTRY g_lTempRules;

NTSTATUS srvrules_init()
{
	InitializeListHead(&g_lRules);
	KeInitializeSpinLock(&g_slRules);

	InitializeListHead(&g_lTempRules);

	ExInitializeNPagedLookasideList( &g_rulesLAList,
                                     NULL,
                                     NULL,
                                     0,
                                     sizeof( SRV_RULE_ENTRY ),
                                     MEM_TAG,
                                     0 );

	g_initialized = TRUE;

	return STATUS_SUCCESS;
}

void srvrules_free()
{
	KdPrint((DPREFIX"srvrules_free\n"));

	if (g_initialized)
	{
		srvrules_remove_all();
		srvrules_remove_all_temp();
		ExDeleteNPagedLookasideList( &g_rulesLAList );
		g_initialized = FALSE;
	}
}

/**
 *  Add RULE to linked list
 */
void srvrules_add(PNF_SRV_RULE pRule, BOOLEAN toHead)
{
    KLOCK_QUEUE_HANDLE lh;
	PSRV_RULE_ENTRY pRuleEntry;

	pRuleEntry = (PSRV_RULE_ENTRY)ExAllocateFromNPagedLookasideList( &g_rulesLAList );
	if (!pRuleEntry)
		return;

	// Don't count the blocked traffic
	if (pRule->action.filteringFlag & NF_SRV_BLOCK)
		pRule->action.fcHandle = 0;

	memcpy(&pRuleEntry->rule, pRule, sizeof(NF_SRV_RULE));

    sl_lock(&g_slRules, &lh);	

	if (toHead)
	{
		InsertHeadList(&g_lRules, &pRuleEntry->entry);
	} else
	{
		InsertTailList(&g_lRules, &pRuleEntry->entry);
	}

    sl_unlock(&lh);	
}

/**
 *	Remove all rules from list
 */
void srvrules_remove_all()
{
	PSRV_RULE_ENTRY pRule;
    KLOCK_QUEUE_HANDLE lh;

    sl_lock(&g_slRules, &lh);	

	while (!IsListEmpty(&g_lRules))
	{
		pRule = (PSRV_RULE_ENTRY)RemoveHeadList(&g_lRules);
		ExFreeToNPagedLookasideList( &g_rulesLAList, pRule );
	}

	sl_unlock(&lh);	
}

/**
 *  Add RULE to temp linked list
 */
BOOLEAN srvrules_add_temp(PNF_SRV_RULE pRule)
{
    KLOCK_QUEUE_HANDLE lh;
	PSRV_RULE_ENTRY pRuleEntry;

	pRuleEntry = (PSRV_RULE_ENTRY)ExAllocateFromNPagedLookasideList( &g_rulesLAList );
	if (!pRuleEntry)
		return FALSE;

	// Don't count the blocked traffic
	if (pRule->action.filteringFlag & NF_SRV_BLOCK)
		pRule->action.fcHandle = 0;

	memcpy(&pRuleEntry->rule, pRule, sizeof(NF_SRV_RULE));

    sl_lock(&g_slRules, &lh);	

	InsertTailList(&g_lTempRules, &pRuleEntry->entry);

    sl_unlock(&lh);	

	return TRUE;
}


/**
 *	Remove all rules from temp list
 */
void srvrules_remove_all_temp()
{
	PSRV_RULE_ENTRY pRule;
    KLOCK_QUEUE_HANDLE lh;

    sl_lock(&g_slRules, &lh);	

	while (!IsListEmpty(&g_lTempRules))
	{
		pRule = (PSRV_RULE_ENTRY)RemoveHeadList(&g_lTempRules);
		ExFreeToNPagedLookasideList( &g_rulesLAList, pRule );
	}

	sl_unlock(&lh);	
}

/**
 *  Assign temp rules list as current
 */
void srvrules_set_temp()
{
    KLOCK_QUEUE_HANDLE lh;
	PSRV_RULE_ENTRY pRule;

    sl_lock(&g_slRules, &lh);	

	while (!IsListEmpty(&g_lRules))
	{
		pRule = (PSRV_RULE_ENTRY)RemoveHeadList(&g_lRules);
		ExFreeToNPagedLookasideList( &g_rulesLAList, pRule );
	}

	while (!IsListEmpty(&g_lTempRules))
	{
		pRule = (PSRV_RULE_ENTRY)RemoveHeadList(&g_lTempRules);
		InsertTailList(&g_lRules, &pRule->entry);
	}

    sl_unlock(&lh);	
}


static BOOLEAN isZeroBuffer(const unsigned char * buf, int len)
{
	int i;
	for (i=0; i<len; i++)
	{
		if (buf[i] != 0)
			return FALSE;
	}
	return TRUE;
}

static BOOLEAN 
srvrules_isEqualIpAddresses(USHORT family,
							gen_addr * pRuleAddress, 
							gen_addr * pRuleAddressMask,
							NF_ADDRESS * pAddress)
{
	switch (family)
	{
	case AF_INET:
		if (!pRuleAddress->sin_addr.S_un.S_addr)
			return TRUE;

		if (pRuleAddressMask->sin_addr.S_un.S_addr)
		{
			return (pAddress->ip.v4 & pRuleAddressMask->sin_addr.S_un.S_addr) ==
				(pRuleAddress->sin_addr.S_un.S_addr & pRuleAddressMask->sin_addr.S_un.S_addr);
		} else
		{
			return pAddress->ip.v4 == pRuleAddress->sin_addr.S_un.S_addr;
		}
		break;

	case AF_INET6:
		{
			int i;

			if (isZeroBuffer((unsigned char *)&pRuleAddress->sin6_addr, sizeof(pRuleAddress->sin6_addr)))
				return TRUE;

			if (!isZeroBuffer((unsigned char *)&pRuleAddressMask->sin6_addr, sizeof(pRuleAddressMask->sin6_addr)))
			{
				for (i=0; i<8; i++)
				{
					if ((pRuleAddress->sin6_addr.u.Word[i] & pRuleAddressMask->sin6_addr.u.Word[i]) !=
						(((unsigned short*)pAddress->ip.v6)[i] & pRuleAddressMask->sin6_addr.u.Word[i]))
					{
						return FALSE;
					}
				}

				return TRUE;
			} else
			{
				for (i=0; i<8; i++)
				{
					if (pRuleAddress->sin6_addr.u.Word[i] != ((unsigned short*)pAddress->ip.v6)[i])
					{
						return FALSE;
					}
				}

				return TRUE;
			}
		}
		break;

	default:
		break;
	}

	return FALSE;
}

#define PORT_IN_RANGE(port, portRange) ((portRange.valueLow == 0 && portRange.valueHigh == 0) || ((port >= portRange.valueLow) && (port <= portRange.valueHigh)))

BOOLEAN srvrules_find(PSRV_PACKET_INFO pPacketInfo, PNF_SRV_RULE_ACTION pAction)
{
	PSRV_RULE_ENTRY	pRuleEntry;
	PNF_SRV_RULE	pRule;
	NF_ADDRESS * pSrcAddress = NULL;
	NF_ADDRESS * pDstAddress = NULL;
	unsigned short srcPort = 0;
	unsigned short dstPort = 0;
	gen_addr * pRuleSrcIpAddress = NULL;
	gen_addr * pRuleSrcIpAddressMask = NULL;
	gen_addr * pRuleDstIpAddress = NULL;
	gen_addr * pRuleDstIpAddressMask = NULL;
    KLOCK_QUEUE_HANDLE lh;

#ifdef _DEMO
	static unsigned int counter = (unsigned int)10000000;
	if (counter == 0)
	{
		return FALSE;
	}		
	counter--;
#endif

	memset(pAction, 0, sizeof(*pAction));
	pAction->filteringFlag = NF_SRV_ALLOW;

	if (!devctrl_isProxyAttached())
	{
		return FALSE;
	}
	
	pSrcAddress = &pPacketInfo->srcAddress;
	pDstAddress = &pPacketInfo->dstAddress;
	srcPort = htons(pSrcAddress->port);
	dstPort = htons(pDstAddress->port);

    sl_lock(&g_slRules, &lh);	

	if (IsListEmpty(&g_lRules))
	{
		sl_unlock(&lh);	
		return FALSE;
	}

	for (pRuleEntry = (PSRV_RULE_ENTRY)g_lRules.Flink;
		pRuleEntry != (PSRV_RULE_ENTRY)&g_lRules;
		pRuleEntry = (PSRV_RULE_ENTRY)pRuleEntry->entry.Flink)
	{
		pRule = &pRuleEntry->rule;

		if ((pRule->protocol != 0) && (pRule->protocol != pPacketInfo->protocol))
		{
			continue;
		}

		if ((pRule->interfaceLuid != 0) && (pRule->interfaceLuid != pPacketInfo->interfaceLuid))
		{
			continue;
		}

		if (pPacketInfo->protocol == IPPROTO_TCP ||
			pPacketInfo->protocol == IPPROTO_UDP)
		{
			if (pRule->direction == NF_SRV_D_BOTH)
			{
				if (!(
					(PORT_IN_RANGE(srcPort, pRule->srcPort) && PORT_IN_RANGE(dstPort, pRule->dstPort)) ||
					(PORT_IN_RANGE(dstPort, pRule->srcPort) && PORT_IN_RANGE(srcPort, pRule->dstPort))
					))
				{
					continue;
				}

			} else
			{
				if (!PORT_IN_RANGE(srcPort, pRule->srcPort) || !PORT_IN_RANGE(dstPort, pRule->dstPort))
				{
					continue;
				}
			}
		}

		pRuleSrcIpAddress = (gen_addr*)pRule->srcIpAddress;
		pRuleDstIpAddress = (gen_addr*)pRule->dstIpAddress;
		pRuleSrcIpAddressMask = (gen_addr*)pRule->srcIpAddressMask;
		pRuleDstIpAddressMask = (gen_addr*)pRule->dstIpAddressMask;
		
		if (pRule->ip_family != 0)
		{
			if (pRule->ip_family != pSrcAddress->ipFamily)
				continue;

			if (pRule->direction == NF_SRV_D_BOTH)
			{
				if (!(
						(
							srvrules_isEqualIpAddresses(
								pRule->ip_family,
								pRuleSrcIpAddress,
								pRuleSrcIpAddressMask,
								pSrcAddress
								) &&
							srvrules_isEqualIpAddresses(
								pRule->ip_family,
								pRuleDstIpAddress,
								pRuleDstIpAddressMask,
								pDstAddress
								)
						) ||
						(
							srvrules_isEqualIpAddresses(
								pRule->ip_family,
								pRuleSrcIpAddress,
								pRuleSrcIpAddressMask,
								pDstAddress
								) &&
							srvrules_isEqualIpAddresses(
								pRule->ip_family,
								pRuleDstIpAddress,
								pRuleDstIpAddressMask,
								pSrcAddress
								)
						)
					))
				{
					continue;
				}
			} else
			{
				if (!srvrules_isEqualIpAddresses(
						pRule->ip_family,
						pRuleSrcIpAddress,
						pRuleSrcIpAddressMask,
						pSrcAddress
						))
				{
					continue;
				}

				if (!srvrules_isEqualIpAddresses(
						pRule->ip_family,
						pRuleDstIpAddress,
						pRuleDstIpAddressMask,
						pDstAddress
						))
				{
					continue;
				}
			}
		}
		
		*pAction = pRule->action;

		sl_unlock(&lh);	

		return TRUE;
	}

	sl_unlock(&lh);	

	return FALSE;
}
