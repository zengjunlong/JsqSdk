//
// 	NetFilterSDK 
// 	Copyright (C) 2013 Vitaly Sidorov
//	All rights reserved.
//
//	This file is a part of the NetFilter SDK.
//	The code and information is provided "as-is" without
//	warranty of any kind, either expressed or implied.
//


#include "stdinc.h"
#include "rules.h"
#include "devctrl.h"

#define PORT_IN_RANGE(port, portRange) ((portRange.valueLow == 0 && portRange.valueHigh == 0) || ((port >= portRange.valueLow) && (port <= portRange.valueHigh)))

typedef UNALIGNED union _gen_addr
{
    struct in_addr sin_addr;
    struct in6_addr sin6_addr;
} gen_addr;

typedef struct _RULE_ENTRY
{
	LIST_ENTRY		entry;
	NF_RULE_EX		rule;
	PISID			pPackageSid;
} RULE_ENTRY, *PRULE_ENTRY; 

static NPAGED_LOOKASIDE_LIST g_rulesLAList;
static LIST_ENTRY g_lRules;
static KSPIN_LOCK g_slRules;
static BOOLEAN	  g_initialized = FALSE;

static ULONG	g_rulesMask;

static LIST_ENTRY g_lTempRules;

typedef struct _BINDING_RULE_ENTRY
{
	LIST_ENTRY			entry;
	NF_BINDING_RULE		rule;
	PISID				pPackageSid;
} BINDING_RULE_ENTRY, *PBINDING_RULE_ENTRY; 

static NPAGED_LOOKASIDE_LIST g_bindingRulesLAList;
static LIST_ENTRY g_lBindingRules;

static BOOLEAN
rules_convertUnicodeSidtoSid(wchar_t * pUnicodeSid, PISID* ppSid);

static BOOLEAN rules_equalSid(PISID pSid1, PISID pSid2);

NTSTATUS rules_init()
{
	InitializeListHead(&g_lRules);
	sl_init(&g_slRules);

    ExInitializeNPagedLookasideList( &g_rulesLAList,
                                     NULL,
                                     NULL,
                                     0,
                                     sizeof( RULE_ENTRY ),
                                     MEM_TAG,
                                     0 );

	InitializeListHead(&g_lTempRules);

	InitializeListHead(&g_lBindingRules);

    ExInitializeNPagedLookasideList( &g_bindingRulesLAList,
                                     NULL,
                                     NULL,
                                     0,
                                     sizeof( BINDING_RULE_ENTRY ),
                                     MEM_TAG,
                                     0 );

	g_initialized = TRUE;

	g_rulesMask = RM_NONE;

	return STATUS_SUCCESS;
}

void rules_free()
{
	KdPrint((DPREFIX"rules_free\n"));

	if (g_initialized)
	{
		rules_remove_all();
		rules_remove_all_temp();
		ExDeleteNPagedLookasideList( &g_rulesLAList );
		ExDeleteNPagedLookasideList( &g_bindingRulesLAList );
		g_initialized = FALSE;
	}
}

ULONG rules_getRulesMask()
{
    KLOCK_QUEUE_HANDLE lh;
	ULONG mask;

    sl_lock(&g_slRules, &lh);	
	mask = g_rulesMask;
	sl_unlock(&lh);	

	return mask;
}

PRULE_ENTRY rules_allocateRuleEntry()
{
	PRULE_ENTRY pRuleEntry;

	pRuleEntry = (PRULE_ENTRY)ExAllocateFromNPagedLookasideList( &g_rulesLAList );
	if (!pRuleEntry)
		return NULL;

	memset(pRuleEntry, 0, sizeof(RULE_ENTRY));
	
	return pRuleEntry;
}

void rules_freeRuleEntry(PRULE_ENTRY pRuleEntry)
{
	if (pRuleEntry->pPackageSid)
	{
		free_np(pRuleEntry->pPackageSid);
	}
	ExFreeToNPagedLookasideList( &g_rulesLAList, pRuleEntry );
}

/**
 *  Add RULE to linked list
 */
void rules_add(PNF_RULE pRule, BOOLEAN toHead)
{
    KLOCK_QUEUE_HANDLE lh;
	PRULE_ENTRY pRuleEntry;

	pRuleEntry = rules_allocateRuleEntry();
	if (!pRuleEntry)
		return;

	memcpy(&pRuleEntry->rule, pRule, sizeof(NF_RULE));

    sl_lock(&g_slRules, &lh);	

	if (toHead)
	{
		InsertHeadList(&g_lRules, &pRuleEntry->entry);
	} else
	{
		InsertTailList(&g_lRules, &pRuleEntry->entry);
	}

	if (pRule->protocol == IPPROTO_TCP)
	{
		g_rulesMask |= RM_TCP;

		if (pRule->ip_family == AF_INET6)
		{
			unsigned char loopbackAddr[NF_MAX_IP_ADDRESS_LENGTH] = { 0 };

			loopbackAddr[NF_MAX_IP_ADDRESS_LENGTH-1] = 1;

			if (_memcmp(pRule->localIpAddress, loopbackAddr, NF_MAX_IP_ADDRESS_LENGTH) == 0)
			{
				g_rulesMask |= RM_LOCAL_IPV6;
			} else
			if (_memcmp(pRule->remoteIpAddress, loopbackAddr, NF_MAX_IP_ADDRESS_LENGTH) == 0)
			{
				g_rulesMask |= RM_LOCAL_IPV6;
			} 
		}

	} else
	if (pRule->protocol == IPPROTO_UDP)
	{
		g_rulesMask |= RM_UDP;
	} 

	if (pRule->filteringFlag & NF_FILTER_AS_IP_PACKETS)
	{
		g_rulesMask |= RM_IP;
	}

    sl_unlock(&lh);	
}

/**
 *  Add RULE to linked list
 */
void rules_addEx(PNF_RULE_EX pRule, BOOLEAN toHead)
{
    KLOCK_QUEUE_HANDLE lh;
	PRULE_ENTRY pRuleEntry;

	pRuleEntry = rules_allocateRuleEntry();
	if (!pRuleEntry)
		return;

	memcpy(&pRuleEntry->rule, pRule, sizeof(NF_RULE_EX));

	if (pRuleEntry->rule.processName[0] != 0)
	{
		if (rules_convertUnicodeSidtoSid((wchar_t*)pRuleEntry->rule.processName, &pRuleEntry->pPackageSid))
		{
			pRuleEntry->rule.processName[0] = 0;
		}
	}

    sl_lock(&g_slRules, &lh);	

	if (toHead)
	{
		InsertHeadList(&g_lRules, &pRuleEntry->entry);
	} else
	{
		InsertTailList(&g_lRules, &pRuleEntry->entry);
	}

	if (pRule->protocol == IPPROTO_TCP)
	{
		g_rulesMask |= RM_TCP;

		if (pRule->ip_family == AF_INET6)
		{
			unsigned char loopbackAddr[NF_MAX_IP_ADDRESS_LENGTH] = { 0 };

			loopbackAddr[NF_MAX_IP_ADDRESS_LENGTH-1] = 1;

			if (_memcmp(pRule->localIpAddress, loopbackAddr, NF_MAX_IP_ADDRESS_LENGTH) == 0)
			{
				g_rulesMask |= RM_LOCAL_IPV6;
			} else
			if (_memcmp(pRule->remoteIpAddress, loopbackAddr, NF_MAX_IP_ADDRESS_LENGTH) == 0)
			{
				g_rulesMask |= RM_LOCAL_IPV6;
			} 
		}

	} else
	if (pRule->protocol == IPPROTO_UDP)
	{
		g_rulesMask |= RM_UDP;
	} 

	if (pRule->filteringFlag & NF_FILTER_AS_IP_PACKETS)
	{
		g_rulesMask |= RM_IP;
	}

    sl_unlock(&lh);	
}

/**
 *	Remove all rules from list
 */
void rules_remove_all()
{
	PRULE_ENTRY pRule;
    KLOCK_QUEUE_HANDLE lh;

    sl_lock(&g_slRules, &lh);	

	while (!IsListEmpty(&g_lRules))
	{
		pRule = (PRULE_ENTRY)RemoveHeadList(&g_lRules);
		rules_freeRuleEntry( pRule );
	}

	g_rulesMask = RM_NONE;

	sl_unlock(&lh);	

	rules_bindingRemove_all();
}


/**
 *  Add RULE to temp linked list
 */
BOOLEAN rules_add_temp(PNF_RULE pRule)
{
    KLOCK_QUEUE_HANDLE lh;
	PRULE_ENTRY pRuleEntry;

	pRuleEntry = rules_allocateRuleEntry();
	if (!pRuleEntry)
		return FALSE;

	memcpy(&pRuleEntry->rule, pRule, sizeof(NF_RULE));

    sl_lock(&g_slRules, &lh);	

	InsertTailList(&g_lTempRules, &pRuleEntry->entry);

    sl_unlock(&lh);	

	return TRUE;
}

/**
 *  Add RULE to temp linked list
 */
BOOLEAN rules_add_tempEx(PNF_RULE_EX pRule)
{
    KLOCK_QUEUE_HANDLE lh;
	PRULE_ENTRY pRuleEntry;

	pRuleEntry = rules_allocateRuleEntry();
	if (!pRuleEntry)
		return FALSE;

	memcpy(&pRuleEntry->rule, pRule, sizeof(NF_RULE_EX));

	if (pRuleEntry->rule.processName[0] != 0)
	{
		if (rules_convertUnicodeSidtoSid((wchar_t*)pRuleEntry->rule.processName, &pRuleEntry->pPackageSid))
		{
			pRuleEntry->rule.processName[0] = 0;
		}
	}

	sl_lock(&g_slRules, &lh);

	InsertTailList(&g_lTempRules, &pRuleEntry->entry);

    sl_unlock(&lh);	

	return TRUE;
}

/**
 *	Remove all rules from temp list
 */
void rules_remove_all_temp()
{
	PRULE_ENTRY pRule;
    KLOCK_QUEUE_HANDLE lh;

    sl_lock(&g_slRules, &lh);	

	while (!IsListEmpty(&g_lTempRules))
	{
		pRule = (PRULE_ENTRY)RemoveHeadList(&g_lTempRules);
		rules_freeRuleEntry( pRule );
	}

	sl_unlock(&lh);	
}

/**
 *  Assign temp rules list as current
 */
void rules_set_temp()
{
    KLOCK_QUEUE_HANDLE lh;
	PRULE_ENTRY pRule;

    sl_lock(&g_slRules, &lh);	

	while (!IsListEmpty(&g_lRules))
	{
		pRule = (PRULE_ENTRY)RemoveHeadList(&g_lRules);
		rules_freeRuleEntry( pRule );
	}

	g_rulesMask = RM_NONE;

	while (!IsListEmpty(&g_lTempRules))
	{
		pRule = (PRULE_ENTRY)RemoveHeadList(&g_lTempRules);

		InsertTailList(&g_lRules, &pRule->entry);

		if (pRule->rule.protocol == IPPROTO_TCP)
		{
			g_rulesMask |= RM_TCP;

			if (pRule->rule.ip_family == AF_INET6)
			{
				unsigned char loopbackAddr[NF_MAX_IP_ADDRESS_LENGTH] = { 0 };

				loopbackAddr[NF_MAX_IP_ADDRESS_LENGTH-1] = 1;

				if (_memcmp(pRule->rule.localIpAddress, loopbackAddr, NF_MAX_IP_ADDRESS_LENGTH) == 0)
				{
					g_rulesMask |= RM_LOCAL_IPV6;
				} else
				if (_memcmp(pRule->rule.remoteIpAddress, loopbackAddr, NF_MAX_IP_ADDRESS_LENGTH) == 0)
				{
					g_rulesMask |= RM_LOCAL_IPV6;
				} 
			}
		} else
		if (pRule->rule.protocol == IPPROTO_UDP)
		{
			g_rulesMask |= RM_UDP;
		} 

		if (pRule->rule.filteringFlag & NF_FILTER_AS_IP_PACKETS)
		{
			g_rulesMask |= RM_IP;
		}
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

/**
*	Returns TRUE if pAddress matches pRuleAddress/pRuleAddressMask
*/
static BOOLEAN rules_isEqualIpAddresses(USHORT family,
								gen_addr * pRuleAddress, 
								gen_addr * pRuleAddressMask,
								gen_addr * pAddress)
{
	switch (family)
	{
	case AF_INET:
		if (!pRuleAddress->sin_addr.S_un.S_addr)
			return TRUE;

		if (pRuleAddressMask->sin_addr.S_un.S_addr)
		{
			return (pAddress->sin_addr.S_un.S_addr & pRuleAddressMask->sin_addr.S_un.S_addr) ==
				(pRuleAddress->sin_addr.S_un.S_addr & pRuleAddressMask->sin_addr.S_un.S_addr);
		} else
		{
			return pAddress->sin_addr.S_un.S_addr == pRuleAddress->sin_addr.S_un.S_addr;
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
						(pAddress->sin6_addr.u.Word[i] & pRuleAddressMask->sin6_addr.u.Word[i]))
					{
						return FALSE;
					}
				}

				return TRUE;
			} else
			{
				for (i=0; i<8; i++)
				{
					if (pRuleAddress->sin6_addr.u.Word[i] != pAddress->sin6_addr.u.Word[i])
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

BOOLEAN rules_nameMatches(const wchar_t * mask, size_t maskLen, const wchar_t * name, size_t nameLen)
{
	const wchar_t *p, *s;

	s = mask;
	p = name;

	while (maskLen > 0 && nameLen > 0)
	{
		if (*s == L'*')
		{
			s--;
			maskLen--;
			while (nameLen > 0)
			{
				if (rules_nameMatches(s, maskLen, p, nameLen))
				{
					return TRUE;
				}
				p--;
				nameLen--;
			}
			return (maskLen == 0);
		}

		if (*s != *p)
			return FALSE;

		s--;
		maskLen--;

		p--;
		nameLen--;
	}

	if (maskLen == 0)
	{
		return TRUE;
	}

	if (maskLen == 1 && nameLen == 0 && *s == L'*')
	{
		return TRUE;
	}

	return FALSE;
}


/**
* Search the list of rules and return the flag of a first rule that matches pCtx
* @return NF_FILTERING_FLAG 
* @param pCtx 
**/
NF_FILTERING_FLAG rules_findByTcpCtx(PTCPCTX pCtx, PNF_RULE_EX pMatchingRule)
{
	PRULE_ENTRY	pRuleEntry;
	PNF_RULE_EX	pRule;
	sockaddr_gen * pLocalAddress = NULL;
	sockaddr_gen * pRemoteAddress = NULL;
	gen_addr * pRuleLocalIpAddress = NULL;
	gen_addr * pRuleLocalIpAddressMask = NULL;
	gen_addr * pRuleRemoteIpAddress = NULL;
	gen_addr * pRuleRemoteIpAddressMask = NULL;
	NF_FILTERING_FLAG flag = NF_ALLOW;
	size_t processNameLen = 0;
	unsigned short localPortHostOrder;
	unsigned short remotePortHostOrder;
    KLOCK_QUEUE_HANDLE lh;

#ifdef _DEMO
	static unsigned int counter = (unsigned int)(100 * 1000 * 1000);
	if (counter == 0)
	{
		return NF_ALLOW;
	}		
	counter--;
#endif

	if (!devctrl_isProxyAttached() ||
		(pCtx->processId == devctrl_getProxyPid()))
	{
		return NF_ALLOW;
	}
	
	pLocalAddress = (sockaddr_gen*)pCtx->localAddr;
	pRemoteAddress = (sockaddr_gen*)pCtx->remoteAddr;

	localPortHostOrder = htons(pLocalAddress->AddressIn.sin_port);
	remotePortHostOrder = htons(pRemoteAddress->AddressIn.sin_port);

	if (!(rules_getRulesMask() & RM_LOCAL_IPV6))
	{
		if (pRemoteAddress->AddressIn.sin_family == AF_INET6)
		{
			unsigned char loopbackAddr[NF_MAX_IP_ADDRESS_LENGTH] = { 0 };
			unsigned char * ipAddress = (pCtx->direction == NF_D_IN)? 
				pLocalAddress->AddressIn6.sin6_addr.u.Byte :
				pRemoteAddress->AddressIn6.sin6_addr.u.Byte;

			loopbackAddr[NF_MAX_IP_ADDRESS_LENGTH-1] = 1;

			// Do not filter local IPv6 connections
			if (_memcmp(ipAddress, loopbackAddr, NF_MAX_IP_ADDRESS_LENGTH) == 0)
			{
				return NF_ALLOW;
			}
		}
	}

	if (pCtx->processName[0] != 0)
	{
		processNameLen = wcslen((wchar_t*)&pCtx->processName);
	}

	sl_lock(&g_slRules, &lh);	

	if (IsListEmpty(&g_lRules))
	{
		sl_unlock(&lh);	
		return NF_ALLOW;
	}

	pRuleEntry = (PRULE_ENTRY)g_lRules.Flink;

	while (pRuleEntry != (PRULE_ENTRY)&g_lRules)
	{
		pRule = &pRuleEntry->rule;

		if (pRule->filteringFlag & NF_FILTER_AS_IP_PACKETS)
		{
			goto next_rule;
		}

		if ((pRule->processId != 0) && (pRule->processId != pCtx->processId))
		{
			goto next_rule;
		}

		if ((pRule->protocol != 0) && (pRule->protocol != IPPROTO_TCP))
		{
			goto next_rule;
		}

		if ((pRule->direction != 0) && !(pRule->direction & pCtx->direction))
		{
			goto next_rule;
		}

		if ((pRule->localPort != 0) && (pRule->localPort != pLocalAddress->AddressIn.sin_port))
		{
			goto next_rule;
		}

		if ((pRule->remotePort != 0) && (pRule->remotePort != pRemoteAddress->AddressIn.sin_port))
		{
			goto next_rule;
		}

		if ((pRule->localPortRange.valueLow != 0) || (pRule->localPortRange.valueHigh != 0))
		{
			if (!PORT_IN_RANGE(localPortHostOrder, pRule->localPortRange))
			{
				goto next_rule;
			}
		}

		if ((pRule->remotePortRange.valueLow != 0) || (pRule->remotePortRange.valueHigh != 0))
		{
			if (!PORT_IN_RANGE(remotePortHostOrder, pRule->remotePortRange))
			{
				goto next_rule;
			}
		}

		pRuleLocalIpAddress = (gen_addr*)pRule->localIpAddress;
		pRuleRemoteIpAddress = (gen_addr*)pRule->remoteIpAddress;
		pRuleLocalIpAddressMask = (gen_addr*)pRule->localIpAddressMask;
		pRuleRemoteIpAddressMask = (gen_addr*)pRule->remoteIpAddressMask;
		
		if (pRule->ip_family != 0)
		{
			if (pRule->ip_family != pLocalAddress->AddressIn.sin_family)
				goto next_rule;

			switch (pRule->ip_family)
			{
			case AF_INET:
				
				if (!rules_isEqualIpAddresses(
						AF_INET,
						pRuleLocalIpAddress,
						pRuleLocalIpAddressMask,
						(gen_addr*)&pLocalAddress->AddressIn.sin_addr
						))
				{
					goto next_rule;
				}

				if (!rules_isEqualIpAddresses(
						AF_INET,
						pRuleRemoteIpAddress,
						pRuleRemoteIpAddressMask,
						(gen_addr*)&pRemoteAddress->AddressIn.sin_addr
						))
				{
					goto next_rule;
				}

				break;

			case AF_INET6:
				
				if (!rules_isEqualIpAddresses(
						AF_INET6,
						pRuleLocalIpAddress,
						pRuleLocalIpAddressMask,
						(gen_addr*)&pLocalAddress->AddressIn6.sin6_addr
						))
				{
					goto next_rule;
				}

				if (!rules_isEqualIpAddresses(
						AF_INET6,
						pRuleRemoteIpAddress,
						pRuleRemoteIpAddressMask,
						(gen_addr*)&pRemoteAddress->AddressIn6.sin6_addr
						))
				{
					goto next_rule;
				}

				break;

			default:
				break;
			}
		}
		
		if (pRule->processName[0] != 0)
		{
			size_t len;
			
			len = wcslen((wchar_t*)&pRule->processName);

			if (!rules_nameMatches(
					(wchar_t*)&pRule->processName + len - 1, len, 
					(wchar_t*)&pCtx->processName + processNameLen - 1, processNameLen))
			{
				goto next_rule;
			}
		}

		if (pRuleEntry->pPackageSid)
		{
			if (!pCtx->pPackageSid)
			{
				goto next_rule;
			}

			if (!rules_equalSid(pRuleEntry->pPackageSid, pCtx->pPackageSid))
			{
				goto next_rule;
			}
		}

		flag = pRule->filteringFlag;

		if (pMatchingRule)
		{
			memcpy(pMatchingRule, pRule, sizeof(NF_RULE_EX));
		}

		sl_unlock(&lh);	

		return flag;

next_rule:
		
		pRuleEntry = (PRULE_ENTRY)pRuleEntry->entry.Flink;
	}

	sl_unlock(&lh);	

	return NF_ALLOW;
}


NF_FILTERING_FLAG rules_findByUdpInfo(PUDPCTX pCtx, char * remoteAddress, UCHAR direction)
{
	PRULE_ENTRY	pRuleEntry;
	PNF_RULE_EX	pRule;
	sockaddr_gen * pLocalAddress = NULL;
	sockaddr_gen * pRemoteAddress = NULL;
	gen_addr * pRuleLocalIpAddress = NULL;
	gen_addr * pRuleLocalIpAddressMask = NULL;
	gen_addr * pRuleRemoteIpAddress = NULL;
	gen_addr * pRuleRemoteIpAddressMask = NULL;
	NF_FILTERING_FLAG flag = NF_ALLOW;
	size_t processNameLen = 0;
	unsigned short localPortHostOrder;
	unsigned short remotePortHostOrder;
    KLOCK_QUEUE_HANDLE lh;

#ifdef _DEMO
	static unsigned int counter = (unsigned int)(100 * 1000 * 1000);
	if (counter == 0)
	{
		return NF_ALLOW;
	}		
	counter--;
#endif

	if (!devctrl_isProxyAttached() ||
		(pCtx->processId == devctrl_getProxyPid()))
	{
		return NF_ALLOW;
	}
	
	pLocalAddress = (sockaddr_gen*)pCtx->localAddr;
	pRemoteAddress = (sockaddr_gen*)remoteAddress;

	localPortHostOrder = htons(pLocalAddress->AddressIn.sin_port);
	remotePortHostOrder = htons(pRemoteAddress->AddressIn.sin_port);

	if (pCtx->processName[0] != 0)
	{
		processNameLen = wcslen((wchar_t*)&pCtx->processName);
	}

	sl_lock(&g_slRules, &lh);	

	if (IsListEmpty(&g_lRules))
	{
		sl_unlock(&lh);	
		return NF_ALLOW;
	}

	pRuleEntry = (PRULE_ENTRY)g_lRules.Flink;

	while (pRuleEntry != (PRULE_ENTRY)&g_lRules)
	{
		pRule = &pRuleEntry->rule;

		if (pRule->filteringFlag & NF_FILTER_AS_IP_PACKETS)
		{
			goto next_rule;
		}

		if ((pRule->protocol != 0) && (pRule->protocol != IPPROTO_UDP))
		{
			goto next_rule;
		}

		if ((pRule->processId != 0) && (pRule->processId != pCtx->processId))
		{
			goto next_rule;
		}

		if ((pRule->direction != 0) && !(pRule->direction & direction))
		{
			goto next_rule;
		}

		if ((pRule->localPort != 0) && (pRule->localPort != pLocalAddress->AddressIn.sin_port))
		{
			goto next_rule;
		}

		if ((pRule->remotePort != 0) && (pRule->remotePort != pRemoteAddress->AddressIn.sin_port))
		{
			goto next_rule;
		}

		if ((pRule->localPortRange.valueLow != 0) || (pRule->localPortRange.valueHigh != 0))
		{
			if (!PORT_IN_RANGE(localPortHostOrder, pRule->localPortRange))
			{
				goto next_rule;
			}
		}

		if ((pRule->remotePortRange.valueLow != 0) || (pRule->remotePortRange.valueHigh != 0))
		{
			if (!PORT_IN_RANGE(remotePortHostOrder, pRule->remotePortRange))
			{
				goto next_rule;
			}
		}

		pRuleLocalIpAddress = (gen_addr*)pRule->localIpAddress;
		pRuleRemoteIpAddress = (gen_addr*)pRule->remoteIpAddress;
		pRuleLocalIpAddressMask = (gen_addr*)pRule->localIpAddressMask;
		pRuleRemoteIpAddressMask = (gen_addr*)pRule->remoteIpAddressMask;
		
		if (pRule->ip_family != 0)
		{
			if (pRule->ip_family != pLocalAddress->AddressIn.sin_family)
				goto next_rule;

			switch (pRule->ip_family)
			{
			case AF_INET:
				
				if (!rules_isEqualIpAddresses(
						AF_INET,
						pRuleLocalIpAddress,
						pRuleLocalIpAddressMask,
						(gen_addr*)&pLocalAddress->AddressIn.sin_addr
						))
				{
					goto next_rule;
				}

				if (!rules_isEqualIpAddresses(
						AF_INET,
						pRuleRemoteIpAddress,
						pRuleRemoteIpAddressMask,
						(gen_addr*)&pRemoteAddress->AddressIn.sin_addr
						))
				{
					goto next_rule;
				}

				break;

			case AF_INET6:
				
				if (!rules_isEqualIpAddresses(
						AF_INET6,
						pRuleLocalIpAddress,
						pRuleLocalIpAddressMask,
						(gen_addr*)&pLocalAddress->AddressIn6.sin6_addr
						))
				{
					goto next_rule;
				}

				if (!rules_isEqualIpAddresses(
						AF_INET6,
						pRuleRemoteIpAddress,
						pRuleRemoteIpAddressMask,
						(gen_addr*)&pRemoteAddress->AddressIn6.sin6_addr
						))
				{
					goto next_rule;
				}

				break;

			default:
				break;
			}
		}
		
		if (pRule->processName[0] != 0)
		{
			size_t len;
			
			len = wcslen((wchar_t*)&pRule->processName);

			if (!rules_nameMatches(
					(wchar_t*)&pRule->processName + len - 1, len, 
					(wchar_t*)&pCtx->processName + processNameLen - 1, processNameLen))
			{
				goto next_rule;
			}
		}

		if (pRuleEntry->pPackageSid)
		{
			if (!pCtx->pPackageSid)
			{
				goto next_rule;
			}

			if (!rules_equalSid(pRuleEntry->pPackageSid, pCtx->pPackageSid))
			{
				goto next_rule;
			}
		}

		flag = pRule->filteringFlag;

		sl_unlock(&lh);	

		return flag;

next_rule:
		
		pRuleEntry = (PRULE_ENTRY)pRuleEntry->entry.Flink;
	}

	sl_unlock(&lh);	

	return NF_ALLOW;
}


NF_FILTERING_FLAG rules_findByIPInfo(PPACKET_INFO pPacketInfo)
{
	PRULE_ENTRY	pRuleEntry;
	PNF_RULE_EX	pRule;
	sockaddr_gen * pLocalAddress = NULL;
	sockaddr_gen * pRemoteAddress = NULL;
	gen_addr * pRuleLocalIpAddress = NULL;
	gen_addr * pRuleLocalIpAddressMask = NULL;
	gen_addr * pRuleRemoteIpAddress = NULL;
	gen_addr * pRuleRemoteIpAddressMask = NULL;
	NF_FILTERING_FLAG flag = NF_ALLOW;
	unsigned short localPortHostOrder;
	unsigned short remotePortHostOrder;
    KLOCK_QUEUE_HANDLE lh;

#ifdef _DEMO
	static unsigned int counter = (unsigned int)(100 * 1000 * 1000);
	if (counter == 0)
	{
		return NF_ALLOW;
	}		
	counter--;
#endif

	if (!devctrl_isProxyAttached())
	{
		return NF_ALLOW;
	}
	
	pLocalAddress = &pPacketInfo->localAddress;
	pRemoteAddress = &pPacketInfo->remoteAddress;

	localPortHostOrder = htons(pLocalAddress->AddressIn.sin_port);
	remotePortHostOrder = htons(pRemoteAddress->AddressIn.sin_port);

	sl_lock(&g_slRules, &lh);	

	if (IsListEmpty(&g_lRules))
	{
		sl_unlock(&lh);	
		return NF_ALLOW;
	}

	pRuleEntry = (PRULE_ENTRY)g_lRules.Flink;

	while (pRuleEntry != (PRULE_ENTRY)&g_lRules)
	{
		pRule = &pRuleEntry->rule;

		if (!(pRule->filteringFlag & NF_FILTER_AS_IP_PACKETS))
		{
			goto next_rule;
		}

		if ((pRule->direction != 0) && !(pRule->direction & pPacketInfo->direction))
		{
			goto next_rule;
		}

		if ((pRule->protocol != 0) && (pRule->protocol != pPacketInfo->protocol))
		{
			goto next_rule;
		}

		if ((pRule->localPort != 0) || (pRule->remotePort != 0))
		{
			if (pPacketInfo->protocol == IPPROTO_TCP ||
				pPacketInfo->protocol == IPPROTO_UDP)
			{
				if ((pRule->localPort != 0) && (pRule->localPort != pLocalAddress->AddressIn.sin_port))
				{
					goto next_rule;
				}

				if ((pRule->remotePort != 0) && (pRule->remotePort != pRemoteAddress->AddressIn.sin_port))
				{
					goto next_rule;
				}
			} else
			{
				goto next_rule;
			}
		}

		if ((pRule->localPortRange.valueLow != 0) || (pRule->localPortRange.valueHigh != 0))
		{
			if (pPacketInfo->protocol == IPPROTO_TCP ||
				pPacketInfo->protocol == IPPROTO_UDP)
			{
				if (!PORT_IN_RANGE(localPortHostOrder, pRule->localPortRange))
				{
					goto next_rule;
				}
			} else
			{
				goto next_rule;
			}
		}

		if ((pRule->remotePortRange.valueLow != 0) || (pRule->remotePortRange.valueHigh != 0))
		{
			if (pPacketInfo->protocol == IPPROTO_TCP ||
				pPacketInfo->protocol == IPPROTO_UDP)
			{
				if (!PORT_IN_RANGE(remotePortHostOrder, pRule->remotePortRange))
				{
					goto next_rule;
				}
			} else
			{
				goto next_rule;
			}
		}

		pRuleLocalIpAddress = (gen_addr*)pRule->localIpAddress;
		pRuleRemoteIpAddress = (gen_addr*)pRule->remoteIpAddress;
		pRuleLocalIpAddressMask = (gen_addr*)pRule->localIpAddressMask;
		pRuleRemoteIpAddressMask = (gen_addr*)pRule->remoteIpAddressMask;
		
		if (pRule->ip_family != 0)
		{
			if (pRule->ip_family != pLocalAddress->AddressIn.sin_family)
				goto next_rule;

			switch (pRule->ip_family)
			{
			case AF_INET:
				
				if (!rules_isEqualIpAddresses(
						AF_INET,
						pRuleLocalIpAddress,
						pRuleLocalIpAddressMask,
						(gen_addr*)&pLocalAddress->AddressIn.sin_addr
						))
				{
					goto next_rule;
				}

				if (!rules_isEqualIpAddresses(
						AF_INET,
						pRuleRemoteIpAddress,
						pRuleRemoteIpAddressMask,
						(gen_addr*)&pRemoteAddress->AddressIn.sin_addr
						))
				{
					goto next_rule;
				}

				break;

			case AF_INET6:
				
				if (!rules_isEqualIpAddresses(
						AF_INET6,
						pRuleLocalIpAddress,
						pRuleLocalIpAddressMask,
						(gen_addr*)&pLocalAddress->AddressIn6.sin6_addr
						))
				{
					goto next_rule;
				}

				if (!rules_isEqualIpAddresses(
						AF_INET6,
						pRuleRemoteIpAddress,
						pRuleRemoteIpAddressMask,
						(gen_addr*)&pRemoteAddress->AddressIn6.sin6_addr
						))
				{
					goto next_rule;
				}

				break;

			default:
				break;
			}
		}
		
		flag = pRule->filteringFlag;

		sl_unlock(&lh);	

		return flag;

next_rule:
		
		pRuleEntry = (PRULE_ENTRY)pRuleEntry->entry.Flink;
	}

	sl_unlock(&lh);	

	return NF_ALLOW;
}

PBINDING_RULE_ENTRY rules_allocateBindingRuleEntry()
{
	PBINDING_RULE_ENTRY pRuleEntry;

	pRuleEntry = (PBINDING_RULE_ENTRY)ExAllocateFromNPagedLookasideList( &g_bindingRulesLAList );
	if (!pRuleEntry)
		return NULL;

	memset(pRuleEntry, 0, sizeof(BINDING_RULE_ENTRY));
	
	return pRuleEntry;
}

void rules_freeBindingRuleEntry(PBINDING_RULE_ENTRY pRuleEntry)
{
	if (pRuleEntry->pPackageSid)
	{
		free_np(pRuleEntry->pPackageSid);
	}
	ExFreeToNPagedLookasideList( &g_bindingRulesLAList, pRuleEntry );
}

/**
 *  Add binding rule to linked list
 */
void rules_bindingAdd(PNF_BINDING_RULE pRule, BOOLEAN toHead)
{
    KLOCK_QUEUE_HANDLE lh;
	PBINDING_RULE_ENTRY pRuleEntry;

	pRuleEntry = (PBINDING_RULE_ENTRY)rules_allocateBindingRuleEntry();
	if (!pRuleEntry)
		return;

	memcpy(&pRuleEntry->rule, pRule, sizeof(NF_BINDING_RULE));

	if (pRuleEntry->rule.processName[0] != 0)
	{
		if (rules_convertUnicodeSidtoSid((wchar_t*)pRuleEntry->rule.processName, &pRuleEntry->pPackageSid))
		{
			pRuleEntry->rule.processName[0] = 0;
		}
	}

    sl_lock(&g_slRules, &lh);	

	if (toHead)
	{
		InsertHeadList(&g_lBindingRules, &pRuleEntry->entry);
	} else
	{
		InsertTailList(&g_lBindingRules, &pRuleEntry->entry);
	}

    sl_unlock(&lh);	
}

/**
 *	Remove all binding rules from list
 */
void rules_bindingRemove_all()
{
	PBINDING_RULE_ENTRY pRule;
    KLOCK_QUEUE_HANDLE lh;

    sl_lock(&g_slRules, &lh);	

	while (!IsListEmpty(&g_lBindingRules))
	{
		pRule = (PBINDING_RULE_ENTRY)RemoveHeadList(&g_lBindingRules);
		rules_freeBindingRuleEntry( pRule );
	}

	sl_unlock(&lh);	
}

NF_FILTERING_FLAG rules_findByBindInfo(PNF_BINDING_RULE pBindInfo, PISID pPackageSid)
{
	PBINDING_RULE_ENTRY	pRuleEntry;
	PNF_BINDING_RULE	pRule;
	gen_addr * pLocalAddress = NULL;
	gen_addr * pRuleLocalIpAddress = NULL;
	gen_addr * pRuleLocalIpAddressMask = NULL;
	NF_FILTERING_FLAG flag = NF_ALLOW;
	size_t processNameLen = 0;
    KLOCK_QUEUE_HANDLE lh;

#ifdef _DEMO
	static unsigned int counter = (unsigned int)-1;
	if (counter == 0)
	{
		return NF_ALLOW;
	}		
	counter--;
#endif

	if (!devctrl_isProxyAttached())
	{
		return NF_ALLOW;
	}
	
	pLocalAddress = (gen_addr *)&pBindInfo->localIpAddress;

	if (pBindInfo->processName[0] != 0)
	{
		processNameLen = wcslen((wchar_t*)&pBindInfo->processName);
	}

    sl_lock(&g_slRules, &lh);	

	if (IsListEmpty(&g_lBindingRules))
	{
		sl_unlock(&lh);	
		return NF_ALLOW;
	}

	pRuleEntry = (PBINDING_RULE_ENTRY)g_lBindingRules.Flink;

	while (pRuleEntry != (PBINDING_RULE_ENTRY)&g_lBindingRules)
	{
		pRule = &pRuleEntry->rule;

		if ((pRule->protocol != 0) && (pRule->protocol != pBindInfo->protocol))
		{
			goto next_rule;
		}

		if ((pRule->processId != 0) && (pRule->processId != pBindInfo->processId))
		{
			goto next_rule;
		}

		if ((pRule->localPort != 0) && (pRule->localPort != pBindInfo->localPort))
		{
			goto next_rule;
		}

		pRuleLocalIpAddress = (gen_addr*)pRule->localIpAddress;
		pRuleLocalIpAddressMask = (gen_addr*)pRule->localIpAddressMask;
		
		if (pRule->ip_family != 0)
		{
			if (pRule->ip_family != pBindInfo->ip_family)
				goto next_rule;

			switch (pRule->ip_family)
			{
			case AF_INET:
				
				if (!rules_isEqualIpAddresses(
						AF_INET,
						pRuleLocalIpAddress,
						pRuleLocalIpAddressMask,
						pLocalAddress
						))
				{
					goto next_rule;
				}

				break;

			case AF_INET6:
				
				if (!rules_isEqualIpAddresses(
						AF_INET6,
						pRuleLocalIpAddress,
						pRuleLocalIpAddressMask,
						pLocalAddress
						))
				{
					goto next_rule;
				}

				break;

			default:
				break;
			}
		}

		if (pRule->processName[0] != 0)
		{
			size_t len;
			
			len = wcslen((wchar_t*)&pRule->processName);

			if (!rules_nameMatches(
					(wchar_t*)&pRule->processName + len - 1, len, 
					(wchar_t*)&pBindInfo->processName + processNameLen - 1, processNameLen))
			{
				goto next_rule;
			}
		}

		if (pRuleEntry->pPackageSid)
		{
			if (!pPackageSid)
			{
				goto next_rule;
			}

			if (!rules_equalSid(pRuleEntry->pPackageSid, pPackageSid))
			{
				goto next_rule;
			}
		}

		flag = pRule->filteringFlag;

		if (flag != NF_ALLOW)
		{
			memcpy(pBindInfo->newLocalIpAddress, pRule->newLocalIpAddress, NF_MAX_IP_ADDRESS_LENGTH);
			pBindInfo->newLocalPort = pRule->newLocalPort;
		}

		sl_unlock(&lh);	

		return flag;

next_rule:
		
		pRuleEntry = (PBINDING_RULE_ENTRY)pRuleEntry->entry.Flink;
	}

	sl_unlock(&lh);	 

	return NF_ALLOW;
}

static BOOLEAN rules_equalSid(PISID pSid1, PISID pSid2)
{
	USHORT sidLen;
	
	if (pSid1->SubAuthorityCount != pSid2->SubAuthorityCount)
		return FALSE;

	sidLen = sizeof(SID) + sizeof(ULONG) * (pSid1->SubAuthorityCount - 1);

	if (_memcmp(pSid1, pSid2, sidLen) == 0)
		return TRUE;

	return FALSE;
}

static BOOLEAN
rules_parseAuthority(wchar_t * buffer, ULONG * pAuthority, USHORT * offset)
{
    ULONG authority = 0;
    UCHAR count = 0;
	USHORT i;

    for (i = *offset;; i++)
    {
        if ((buffer[i] >= L'0') && (buffer[i] <= L'9'))
        {
            authority = authority * 10 + (buffer[i] - L'0');
            continue;
        } else 
		if (buffer[i] == L'-')
        {
			*pAuthority = authority;
			*offset = i+1;
            return TRUE;
        } else 
		if (buffer[i] == 0)
        {
            break;
        }
    }

	return FALSE;
}

static BOOLEAN
rules_parseSubAuthorities(PCWCHAR buffer, PISID pSid)
{
    ULONG authority = 0;
    UCHAR count = 0;
	USHORT i;

    for (i = 0;; i++)
    {
        if ((buffer[i] >= L'0') && (buffer[i] <= L'9'))
        {
            authority = authority * 10 + (buffer[i] - L'0');
            continue;
        }
        else if (buffer[i] == L'-')
        {
            pSid->SubAuthority[count] = authority;
            authority = 0;

            if (++count >= pSid->SubAuthorityCount)
            {
                return FALSE;
            }
            continue;
        }
        else if (buffer[i] == 0)
        {
            break;
        }
        return FALSE;
    }
    
	pSid->SubAuthority[count] = authority;
    
	return TRUE;
}

static UCHAR 
rules_getSubAuthorityCount(PCWCHAR buffer)
{
    UCHAR count = 1; 
	UCHAR i;
    
	for (i = 0;; i++)
    {
        if (buffer[i] == L'-')
        {
            count++;
        }
        else if (buffer[i] == 0)
        {
            break;
        }
    }
    
	return count;
}

static BOOLEAN
rules_convertUnicodeSidtoSid(wchar_t * pUnicodeSid, PISID* ppSid)
{
    wchar_t * PREFIX = L"s-1-";
    const USHORT PREFIX_LEN = 4;
    SIZE_T result;
	UCHAR subAuthorityCount;
	ULONG authority = 0;
	USHORT offset;
    PISID pSid;

    result = RtlCompareMemory(PREFIX, pUnicodeSid, PREFIX_LEN);
	if (result != PREFIX_LEN)
    {
        return FALSE;
    }
    
	offset = PREFIX_LEN;

	if (!rules_parseAuthority(pUnicodeSid, &authority, &offset))
	{
		return FALSE;
	}

	subAuthorityCount = rules_getSubAuthorityCount(pUnicodeSid + offset);

    pSid = (PISID)malloc_np(sizeof(SID) + sizeof(ULONG) * (subAuthorityCount - 1));
	if (!pSid)
	{
		return FALSE;
	}

	pSid->Revision = 1;
    pSid->IdentifierAuthority.Value[0] = 0;
    pSid->IdentifierAuthority.Value[1] = 0;
	pSid->IdentifierAuthority.Value[2] = (BYTE)((authority & 0xff000000) >> 24);
	pSid->IdentifierAuthority.Value[3] = (BYTE)((authority & 0xff0000) >> 16);
	pSid->IdentifierAuthority.Value[4] = (BYTE)((authority & 0xff00) >> 8);
	pSid->IdentifierAuthority.Value[5] = (BYTE)(authority & 0xff);
    pSid->SubAuthorityCount = subAuthorityCount;

    if (!rules_parseSubAuthorities(pUnicodeSid + offset, pSid))
    {
        free_np(pSid);
        return FALSE;
    }

    if (!RtlValidSid(pSid))
    {
        free_np(pSid);
        return FALSE;
    }

    *ppSid = pSid;
    return TRUE;
}