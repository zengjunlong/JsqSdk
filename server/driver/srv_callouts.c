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
#include "srv_callouts.h"
#include "srv_rules.h"
#include "srv_ipfrag.h"
#include "devctrl.h"
#include "hashtable.h"
#include "flowctl.h"
#include "interfaces.h"
#include "udp_port_pool.h"

#ifdef _WPPTRACE
#include "srv_callouts.tmh"
#endif

#define ETH_P_IPv4		0x0800
#define ETH_P_IPv6		0x86DD
#define	ETH_P_PPPoe		0x8864

#pragma pack(1) 

typedef struct _IP_HEADER_V4_
{
   union
   {
      UINT8 versionAndHeaderLength;
      struct
      {
         UINT8 headerLength : 4;
         UINT8 version : 4;
      };
   };
   union
   {
      UINT8  typeOfService;
      UINT8  differentiatedServicesCodePoint;
      struct
      {
         UINT8 explicitCongestionNotification : 2;
         UINT8 _typeOfService : 6;
      };
   };
   UINT16 totalLength;
   UINT16 identification;
   union
   {
      UINT16 flagsAndFragmentOffset;
      struct
      {
         UINT16 fragmentOffset : 13;
         UINT16 flags : 3;
      };
   };
   UINT8  timeToLive;
   UINT8  protocol;
   UINT16 checksum;
   BYTE   pSourceAddress[sizeof(UINT32)];
   BYTE   pDestinationAddress[sizeof(UINT32)];
} IP_HEADER_V4, *PIP_HEADER_V4;

#define IP_MF              (0x2000)    /* more fragments flag */
#define IP_FLAG_MASK       (0xE000)    /* mask for fragmenting bits */
#define IP_OFFSET_MASK     (0x1fff)    /* mask for fragmenting bits */
#define IP_HEADER_GET_MF(x)  !!(x & htons(IP_MF))
#define IP_HEADER_GET_OFFSET(x)  (htons(x) & IP_OFFSET_MASK)
#define IP_HEADER_IS_FRAGMENT(x)  !!(x & htons(IP_MF | IP_OFFSET_MASK))

struct iphdr
{
    UINT8  HdrLength:4;
    UINT8  Version:4;
    UINT8  TOS;
    UINT16 Length;
    UINT16 Id;
    UINT16 FragOff0;
    UINT8  TTL;
    UINT8  Protocol;
    UINT16 Checksum;
    UINT32 SrcAddr;
    UINT32 DstAddr;
};

typedef struct _IP_HEADER_V6_
{
   union
   {
      UINT8 pVersionTrafficClassAndFlowLabel[4];
      struct
      {
       UINT8 r1 : 4;
       UINT8 value : 4;
       UINT8 r2;
       UINT8 r3;
       UINT8 r4;
      }version;
   };
   UINT16 payloadLength;
   UINT8  nextHeader;
   UINT8  hopLimit;
   BYTE   pSourceAddress[16];
   BYTE   pDestinationAddress[16];
} IP_HEADER_V6, *PIP_HEADER_V6;

typedef struct _IPV6_FRAGMENT_HDR
{
    UCHAR    next_header;
    UCHAR    _reserved;
    USHORT   offset_more;
    ULONG    id;
} IPV6_FRAGMENT_HDR, *PIPV6_FRAGMENT_HDR;

#define IP6_FRAGMENT_MF_MASK  (0x1)     
#define IP6_FRAGMENT_MF(offset_more)   !!(htons(offset_more) & IP6_FRAGMENT_MF_MASK)
#define IP6_FRAGMENT_OFFSET_MASK   (0xFFF8)
#define IP6_FRAGMENT_OFFSET(offset_more)   (htons(offset_more) & IP6_FRAGMENT_OFFSET_MASK)

typedef unsigned char   u_char;
typedef unsigned short  u_short;
typedef unsigned int    u_int;
typedef unsigned long   u_long;

typedef	u_long	tcp_seq;
typedef u_long	tcp_cc;			


typedef struct _TCP_HEADER 
{
	u_short	th_sport;		/* source port */
	u_short	th_dport;		/* destination port */
	tcp_seq	th_seq;			/* sequence number */
	tcp_seq	th_ack;			/* acknowledgement number */
	u_char	th_off:4,			/* data offset */
		th_x2:4;
	u_char	th_flags;
#define	TH_FIN	0x01
#define	TH_SYN	0x02
#define	TH_RST	0x04
#define	TH_PUSH	0x08
#define	TH_ACK	0x10
#define	TH_URG	0x20
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG)

	u_short	th_win;			/* window */
	u_short	th_sum;			/* checksum */
	u_short	th_urp;			/* urgent pointer */
} TCP_HEADER, *PTCP_HEADER;

typedef struct UDP_HEADER_ 
{
    UINT16 srcPort;
    UINT16 destPort;
    UINT16 length;
    UINT16 checksum;
} UDP_HEADER, *PUDP_HEADER;

#pragma pack()


#define NANOSECONDS_PER_SECOND		(LONGLONG)(10 * 1000 * 1000)
#define NF_NAT_TABLE_CHECK_PERIOD	-(10 * NANOSECONDS_PER_SECOND)

static uint64_t g_timeouts[NSTT_MAX];

#define NF_NAT_TCP_TIMEOUT			(120 * 60 * NANOSECONDS_PER_SECOND)
#define NF_NAT_TCP_SYN_TIMEOUT		(20 * NANOSECONDS_PER_SECOND)
#define NF_NAT_TCP_CLOSE_TIMEOUT	(20 * NANOSECONDS_PER_SECOND)
#define NF_NAT_UDP_TIMEOUT			(20 * NANOSECONDS_PER_SECOND)

typedef enum _NF_ENTRY_STATE
{
	TES_SYN_SENT,
	TES_ESTABLISHED,
	TES_FIN_WAIT_1,
	TES_FIN_WAIT_2,
	TES_ACK_WAIT_1,
	TES_ACK_WAIT_2,
	TES_CLOSED
} NF_ENTRY_STATE;

typedef struct _NF_NAT_ENTRY
{
	LIST_ENTRY	entry;
	
    HASH_ID		id;
	PHASH_TABLE_ENTRY next;
	
	char		ipFamily;
	char		protocol;	

	NF_ADDRESS	srcAddress;	// Source address
	NF_ADDRESS	dstAddress;	// Destination address
	NF_ADDRESS	redirectTo;	// Redirection address

	NF_ENTRY_STATE state;		// Entry state

	uint64_t	ts;			// Last activity time
} NF_NAT_ENTRY, *PNF_NAT_ENTRY;

static PHASH_TABLE		g_natTable;
static LIST_ENTRY		g_natList;
static KSPIN_LOCK		g_slNat;
static NPAGED_LOOKASIDE_LIST	g_laNatEntry;

static PVOID	g_timerThreadObject = NULL;
static KEVENT	g_timerThreadEvent;

static void srvcallouts_timerThread(IN PVOID StartContext);

static BOOLEAN	g_initialized = FALSE;

static uint64_t 
srvcallouts_getTickCount()
{
	LARGE_INTEGER li;

	KeQuerySystemTime(&li);

	return li.QuadPart;
}

static void 
srvcallouts_cksumAdjust(unsigned char *chksum, unsigned char *optr, int olen, unsigned char *nptr, int nlen)
{
     long x, oldv, newv;
     
	 x = chksum[0]*256 + chksum[1];
     
	 x = ~x & 0xffff;
     
	 while (olen) 
	 {
		if (olen == 1) 
		{
			oldv=optr[0]*256 + optr[1];
			x -= oldv & 0xff00;
			if (x <= 0) 
			{ 
				x--; 
				x &= 0xffff; 
			}
			break;
		} else 
		{
			oldv = optr[0]*256 + optr[1]; 
			optr += 2;
			x -= oldv & 0xffff;
			if (x <= 0) 
			{ 
				x--; 
				x &= 0xffff; 
			}
			olen -= 2;
		}
     }
     
	 while (nlen) 
	 {
		if (nlen == 1) 
		{
			newv = nptr[0]*256 + nptr[1];
			x += newv & 0xff00;
			if (x & 0x10000) 
			{ 
				x++; 
				x &= 0xffff; 
			}
			break;
		} else 
		{
			newv = nptr[0]*256 + nptr[1]; 
			nptr += 2;
			x += newv & 0xffff;
			if (x & 0x10000) 
			{ 
				x++; 
				x &= 0xffff; 
			}
			nlen -= 2;
		}
    }
     
	x = ~x & 0xffff;
     
	chksum[0] = (unsigned char)(x >> 8); 
	chksum[1] = x & 0xff;
}

static void 
srvcallouts_updateCksumTCP(IP_HEADER_V4 * pIPHeader, TCP_HEADER * pTCPHeader, PNF_ADDRESS newAddress, PNF_ADDRESS oldAddress)
{
	BOOLEAN updateTCPChecksum = (pTCPHeader && pTCPHeader->th_sum != 0);

	if (pIPHeader)
	{
		if (pIPHeader->checksum != 0)
		srvcallouts_cksumAdjust(
			(unsigned char*)&pIPHeader->checksum, 
			(unsigned char*)&oldAddress->ip.v4, 4, 
			(unsigned char*)&newAddress->ip.v4, 4);

		if (updateTCPChecksum)
		srvcallouts_cksumAdjust(
			(unsigned char*)&pTCPHeader->th_sum, 
			(unsigned char*)&oldAddress->ip.v4, 4, 
			(unsigned char*)&newAddress->ip.v4, 4);
	} else
	{
		if (updateTCPChecksum)
		srvcallouts_cksumAdjust(
			(unsigned char*)&pTCPHeader->th_sum, 
			(unsigned char*)&oldAddress->ip.v6, 16, 
			(unsigned char*)&newAddress->ip.v6, 16);
	}

	if (updateTCPChecksum)
	srvcallouts_cksumAdjust(
		(unsigned char*)&pTCPHeader->th_sum, 
		(unsigned char*)&oldAddress->port, 2, 
		(unsigned char*)&newAddress->port, 2);

}

static void 
srvcallouts_updateCksumUDP(IP_HEADER_V4 * pIPHeader, UDP_HEADER * pUDPHeader, PNF_ADDRESS newAddress, PNF_ADDRESS oldAddress)
{
	BOOLEAN updateUDPChecksum = (pUDPHeader && pUDPHeader->checksum != 0);

	if (pIPHeader)
	{
		if (pIPHeader->checksum != 0)
		srvcallouts_cksumAdjust(
			(unsigned char*)&pIPHeader->checksum, 
			(unsigned char*)&oldAddress->ip.v4, 4, 
			(unsigned char*)&newAddress->ip.v4, 4);

		if (updateUDPChecksum)
		srvcallouts_cksumAdjust(
			(unsigned char*)&pUDPHeader->checksum, 
			(unsigned char*)&oldAddress->ip.v4, 4, 
			(unsigned char*)&newAddress->ip.v4, 4);
	} else
	{
		if (updateUDPChecksum)
		srvcallouts_cksumAdjust(
			(unsigned char*)&pUDPHeader->checksum, 
			(unsigned char*)&oldAddress->ip.v6, 16, 
			(unsigned char*)&newAddress->ip.v6, 16);
	}

	if (updateUDPChecksum)
	srvcallouts_cksumAdjust(
		(unsigned char*)&pUDPHeader->checksum, 
		(unsigned char*)&oldAddress->port, 2, 
		(unsigned char*)&newAddress->port, 2);
}

static HASH_ID 
srvcallouts_getHash(const char * key, int length) 
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

static PNF_NAT_ENTRY 
srvcallouts_findEntry(PNF_ADDRESS pSrcAddress, char protocol)
{
	HASH_ID id;
	PHASH_TABLE_ENTRY phte;
	PNF_NAT_ENTRY pEntry;

	id = srvcallouts_getHash((char*)pSrcAddress, sizeof(*pSrcAddress));

	KdPrint(("srvcallouts_findEntry entry id %I64u\n", id));

	phte = ht_find_entry(g_natTable, id);
	if (!phte)
	{
		return NULL;
	}

	do {
		pEntry = (PNF_NAT_ENTRY)CONTAINING_RECORD(phte, NF_NAT_ENTRY, id);

		if (pEntry->protocol == protocol &&
			memcmp(&pEntry->srcAddress, pSrcAddress, sizeof(*pSrcAddress)) == 0)
		{
			return pEntry;
		}

		phte = phte->pNext;
	} while (phte != NULL);

	return NULL;
}

static PNF_NAT_ENTRY 
srvcallouts_findUdpEntry(PNF_ADDRESS pSrcAddress, PNF_ADDRESS pDstAddress, BOOLEAN isOutbound)
{
	HASH_ID id;
	PHASH_TABLE_ENTRY phte;
	PNF_NAT_ENTRY pEntry;

	id = srvcallouts_getHash((char*)pSrcAddress, sizeof(*pSrcAddress));

	KdPrint(("srvcallouts_findUdpEntry entry id %I64u\n", id));
	
	phte = ht_find_entry(g_natTable, id);
	if (!phte)
	{
		return NULL;
	}

	if (pDstAddress)
	{
		KdPrint(("srvcallouts_findUdpEntry entry dst %x:%d, src %x:%d\n", 
				pDstAddress->ip.v4, htons(pDstAddress->port),
				pSrcAddress->ip.v4, htons(pSrcAddress->port)));

		if (isOutbound)
		{
			do {
				pEntry = (PNF_NAT_ENTRY)CONTAINING_RECORD(phte, NF_NAT_ENTRY, id);

				if ((pEntry->protocol == IPPROTO_UDP) &&
					(memcmp(&pEntry->srcAddress, pSrcAddress, sizeof(NF_ADDRESS)) == 0) &&
					(memcmp(&pEntry->redirectTo, pDstAddress, sizeof(NF_ADDRESS)) == 0))
				{
					return pEntry;
				}

				phte = phte->pNext;
			} while (phte != NULL);
		} else
		{
			do {
				pEntry = (PNF_NAT_ENTRY)CONTAINING_RECORD(phte, NF_NAT_ENTRY, id);

				if ((pEntry->protocol == IPPROTO_UDP) &&
					(memcmp(&pEntry->srcAddress, pSrcAddress, sizeof(NF_ADDRESS)) == 0) &&
					(memcmp(&pEntry->dstAddress, pDstAddress, sizeof(NF_ADDRESS)) == 0))
				{
					return pEntry;
				}

				phte = phte->pNext;
			} while (phte != NULL);
		}
	} else
	{
		do {
			pEntry = (PNF_NAT_ENTRY)CONTAINING_RECORD(phte, NF_NAT_ENTRY, id);

			if ((pEntry->protocol == IPPROTO_UDP) &&
				(memcmp(&pEntry->srcAddress, pSrcAddress, sizeof(NF_ADDRESS)) == 0))
			{
				return pEntry;
			}

			phte = phte->pNext;
		} while (phte != NULL);
	}

	return NULL;
}

static PNF_NAT_ENTRY 
srvcallouts_findUdpEntryByRedirectAddr(PNF_ADDRESS pSrcAddress, PNF_ADDRESS pRedirectAddress)
{
	HASH_ID id;
	PHASH_TABLE_ENTRY phte;
	PNF_NAT_ENTRY pEntry;

	id = srvcallouts_getHash((char*)pSrcAddress, sizeof(*pSrcAddress));

	KdPrint(("srvcallouts_findUdpEntry entry id %I64u\n", id));
	
	phte = ht_find_entry(g_natTable, id);
	if (!phte)
	{
		return NULL;
	}

	if (pRedirectAddress)
	{
		KdPrint(("srvcallouts_findUdpEntry entry dst %x:%d, src %x:%d\n", 
				pRedirectAddress->ip.v4, htons(pRedirectAddress->port),
				pSrcAddress->ip.v4, htons(pSrcAddress->port)));

		do {
			pEntry = (PNF_NAT_ENTRY)CONTAINING_RECORD(phte, NF_NAT_ENTRY, id);

			if ((pEntry->protocol == IPPROTO_UDP) &&
				(memcmp(&pEntry->srcAddress, pSrcAddress, sizeof(NF_ADDRESS)) == 0) &&
				(pEntry->redirectTo.port == pRedirectAddress->port))
			{
				return pEntry;
			}

			phte = phte->pNext;
		} while (phte != NULL);
	} 

	return NULL;
}

static void
srvcallouts_removeEntry(PNF_NAT_ENTRY pEntry)
{
	ht_remove_entryByPointer(g_natTable, (PHASH_TABLE_ENTRY)&pEntry->id);
	RemoveEntryList(&pEntry->entry);
	ExFreeToNPagedLookasideList( &g_laNatEntry, pEntry );
}

static void
srvcallouts_addEntry(PNF_NAT_ENTRY pEntry, BOOLEAN allowDup)
{
	if (!allowDup)
	{
		PNF_NAT_ENTRY pEntryExisting;
		pEntryExisting = srvcallouts_findEntry(&pEntry->srcAddress, pEntry->protocol);
		if (pEntryExisting)
		{
			srvcallouts_removeEntry(pEntryExisting);
		}
	}
	ht_add_entry(g_natTable, (PHASH_TABLE_ENTRY)&pEntry->id);
	InsertTailList(&g_natList, &pEntry->entry);
}

static BOOLEAN 
srvcallouts_redirectTCP(
	PSRV_PACKET_INFO ppi,
	void * pIPHeader,
	TCP_HEADER * pTCPHeader,
	PNF_SRV_RULE_ACTION pAction)
{
	IP_HEADER_V4* pIPv4Header = NULL;
	IP_HEADER_V6* pIPv6Header = NULL;
	PNF_NAT_ENTRY	pEntry = NULL;
	NF_ADDRESS	redirectTo;
	KLOCK_QUEUE_HANDLE lh;

	KdPrint((DPREFIX"srvcallouts_processTCP\n"));

	if (ppi->ipFamily == AF_INET)
	{
		pIPv4Header = (IP_HEADER_V4*)pIPHeader;
	} else
	{
		pIPv6Header = (IP_HEADER_V6*)pIPHeader;
	}

	if (!ppi->isOutbound)
	{
		if (pTCPHeader &&
			pTCPHeader->th_flags == TH_SYN)
		{
			if (!(pAction->filteringFlag & NF_SRV_FILTER))
			{
				return FALSE;
			}

			if (pAction->tcpRedirectTo.ip.v4 != 0)
			{
				redirectTo = pAction->tcpRedirectTo;
			} else
			{
				if (!interfaces_get(ppi->interfaceLuid, ppi->ipFamily, &redirectTo))
				{
					KdPrint((DPREFIX"srvcallouts_processTCP cannot find the local IP\n"));
					return FALSE;
				}

				redirectTo.port = pAction->tcpRedirectTo.port;
			}

			pEntry = (PNF_NAT_ENTRY)ExAllocateFromNPagedLookasideList( &g_laNatEntry );
			if (!pEntry)
				return FALSE;

			memset(pEntry, 0, sizeof(NF_NAT_ENTRY));

			pEntry->state = TES_SYN_SENT;

			pEntry->srcAddress = ppi->srcAddress;
			pEntry->dstAddress = ppi->dstAddress;

			pEntry->ipFamily = ppi->ipFamily;
			pEntry->protocol = IPPROTO_TCP;
			
			pEntry->ts = srvcallouts_getTickCount();

			pEntry->redirectTo = redirectTo;

			pEntry->id = srvcallouts_getHash((char*)&ppi->srcAddress, sizeof(ppi->srcAddress));

			KdPrint(("srvcallouts_processTCP new entry id %I64u\n", pEntry->id));

			sl_lock(&g_slNat, &lh);
			srvcallouts_addEntry(pEntry, FALSE);
			sl_unlock(&lh);

			if (ppi->ipFamily == AF_INET)
			{
				memcpy(pIPv4Header->pDestinationAddress, &redirectTo.ip.v4, 4);
				pTCPHeader->th_dport = redirectTo.port;

				srvcallouts_updateCksumTCP(pIPv4Header, pTCPHeader, &redirectTo, &ppi->dstAddress);

				KdPrint(("srvcallouts_processTCP entry added dst %x:%d, src %x:%d, redirectTo %x:%d\n",
					ppi->dstAddress.ip.v4, htons(ppi->dstAddress.port),
					ppi->srcAddress.ip.v4, htons(ppi->srcAddress.port),
					redirectTo.ip.v4, htons(redirectTo.port)));
			} else
			{
				memcpy(pIPv6Header->pDestinationAddress, &redirectTo.ip.v6, 16);
				pTCPHeader->th_dport = redirectTo.port;

				srvcallouts_updateCksumTCP(NULL, pTCPHeader, &redirectTo, &ppi->dstAddress);

				KdPrint(("srvcallouts_processTCP IPv6 entry added dst %x:%d, src %x:%d, redirectTo %x:%d\n",
					ppi->dstAddress.ip.v4, htons(ppi->dstAddress.port),
					ppi->srcAddress.ip.v4, htons(ppi->srcAddress.port),
					redirectTo.ip.v4, htons(redirectTo.port)));
			}
		} else
			// pTCPHeader->th_flags != TH_SYN
		{
			sl_lock(&g_slNat, &lh);
			pEntry = srvcallouts_findEntry(&ppi->srcAddress, IPPROTO_TCP);	
			if (pEntry)
			{
				if ((pEntry->protocol == IPPROTO_TCP) &&
					(memcmp(&ppi->dstAddress, &pEntry->dstAddress, sizeof(ppi->dstAddress)) == 0))
				{
					redirectTo = pEntry->redirectTo;
					pEntry->ts = srvcallouts_getTickCount();
				} else
				{
					sl_unlock(&lh);
					KdPrint((DPREFIX"srvcallouts_processTCP unknown dst %x:%d\n", 
						ppi->dstAddress.ip.v4, htons(ppi->dstAddress.port)));
					return FALSE;
				}
			} else
			{
				sl_unlock(&lh);
				KdPrint((DPREFIX"srvcallouts_processTCP unknown src %x:%d\n", 
					ppi->srcAddress.ip.v4, htons(ppi->srcAddress.port)));
				return FALSE;
			}

			if (ppi->ipFamily == AF_INET)
			{
				memcpy(pIPv4Header->pDestinationAddress, &redirectTo.ip.v4, 4);
				
				if (pTCPHeader)
				{
					pTCPHeader->th_dport = redirectTo.port;
				}

				srvcallouts_updateCksumTCP(pIPv4Header, pTCPHeader, &redirectTo, &ppi->dstAddress);
			} else
			{
				memcpy(pIPv6Header->pDestinationAddress, &redirectTo.ip.v6, 16);
				
				if (pTCPHeader)
				{
					pTCPHeader->th_dport = redirectTo.port;
				}

				srvcallouts_updateCksumTCP(NULL, pTCPHeader, &redirectTo, &ppi->dstAddress);
			}

			if (pTCPHeader)
			{
				if (pTCPHeader->th_flags & TH_RST)
				{
					pEntry->state = TES_CLOSED;
				} else
				switch (pEntry->state)
				{
				case TES_ESTABLISHED:
					if (pTCPHeader->th_flags & TH_FIN)
						pEntry->state = TES_FIN_WAIT_1;
					break;
				case TES_FIN_WAIT_2:
					if (pTCPHeader->th_flags & TH_FIN)
						pEntry->state = TES_ACK_WAIT_1;
					break;
				case TES_ACK_WAIT_2:
					if (pTCPHeader->th_flags & TH_ACK)
					{
						pEntry->state = TES_CLOSED;
					}
					break;
				}

				KdPrint(("srvcallouts_processTCP in packet, TCP flags=%x, entry state=%d (src %x:%d)\n", 
					pTCPHeader->th_flags, pEntry->state, ppi->srcAddress.ip.v4, htons(ppi->srcAddress.port)));
			}

			sl_unlock(&lh);
		}
	} else
		// Outbound 
	{
		sl_lock(&g_slNat, &lh);
		pEntry = srvcallouts_findEntry(&ppi->dstAddress, IPPROTO_TCP);	
		if (pEntry)
		{
			if (pEntry->protocol == IPPROTO_TCP)
			{
				pEntry->ts = srvcallouts_getTickCount();
			} else
			{
				sl_unlock(&lh);
				KdPrint((DPREFIX"srvcallouts_processTCP wrong protocol dst %x:%d\n", 
					ppi->dstAddress.ip.v4, htons(ppi->dstAddress.port)));
				return FALSE;
			}
		} else
		{
			sl_unlock(&lh);
			KdPrint((DPREFIX"srvcallouts_processTCP unknown dst %x:%d\n", 
				ppi->dstAddress.ip.v4, htons(ppi->dstAddress.port)));
			return FALSE;
		}

		if (ppi->ipFamily == AF_INET)
		{
			memcpy(pIPv4Header->pSourceAddress, &pEntry->dstAddress.ip.v4, 4);
			
			if (pTCPHeader)
			{
				pTCPHeader->th_sport = pEntry->dstAddress.port;
			}

			KdPrint((DPREFIX"srvcallouts_processTCP src replaced src %x:%d, dst %x:%d, newSrc %x:%d\n",
				ppi->srcAddress.ip.v4, htons(ppi->srcAddress.port),
				ppi->dstAddress.ip.v4, htons(ppi->dstAddress.port),
				pEntry->dstAddress.ip.v4, htons(pEntry->dstAddress.port)));

			srvcallouts_updateCksumTCP(pIPv4Header, pTCPHeader, &pEntry->dstAddress, &ppi->srcAddress);
		} else
		{
			memcpy(pIPv6Header->pSourceAddress, &pEntry->dstAddress.ip.v6, 16);
			
			if (pTCPHeader)
			{
				pTCPHeader->th_sport = pEntry->dstAddress.port;
			}

			KdPrint((DPREFIX"srvcallouts_processTCP src replaced src %x:%d, dst %x:%d, newSrc %x:%d\n",
				ppi->srcAddress.ip.v4, htons(ppi->srcAddress.port),
				ppi->dstAddress.ip.v4, htons(ppi->dstAddress.port),
				pEntry->dstAddress.ip.v4, htons(pEntry->dstAddress.port)));

			srvcallouts_updateCksumTCP(NULL, pTCPHeader, &pEntry->dstAddress, &ppi->srcAddress);
		}

		if (pTCPHeader)
		{
			if (pTCPHeader->th_flags & TH_RST)
			{
				pEntry->state = TES_CLOSED;
			} else
			switch (pEntry->state)
			{
			case TES_SYN_SENT:
				if ((pTCPHeader->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK))
					pEntry->state = TES_ESTABLISHED;
				break;
			case TES_ESTABLISHED:
				if (pTCPHeader->th_flags & TH_FIN)
					pEntry->state = TES_FIN_WAIT_2;
				break;
			case TES_FIN_WAIT_1:
				if (pTCPHeader->th_flags & TH_FIN)
					pEntry->state = TES_ACK_WAIT_2;
				break;
			case TES_ACK_WAIT_1:
				if (pTCPHeader->th_flags & TH_ACK)
				{
					pEntry->state = TES_CLOSED;
				}
				break;
			}

			KdPrint(("srvcallouts_processTCP out packet, TCP flags=%x, entry state=%d (dst x:%d)\n", 
				pTCPHeader->th_flags, pEntry->state, htons(ppi->dstAddress.port)));
		}

		sl_unlock(&lh);
	}

	return TRUE;
}

static BOOLEAN 
srvcallouts_redirectUDP(
	PSRV_PACKET_INFO ppi,
	void * pIPHeader,
	UDP_HEADER * pUDPHeader,
	NET_BUFFER * nb,
	ULONG ipHeaderSize,
	PNF_SRV_RULE_ACTION pAction)
{
	IP_HEADER_V4* pIPv4Header = NULL;
	IP_HEADER_V6* pIPv6Header = NULL;
	PNF_NAT_ENTRY	pEntry = NULL;
	KLOCK_QUEUE_HANDLE lh;

	KdPrint((DPREFIX"srvcallouts_redirectUDP\n"));

	if (ppi->ipFamily == AF_INET)
	{
		pIPv4Header = (IP_HEADER_V4*)pIPHeader;
	} else
	{
		pIPv6Header = (IP_HEADER_V6*)pIPHeader;
	}

	if (!ppi->isOutbound)
	{
		NF_ADDRESS	redirectTo;
	
		sl_lock(&g_slNat, &lh);
		pEntry = srvcallouts_findUdpEntry(&ppi->srcAddress, &ppi->dstAddress, FALSE);
		if (pEntry)
		{
			KdPrint((DPREFIX"srvcallouts_redirectUDP NAT entry found\n"));
			redirectTo = pEntry->redirectTo;
			pEntry->ts = srvcallouts_getTickCount();
			sl_unlock(&lh);
		} else
		{
			sl_unlock(&lh);

			KdPrint((DPREFIX"srvcallouts_redirectUDP NAT entry not found\n"));

			if (!(pAction->filteringFlag & NF_SRV_FILTER))
			{
				return FALSE;
			}

			if (pAction->udpRedirectTo.ip.v4 != 0)
			{
				redirectTo = pAction->udpRedirectTo;
			} else
			{
				if (!interfaces_get(ppi->interfaceLuid, ppi->ipFamily, &redirectTo))
				{
					KdPrint((DPREFIX"srvcallouts_redirectUDP cannot find the local IP\n"));
					return FALSE;
				}

				redirectTo.port = udp_port_pool_get(ppi->ipFamily); 
				if (redirectTo.port == 0)
				{
					KdPrint((DPREFIX"srvcallouts_redirectUDP Out of UDP ports!\n"));
					return FALSE;
				}
			}

			pEntry = (PNF_NAT_ENTRY)ExAllocateFromNPagedLookasideList( &g_laNatEntry );
			if (!pEntry)
			{
				return FALSE;
			}

			memset(pEntry, 0, sizeof(NF_NAT_ENTRY));

			pEntry->state = TES_ESTABLISHED;

			pEntry->srcAddress = ppi->srcAddress;
			pEntry->dstAddress = ppi->dstAddress;

			pEntry->ipFamily = ppi->ipFamily;
			pEntry->protocol = IPPROTO_UDP;
			
			pEntry->ts = srvcallouts_getTickCount();

			pEntry->redirectTo = redirectTo;

			pEntry->id = srvcallouts_getHash((char*)&ppi->srcAddress, sizeof(ppi->srcAddress));

			sl_lock(&g_slNat, &lh);
			srvcallouts_addEntry(pEntry, TRUE);
			sl_unlock(&lh);
		}

		if (ppi->ipFamily == AF_INET)
		{
			memcpy(pIPv4Header->pDestinationAddress, &redirectTo.ip.v4, 4);
			
			if (pUDPHeader)
			{
				pUDPHeader->destPort = redirectTo.port;
			}

			srvcallouts_updateCksumUDP(pIPv4Header, pUDPHeader, &redirectTo, &ppi->dstAddress);

			KdPrint(("srvcallouts_redirectUDP entry added dst %x:%d, src %x:%d\n", 
					ppi->dstAddress.ip.v4, htons(ppi->dstAddress.port),
					ppi->srcAddress.ip.v4, htons(ppi->srcAddress.port)));
		} else
		{
			memcpy(pIPv6Header->pDestinationAddress, &redirectTo.ip.v6, 16);
			
			if (pUDPHeader)
			{
				pUDPHeader->destPort = redirectTo.port;
			}

			srvcallouts_updateCksumUDP(NULL, pUDPHeader, &redirectTo, &ppi->dstAddress);

			KdPrint(("srvcallouts_redirectUDP IPv6 entry added dst %x:%d, src %x:%d\n", 
					ppi->dstAddress.ip.v4, htons(ppi->dstAddress.port),
					ppi->srcAddress.ip.v4, htons(ppi->srcAddress.port)));
		}

		return TRUE;
	} else
		// Outbound 
	{

		KdPrint(("srvcallouts_redirectUDP outbound entry dst %x:%d, src %x:%d\n", 
				ppi->dstAddress.ip.v4, htons(ppi->dstAddress.port),
				ppi->srcAddress.ip.v4, htons(ppi->srcAddress.port)));

		sl_lock(&g_slNat, &lh);
		pEntry = srvcallouts_findUdpEntry(&ppi->dstAddress, &ppi->srcAddress, TRUE);	
		if (pEntry)
		{
			pEntry->ts = srvcallouts_getTickCount();
		} else
		{
			sl_unlock(&lh);
			return FALSE;
		}

		if (ppi->ipFamily == AF_INET)
		{
			memcpy(pIPv4Header->pSourceAddress, &pEntry->dstAddress.ip.v4, 4);
			
			if (pUDPHeader)
			{
				pUDPHeader->srcPort = pEntry->dstAddress.port;
			}

			KdPrint((DPREFIX"srvcallouts_redirectUDP src replaced dst %x:%d, src %x:%d\n",
				ppi->dstAddress.ip.v4, htons(ppi->dstAddress.port),
				pEntry->dstAddress.ip.v4, htons(pEntry->dstAddress.port)));

			srvcallouts_updateCksumUDP(pIPv4Header, pUDPHeader, &pEntry->dstAddress, &ppi->srcAddress);
		} else
		{
			memcpy(pIPv6Header->pSourceAddress, &pEntry->dstAddress.ip.v6, 16);
			
			if (pUDPHeader)
			{
				pUDPHeader->srcPort = pEntry->dstAddress.port;
			}

			KdPrint((DPREFIX"srvcallouts_redirectUDP src replaced dst %x:%d, src %x:%d\n",
				ppi->dstAddress.ip.v4, htons(ppi->dstAddress.port),
				pEntry->dstAddress.ip.v4, htons(pEntry->dstAddress.port)));

			srvcallouts_updateCksumUDP(NULL, pUDPHeader, &pEntry->dstAddress, &ppi->srcAddress);
		}

		sl_unlock(&lh);
	}

	return TRUE;
}

// Blocking the packets in documented way doesn't work as expected in case when there
// are several callouts are registered for filtering on *_MAC_FRAME_ETHERNET layers.
// The issue symptoms are described here:
// https://social.msdn.microsoft.com/Forums/windowsserver/en-US/0b039e0e-39e2-4a98-9be0-1f1091a69075/injection-fwpmlayerinboundmacframeethernet?forum=wfp
// There is no hope that Microsoft will fix this. 
// So we are using a workaround with modifying IP packets.

static void
srvcallouts_blockPacket(IP_HEADER_V4* pIPv4Header, IP_HEADER_V6* pIPv6Header)
{
	if (pIPv4Header)
	{
		pIPv4Header->version = 0;
	} else
	if (pIPv6Header)
	{
		pIPv6Header->version.value = 0;
	}
}

static void 
srvcallouts_processPacket(
   NET_BUFFER * nb,
   BOOLEAN isOutbound,
   UINT16 etherType,
   UINT64 interfaceLuid
   )
{
	IP_HEADER_V4* pIPv4Header = NULL;
	IP_HEADER_V6* pIPv6Header = NULL;
	TCP_HEADER * pTCPHeader = NULL;
	UDP_HEADER * pUDPHeader = NULL;
	NF_SRV_RULE_ACTION action = {0};
	SRV_PACKET_INFO pi;
	ULONG ipHeaderSize;
	ULONG packetLength;

	KdPrint((DPREFIX"srvcallouts_processPacket isOutbound=%d\n", isOutbound));

	packetLength = NET_BUFFER_DATA_LENGTH(nb);

	memset(&pi, 0, sizeof(pi));

	pi.isOutbound = isOutbound;
	pi.interfaceLuid = interfaceLuid;

	for (;;)
	{
		if (etherType == ETH_P_IPv4)
		{
			pIPv4Header = (IP_HEADER_V4*)NdisGetDataBuffer(
					nb,
					sizeof(IP_HEADER_V4),
					NULL,
					1,
					0);
			if (!pIPv4Header)
			{
				KdPrint((DPREFIX"srvcallouts_processPacket !pIPv4Header\n"));
				break;
			}

			if (pIPv4Header->version == 4)
			{
				USHORT flagsAndFragmentOffset;

				ipHeaderSize = pIPv4Header->headerLength * 4;

				pi.ipFamily = AF_INET;
				pi.protocol = pIPv4Header->protocol;

				pi.srcAddress.ipFamily = AF_INET;
				memcpy(&pi.srcAddress.ip.v4, pIPv4Header->pSourceAddress, 4);
				pi.dstAddress.ipFamily = AF_INET;
				memcpy(&pi.dstAddress.ip.v4, pIPv4Header->pDestinationAddress, 4);

				pi.payloadLength = htons(pIPv4Header->totalLength);
				if (pi.payloadLength >= ipHeaderSize)
					pi.payloadLength -= ipHeaderSize;

				flagsAndFragmentOffset = pIPv4Header->flagsAndFragmentOffset;

				pi.isFragment = IP_HEADER_IS_FRAGMENT(flagsAndFragmentOffset);
				if (pi.isFragment)
				{
					pi.fragOffset = IP_HEADER_GET_OFFSET(flagsAndFragmentOffset) * 8;
					pi.fragId = pIPv4Header->identification;
					pi.isLastFragment = !IP_HEADER_GET_MF(flagsAndFragmentOffset);
				}
			} else
			{
				KdPrint((DPREFIX"srvcallouts_processPacket invalid IP version %d\n", pIPv4Header->version));
				break;
			}
		} else
		if (etherType == ETH_P_IPv6)
		{
			pIPv6Header = (IP_HEADER_V6*)NdisGetDataBuffer(
					nb,
					sizeof(IP_HEADER_V6),
					NULL,
					1,
					0);
			if (!pIPv6Header)
			{
				break;
			}

			if (pIPv6Header->version.value == 6)
			{
				UCHAR proto;
				UINT8 *ext_header;
				ULONG ext_header_len;
				BOOL isexthdr;
				
				pi.ipFamily = AF_INET6;

				pi.srcAddress.ipFamily = AF_INET6;
				memcpy(&pi.srcAddress.ip.v6, pIPv6Header->pSourceAddress, 16);
				pi.dstAddress.ipFamily = AF_INET6;
				memcpy(&pi.dstAddress.ip.v6, pIPv6Header->pDestinationAddress, 16);

				ipHeaderSize = sizeof(IP_HEADER_V6);

				pi.payloadLength = htons(pIPv6Header->payloadLength);
				if (pi.payloadLength >= ipHeaderSize)
					pi.payloadLength -= ipHeaderSize;

				proto = pIPv6Header->nextHeader;

				NdisAdvanceNetBufferDataStart(nb, ipHeaderSize, FALSE, NULL);

				for (;;)
				{
					isexthdr = TRUE;

					ext_header = (UINT8 *)NdisGetDataBuffer(nb, 2, NULL, 1, 0);
					if (ext_header == NULL)
					{
						break;
					}

					ext_header_len = (size_t)ext_header[1];
					switch (proto)
					{
						case IPPROTO_FRAGMENT:
							{
								PIPV6_FRAGMENT_HDR pFrag = 
									(PIPV6_FRAGMENT_HDR)NdisGetDataBuffer(nb, sizeof(IPV6_FRAGMENT_HDR), NULL, 1, 0);
								if (pFrag)
								{
									pi.isFragment = TRUE;
									pi.isLastFragment = !IP6_FRAGMENT_MF(pFrag->offset_more);
									pi.fragOffset = IP6_FRAGMENT_OFFSET(pFrag->offset_more) * 8;
									pi.fragId = pFrag->id;
								}
								ext_header_len = 8;
							}
							break;
						case IPPROTO_AH:
							ext_header_len += 2;
							ext_header_len *= 4;
							break;
						case IPPROTO_HOPOPTS:
						case IPPROTO_DSTOPTS:
						case IPPROTO_ROUTING:
							ext_header_len++;
							ext_header_len *= 8;
							break;
						default:
							isexthdr = FALSE;
							break;
					}

					if (!isexthdr)
					{
						break;
					}

					proto = ext_header[0];
					ipHeaderSize += ext_header_len;
					
					if (pi.payloadLength >= ext_header_len)
						pi.payloadLength -= ext_header_len;

					NdisAdvanceNetBufferDataStart(nb, ext_header_len, FALSE, NULL);
				}

				pi.protocol = proto;

				NdisRetreatNetBufferDataStart(nb, ipHeaderSize,	0, NULL);
			} else
			{
				break;
			}
		} else
		{
			break;
		}

		if (pi.isFragment && (pi.fragOffset > 0))
		{
			NF_PORTS ports;

			if (!ipfrag_lookup(&pi, &ports, &action))
			{
				break;
			}

			pi.srcAddress.port = ports.srcPort;
			pi.dstAddress.port = ports.dstPort;
		}

		if (pi.protocol == IPPROTO_TCP)
		{
			if (pi.isFragment && (pi.fragOffset > 0))
			{
				if (action.fcHandle != 0)
				{
					flowctl_update(action.fcHandle, isOutbound, NET_BUFFER_DATA_LENGTH(nb));
				}

				if (srvcallouts_redirectTCP(&pi, 
						(pi.ipFamily == AF_INET)? (void*)pIPv4Header : (void*)pIPv6Header,
						NULL,
						&action))
				{
					return;
				}
			} else
			{
				NdisAdvanceNetBufferDataStart(
							nb,
							ipHeaderSize,
							FALSE,
							NULL
							);

				pTCPHeader = (TCP_HEADER*)NdisGetDataBuffer(
						nb,
						sizeof(TCP_HEADER),
						NULL,
						1,
						0);

				NdisRetreatNetBufferDataStart(
						nb,
						ipHeaderSize,
						0,
						NULL
						);

				if (!pTCPHeader)
				{
					KdPrint((DPREFIX"srvcallouts_processPacket !pTCPHeader\n"));
					break;
				}

				pi.srcAddress.port = pTCPHeader->th_sport;
				pi.dstAddress.port = pTCPHeader->th_dport;

				if (srvrules_find(&pi, &action))
				{
					ipfrag_add(&pi, &action);

					if (action.filteringFlag & NF_SRV_BLOCK)
					{
						srvcallouts_blockPacket(pIPv4Header, pIPv6Header);
						return;
					}

					if (action.fcHandle != 0)
					{
						if ((pTCPHeader->th_flags & TH_ACK) &&
							!(pTCPHeader->th_flags & (TH_FIN | TH_RST)))
						{
							if (flowctl_mustSuspend(action.fcHandle, isOutbound, flowctl_getTickCount()))
							{
								srvcallouts_blockPacket(pIPv4Header, pIPv6Header);
								return;
							}
						}
					}
				} else
				{
					action.filteringFlag = NF_SRV_ALLOW;
					action.fcHandle = 0;
				} 

				if (action.fcHandle != 0)
				{
					flowctl_update(action.fcHandle, isOutbound, NET_BUFFER_DATA_LENGTH(nb));
				}

				if (srvcallouts_redirectTCP(&pi, 
						(pi.ipFamily == AF_INET)? (void*)pIPv4Header : (void*)pIPv6Header,
						pTCPHeader,
						&action))
				{
					return;
				}
			}
		} else
		if (pi.protocol == IPPROTO_UDP)
		{
			if (pi.isFragment && (pi.fragOffset > 0))
			{
				if (action.fcHandle != 0)
				{
					flowctl_update(action.fcHandle, isOutbound, NET_BUFFER_DATA_LENGTH(nb));
				}

				// Don't redirect the inbound datagrams directed to our IP address
				if (!isOutbound &&
					interfaces_isLocalAddress(pi.interfaceLuid, pi.ipFamily, &pi.dstAddress))
				{
					return;
				}

				if (srvcallouts_redirectUDP(&pi, 
					(pi.ipFamily == AF_INET)? (void*)pIPv4Header : (void*)pIPv6Header,
					pUDPHeader,
					NULL, 
					0,
					&action))
				{
					return;
				}
			} else
			{
				NdisAdvanceNetBufferDataStart(
							nb,
							ipHeaderSize,
							FALSE,
							NULL
							);

				pUDPHeader = (UDP_HEADER*)NdisGetDataBuffer(
						nb,
						sizeof(UDP_HEADER),
						NULL,
						1,
						0);

				NdisRetreatNetBufferDataStart(
						nb,
						ipHeaderSize,
						0,
						NULL
						);

				if (!pUDPHeader)
				{
					break;
				}

				pi.srcAddress.port = pUDPHeader->srcPort;
				pi.dstAddress.port = pUDPHeader->destPort;

				if (srvrules_find(&pi, &action))
				{
					ipfrag_add(&pi, &action);

					if (action.filteringFlag & NF_SRV_BLOCK)
					{
						srvcallouts_blockPacket(pIPv4Header, pIPv6Header);
						return;
					}

					if (action.fcHandle != 0)
					{
						if (flowctl_mustSuspend(action.fcHandle, isOutbound, flowctl_getTickCount()))
						{
							srvcallouts_blockPacket(pIPv4Header, pIPv6Header);
							return;
						}
					}
				} else
				{
					action.filteringFlag = NF_SRV_ALLOW;
					action.fcHandle = 0;
				} 

				if (action.fcHandle != 0)
				{
					flowctl_update(action.fcHandle, isOutbound, NET_BUFFER_DATA_LENGTH(nb));
				}

				// Don't redirect the inbound datagrams directed to our IP address
				if (!isOutbound &&
					interfaces_isLocalAddress(pi.interfaceLuid, pi.ipFamily, &pi.dstAddress))
				{
					return;
				}

				if (srvcallouts_redirectUDP(&pi, 
					(pi.ipFamily == AF_INET)? (void*)pIPv4Header : (void*)pIPv6Header,
					pUDPHeader,
					nb,
					ipHeaderSize,
					&action))
				{
					return;
				}
			}
		} else
		{
			if (pi.isFragment && (pi.fragOffset > 0))
			{
				if (action.fcHandle != 0)
				{
					flowctl_update(action.fcHandle, isOutbound, NET_BUFFER_DATA_LENGTH(nb));
				}
			} else
			{
				if (srvrules_find(&pi, &action))
				{
					ipfrag_add(&pi, &action);

					if (action.filteringFlag & NF_SRV_BLOCK)
					{
						srvcallouts_blockPacket(pIPv4Header, pIPv6Header);
						return;
					}

					if (action.fcHandle != 0)
					{
						if (flowctl_mustSuspend(action.fcHandle, isOutbound, flowctl_getTickCount()))
						{
							srvcallouts_blockPacket(pIPv4Header, pIPv6Header);
							return;
						}
					}
				} else
				{
					action.filteringFlag = NF_SRV_ALLOW;
					action.fcHandle = 0;
				} 

				if (action.fcHandle != 0)
				{
					flowctl_update(action.fcHandle, isOutbound, NET_BUFFER_DATA_LENGTH(nb));
				}
			}
		}
	
		break;
	}
}

VOID srvcallouts_MacFrameCallout(
   IN const FWPS_INCOMING_VALUES* inFixedValues,
   IN const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
   IN VOID* packet,
   IN const void* classifyContext,
   IN const FWPS_FILTER* filter,
   IN UINT64 flowContext,
   OUT FWPS_CLASSIFY_OUT* classifyOut)
{
    BOOLEAN isOutbound;
	UINT typeIndex;
	UINT16 etherType;
	UINT64  interfaceLuid = 0;
	PNET_BUFFER nb;
	UINT32 macHeaderSize = 0;
	NTSTATUS status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(flowContext);

	if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
	{
		KdPrint((DPREFIX"callouts_MacFrameCallout no FWPS_RIGHT_ACTION_WRITE\n"));
		return;
	}

	for (;;)
	{
		if (devctrl_isShutdown() || !devctrl_isProxyAttached())
		{
			break;
		}

		if (FWPS_IS_L2_METADATA_FIELD_PRESENT(inMetaValues, FWPS_L2_METADATA_FIELD_ETHERNET_MAC_HEADER_SIZE))
		{
			macHeaderSize = inMetaValues->ethernetMacHeaderSize;
		}

		isOutbound = (inFixedValues->layerId == FWPS_LAYER_OUTBOUND_MAC_FRAME_ETHERNET);
		typeIndex = isOutbound ? FWPS_FIELD_OUTBOUND_MAC_FRAME_ETHERNET_ETHER_TYPE : FWPS_FIELD_INBOUND_MAC_FRAME_ETHERNET_ETHER_TYPE;
		etherType = inFixedValues->incomingValue[typeIndex].value.uint16;
    
		if ((etherType != ETH_P_IPv6) && (etherType != ETH_P_IPv4))
		{
			KdPrint((DPREFIX"callouts_MacFrameCallout bypass etherType=%x\n", etherType));
			break;
		}

		KdPrint((DPREFIX"callouts_MacFrameCallout isOutbound=%d etherType=%x MacHeaderSize=%d\n", 
			isOutbound, etherType, inMetaValues->ethernetMacHeaderSize));

		if (isOutbound)
		{
			interfaceLuid = *inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_MAC_FRAME_ETHERNET_INTERFACE].value.uint64;
		} else
		{
			interfaceLuid = *inFixedValues->incomingValue[FWPS_FIELD_INBOUND_MAC_FRAME_ETHERNET_INTERFACE].value.uint64;
		}

		nb = NET_BUFFER_LIST_FIRST_NB((NET_BUFFER_LIST*)packet); 
		
		if (isOutbound)
		{
			NdisAdvanceNetBufferDataStart(
					nb,
					macHeaderSize,
					FALSE,
					NULL
					);
		}

		srvcallouts_processPacket(nb, isOutbound, etherType, interfaceLuid);

		if (isOutbound)
		{
			NdisRetreatNetBufferDataStart(
						nb,
						macHeaderSize,
						FALSE,
						NULL
						);
		}

		nb = NET_BUFFER_NEXT_NB(nb);

		while (nb != NULL)
		{
			if (isOutbound)
			{
				NdisAdvanceNetBufferDataStart(
						nb,
						macHeaderSize,
						FALSE,
						NULL
						);
			}

			srvcallouts_processPacket(nb, isOutbound, etherType, interfaceLuid);

			if (isOutbound)
			{
				NdisRetreatNetBufferDataStart(
							nb,
							macHeaderSize,
							FALSE,
							NULL
							);
			}

			nb = NET_BUFFER_NEXT_NB(nb);
		}

		break;
	}

	classifyOut->actionType = FWP_ACTION_PERMIT;
}
 
NTSTATUS srvcallouts_MacFrameNotify(
    IN  FWPS_CALLOUT_NOTIFY_TYPE        notifyType,
    IN  const GUID*             filterKey,
    IN  const FWPS_FILTER*     filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);

    switch (notifyType)
    {
    case FWPS_CALLOUT_NOTIFY_ADD_FILTER:
        KdPrint((DPREFIX"Filter Added to MacFrame layer.\n"));
       break;
    case FWPS_CALLOUT_NOTIFY_DELETE_FILTER:
        KdPrint((DPREFIX"Filter Deleted from MacFrame layer.\n"));
       break;
    }
    return STATUS_SUCCESS;
}

BOOLEAN 
srvcallouts_getDestinationAddress(char protocol, PNF_ADDRESS srcAddress, PNF_ADDRESS dstAddress)
{
	KLOCK_QUEUE_HANDLE lh;
	PNF_NAT_ENTRY	pEntry = NULL;

	KdPrint((DPREFIX"srvcallouts_getDestinationAddress protocol=%d\n", protocol));

	sl_lock(&g_slNat, &lh);

	if (protocol == IPPROTO_TCP)
	{
		pEntry = srvcallouts_findEntry(srcAddress, protocol);
		if (pEntry)
		{
			*dstAddress = pEntry->dstAddress;
			sl_unlock(&lh);
			return TRUE;
		}
	} else
	if (protocol == IPPROTO_UDP)
	{
		pEntry = srvcallouts_findUdpEntryByRedirectAddr(srcAddress, dstAddress);	
		if (pEntry)
		{
			KdPrint((DPREFIX"srvcallouts_getDestinationAddress protocol=UDP found\n"));

			*dstAddress = pEntry->dstAddress;
			sl_unlock(&lh);
			return TRUE;
		} else
		{
			KdPrint((DPREFIX"srvcallouts_getDestinationAddress protocol=UDP not found\n"));
		}
	}
	sl_unlock(&lh);

	KdPrint((DPREFIX"srvcallouts_getDestinationAddress failed\n"));

	return FALSE;
}

BOOLEAN 
srvcallouts_updateUDPDestinationAddress(PNF_ADDRESS srcAddress, PNF_ADDRESS dstAddress, PNF_ADDRESS newDstAddress)
{
	KLOCK_QUEUE_HANDLE lh;
	PNF_NAT_ENTRY	pEntry = NULL;

	KdPrint((DPREFIX"srvcallouts_updateUDPDestinationAddress\n"));

	sl_lock(&g_slNat, &lh);

	pEntry = srvcallouts_findUdpEntry(srcAddress, dstAddress, FALSE);	
	if (pEntry)
	{
		pEntry->dstAddress = *newDstAddress;
		sl_unlock(&lh);
		return TRUE;
	}
	sl_unlock(&lh);

	KdPrint((DPREFIX"srvcallouts_updateUDPDestinationAddress failed\n"));

	return FALSE;
}

void srvcallouts_setTimeout(PNF_SRV_TIMEOUT pt)
{
	KLOCK_QUEUE_HANDLE lh;

	sl_lock(&g_slNat, &lh);
	if (pt->type < NSTT_MAX)
	{
		g_timeouts[pt->type] = pt->value * NANOSECONDS_PER_SECOND;
	}
	sl_unlock(&lh);
}

static void srvcallouts_timerThread(IN PVOID StartContext)
{
	KLOCK_QUEUE_HANDLE lh;
	PNF_NAT_ENTRY pEntry, pEntryToDelete;
	LARGE_INTEGER li;
	uint64_t curTime;

	UNREFERENCED_PARAMETER(StartContext);

	KdPrint((DPREFIX"srvcallouts_timerThread\n"));

	li.QuadPart = NF_NAT_TABLE_CHECK_PERIOD;

	for(;;)
	{
		KeWaitForSingleObject(
			&g_timerThreadEvent,
			 Executive, 
			 KernelMode, 
			 FALSE, 
			 &li
         );

		if (devctrl_isShutdown())
		{
			break;
		}

		curTime = srvcallouts_getTickCount();

		sl_lock(&g_slNat, &lh);
	
		pEntry = (PNF_NAT_ENTRY)g_natList.Flink;
	
		while (pEntry != (PNF_NAT_ENTRY)&g_natList)
		{
			pEntryToDelete = NULL;

			switch (pEntry->protocol)
			{
			case IPPROTO_TCP:
				{
					if (pEntry->state == TES_SYN_SENT)
					{
						if ((curTime - pEntry->ts) > g_timeouts[NSTT_NAT_TCP_SYN])
						{
							pEntryToDelete = pEntry;
						}
					} else
					if (pEntry->state == TES_CLOSED)
					{
						if ((curTime - pEntry->ts) > g_timeouts[NSTT_NAT_TCP_CLOSE])
						{
							pEntryToDelete = pEntry;
						}
					} else
					if ((curTime - pEntry->ts) > g_timeouts[NSTT_NAT_TCP])
					{
						pEntryToDelete = pEntry;
					}
				}
				break;
			case IPPROTO_UDP:
				{
					if ((curTime - pEntry->ts) > g_timeouts[NSTT_NAT_UDP])
					{
						pEntryToDelete = pEntry;
					}
				}
				break;
			}

			pEntry = (PNF_NAT_ENTRY)pEntry->entry.Flink;

			if (pEntryToDelete)
			{
				KdPrint((DPREFIX"srvcallouts_timerThread deleted dst %x:%d, src %x:%d\n",
					pEntry->dstAddress.ip.v4, htons(pEntry->dstAddress.port),
					pEntry->srcAddress.ip.v4, htons(pEntry->srcAddress.port)));

				srvcallouts_removeEntry(pEntryToDelete);
			}
		}

		sl_unlock(&lh);

		ipfrag_deleteExpiredEntries();
	}

	PsTerminateSystemThread(STATUS_SUCCESS);
}


NTSTATUS srvcallouts_init()
{
	HANDLE threadHandle;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if (g_initialized)
		return STATUS_SUCCESS;

	g_initialized = TRUE;

	g_timeouts[NSTT_NAT_TCP] = NF_NAT_TCP_TIMEOUT;
	g_timeouts[NSTT_NAT_TCP_SYN] = NF_NAT_TCP_SYN_TIMEOUT;
	g_timeouts[NSTT_NAT_TCP_CLOSE] = NF_NAT_TCP_CLOSE_TIMEOUT;
	g_timeouts[NSTT_NAT_UDP] = NF_NAT_UDP_TIMEOUT;

	InitializeListHead(&g_natList);
	KeInitializeSpinLock(&g_slNat);

	ExInitializeNPagedLookasideList( &g_laNatEntry,
										NULL,
										NULL,
										0,
										sizeof(NF_NAT_ENTRY),
										MEM_TAG_NAT,
										0 );
	for (;;)
	{
		g_natTable = hash_table_new(DEFAULT_HASH_SIZE);
		if (!g_natTable)
		{
			break;
		}

		KeInitializeEvent(
			&g_timerThreadEvent,
			SynchronizationEvent,
			FALSE
			);

		status = PsCreateSystemThread(
				   &threadHandle,
				   THREAD_ALL_ACCESS,
				   NULL,
				   NULL,
				   NULL,
				   srvcallouts_timerThread,
				   NULL
				   );

		if (!NT_SUCCESS(status))
		{
			break;
		} else
		{
			status = ObReferenceObjectByHandle(
					   threadHandle,
					   0,
					   NULL,
					   KernelMode,
					   &g_timerThreadObject,
					   NULL
					   );
			ASSERT(NT_SUCCESS(status));

			ZwClose(threadHandle);
		} 

		status = STATUS_SUCCESS;
		break;
	}

	if (!NT_SUCCESS(status))
	{
		srvcallouts_free();
	}

	return status;
}

void srvcallouts_free()
{
	PNF_NAT_ENTRY pEntry;

	KdPrint((DPREFIX"srvcallouts_free\n"));

	if (!g_initialized)
		return;

	g_initialized = FALSE;

	if (g_timerThreadObject)
	{
		KeSetEvent(&g_timerThreadEvent, IO_NO_INCREMENT, FALSE);

		KeWaitForSingleObject(
			g_timerThreadObject,
			Executive,
			KernelMode,
			FALSE,
			NULL
		  );

		ObDereferenceObject(g_timerThreadObject);
		g_timerThreadObject = NULL;
	}

	while (!IsListEmpty(&g_natList))
	{
		pEntry = (PNF_NAT_ENTRY)RemoveHeadList(&g_natList);
		ExFreeToNPagedLookasideList( &g_laNatEntry, pEntry );
	}

	ExDeleteNPagedLookasideList( &g_laNatEntry );

	if (g_natTable)
	{
		hash_table_free(g_natTable);
		g_natTable = NULL;
	}
}

void srvcallouts_cleanup()
{
	PNF_NAT_ENTRY pEntry;
	KLOCK_QUEUE_HANDLE lh;

	KdPrint((DPREFIX"srvcallouts_cleanup\n"));

	if (!g_initialized)
		return;

	sl_lock(&g_slNat, &lh);

	while (!IsListEmpty(&g_natList))
	{
		pEntry = (PNF_NAT_ENTRY)RemoveHeadList(&g_natList);
		ht_remove_entryByPointer(g_natTable, (PHASH_TABLE_ENTRY)&pEntry->id);
		ExFreeToNPagedLookasideList( &g_laNatEntry, pEntry );
	}

	sl_unlock(&lh);

	interfaces_clear();
	ipfrag_removeAll();
	udp_port_pool_clear();
}

