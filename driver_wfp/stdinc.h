//
// 	NetFilterSDK 
// 	Copyright (C) 2013 Vitaly Sidorov
//	All rights reserved.
//
//	This file is a part of the NetFilter SDK.
//	The code and information is provided "as-is" without
//	warranty of any kind, either expressed or implied.
//


#ifndef _STDINC_H
#define _STDINC_H

#define _NXPOOLS 1

#ifdef _NXPOOLS
#if defined(USE_NTDDI) && (NTDDI_VERSION >= NTDDI_WIN8)
#define POOL_NX_OPTIN 1
#endif
#endif

#include <ntifs.h>
#include <ntstrsafe.h>

#include <fwpsk.h>
#include <fwpmk.h>

#include "wfplink.h"

#include <ws2ipdef.h>
#include <in6addr.h>
#include <ip2string.h>
#include <stdlib.h>

#undef ASSERT
#define ASSERT(x)

#define MEM_TAG		'3TLF'
#define MEM_TAG_TCP	'TTLF'
#define MEM_TAG_TCP_PACKET	'PTLF'
#define MEM_TAG_TCP_DATA	'DTLF'
#define MEM_TAG_TCP_DATA_COPY	'CTLF'
#define MEM_TAG_TCP_INJECT	'ITLF'
#define MEM_TAG_UDP	'UULF'
#define MEM_TAG_UDP_PACKET	'PULF'
#define MEM_TAG_UDP_DATA	'DULF'
#define MEM_TAG_UDP_DATA_COPY	'CULF'
#define MEM_TAG_UDP_INJECT	'IULF'
#define MEM_TAG_QUEUE	'QTLF'
#define MEM_TAG_IP_PACKET	'PILF'
#define MEM_TAG_IP_DATA_COPY 'DILF'
#define MEM_TAG_IP_INJECT	'IILF'

#define malloc_np(size)	ExAllocatePoolWithTag(NonPagedPool, (size), MEM_TAG)
#define free_np(p) ExFreePool(p);
#define _memcmp(p1, p2, len) (RtlCompareMemory(p1, p2, (SIZE_T)len) != (SIZE_T)len)

#define sl_init(x) *x = 0
#define sl_lock(x, lh) KeAcquireInStackQueuedSpinLock(x, lh)
#define sl_unlock(lh) KeReleaseInStackQueuedSpinLock(lh)

#define htonl(x) (((((ULONG)(x))&0xffL)<<24)           | \
	((((ULONG)(x))&0xff00L)<<8)        | \
	((((ULONG)(x))&0xff0000L)>>8)        | \
	((((ULONG)(x))&0xff000000L)>>24))

#define htons(_x_) ((((unsigned char*)&_x_)[0] << 8) & 0xFF00) | ((unsigned char*)&_x_)[1] 

#define DPREFIX "[NF3] "

#define DEFAULT_HASH_SIZE 3019

//
// Software Tracing Definitions 
//

#define WPP_CONTROL_GUIDS \
    WPP_DEFINE_CONTROL_GUID(CtlGuid,(a7f09d73, 5ac6, 4b8b, 8a33, e7b8c87e4609),  \
        WPP_DEFINE_BIT(FLAG_INFO))

#define _NF_INTERNALS

BOOLEAN regPathExists(wchar_t * registryPath);

#endif