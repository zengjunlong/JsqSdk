//
// 	NetFilterSDK 
// 	Copyright (C) Vitaly Sidorov
//	All rights reserved.
//
//	This file is a part of the NetFilter SDK.
//	The code and information is provided "as-is" without
//	warranty of any kind, either expressed or implied.
//


#ifndef _STDINC_H
#define _STDINC_H

#ifdef _NXPOOLS
#ifdef USE_NTDDI
#if (NTDDI_VERSION >= NTDDI_WIN8)
#define POOL_NX_OPTIN 1
#endif
#endif
#endif

#include <ntifs.h>
#include <ntstrsafe.h>

#include <fwpsk.h>
#include <fwpmk.h>

#include <ws2ipdef.h>
#include <in6addr.h>
#include <ip2string.h>
#include <stdlib.h>

#undef ASSERT
#define ASSERT(x)

#define MEM_TAG		'VSNF'
#define MEM_TAG_NAT	'TANF'
#define MEM_TAG_FRAG 'FSNF'

#define malloc_np(size)	ExAllocatePoolWithTag(NonPagedPool, (size), MEM_TAG)
#define free_np(p) ExFreePool(p);

#define sl_init(x) KeInitializeSpinLock(x)
#define sl_lock(x, lh) KeAcquireInStackQueuedSpinLock(x, lh)
#define sl_unlock(lh) KeReleaseInStackQueuedSpinLock(lh)

#define htonl(x) (((((ULONG)(x))&0xffL)<<24)           | \
	((((ULONG)(x))&0xff00L)<<8)        | \
	((((ULONG)(x))&0xff0000L)>>8)        | \
	((((ULONG)(x))&0xff000000L)>>24))

#define htons(_x_) RtlUshortByteSwap(_x_)

#define DPREFIX "[NFS] "

#define DEFAULT_HASH_SIZE 3019

//
// Software Tracing Definitions 
//

#define WPP_CONTROL_GUIDS \
    WPP_DEFINE_CONTROL_GUID(CtlGuid,(a7f09d73, 5ac6, 4b8b, 8a33, e7b8c87e4610),  \
        WPP_DEFINE_BIT(FLAG_INFO))

#define _NF_INTERNALS

#endif