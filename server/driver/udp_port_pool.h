//
// 	NetFilterSDK 
// 	Copyright (C) Vitaly Sidorov
//	All rights reserved.
//
//	This file is a part of the NetFilter SDK.
//	The code and information is provided "as-is" without
//	warranty of any kind, either expressed or implied.
//

#ifndef _UDP_PORT_POOL
#define _UDP_PORT_POOL

#include "nfsrvext.h"

BOOLEAN udp_port_pool_init();
void udp_port_pool_free();

BOOLEAN udp_port_pool_add(int ipFamily, unsigned short port);
void udp_port_pool_clear();
unsigned short udp_port_pool_get(int ipFamily);

#endif