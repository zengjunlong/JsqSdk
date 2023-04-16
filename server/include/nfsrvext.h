//
// 	NetFilterSDK 
// 	Copyright (C) Vitaly Sidorov
//	All rights reserved.
//
//	This file is a part of the NetFilter SDK.
//	The code and information is provided "as-is" without
//	warranty of any kind, either expressed or implied.
//


#ifndef _NFSRVEXT_H
#define _NFSRVEXT_H

#pragma pack(push, 1)

typedef enum _NF_SRV_DIRECTION
{
	NF_SRV_D_SRC_TO_DST = 0,	// Packets directed from source to destination
	NF_SRV_D_BOTH = 1			// Both directions
} NF_SRV_DIRECTION;

typedef enum _NF_SRV_FILTERING_FLAG
{
	NF_SRV_ALLOW = 0,		// Allow the activity 
	NF_SRV_BLOCK = 1,		// Block the activity
	NF_SRV_FILTER = 2,		// Filter the transmitted packets
} NF_SRV_FILTERING_FLAG;

typedef struct _NF_SRV_PORT_RANGE
{
    unsigned short valueLow;
    unsigned short valueHigh;
} NF_SRV_PORT_RANGE, *PNF_SRV_PORT_RANGE;

typedef struct _NF_IP_ADDRESS
{
	union 
	{
		unsigned int	v4;
		unsigned char	v6[16];
	};
} NF_IP_ADDRESS, *PNF_IP_ADDRESS;

typedef struct _NF_ADDRESS
{
	unsigned char	ipFamily;
	unsigned short	port;
	NF_IP_ADDRESS	ip;
} NF_ADDRESS, *PNF_ADDRESS;

typedef struct _NF_SRV_RULE_ACTION
{
	NF_ADDRESS				tcpRedirectTo;		// Local address for redirecting TCP when NF_SRV_FILTER flag is set in filteringFlag
	NF_ADDRESS				udpRedirectTo;		// Local address for redirecting UDP when NF_SRV_FILTER flag is set in filteringFlag
	unsigned int			fcHandle;		// Flow control context
	unsigned long			filteringFlag;	// See NF_SRV_FILTERING_FLAG
} NF_SRV_RULE_ACTION, *PNF_SRV_RULE_ACTION;

#ifndef NF_MAX_IP_ADDRESS_LENGTH
#define NF_MAX_IP_ADDRESS_LENGTH	16
#endif

typedef struct _NF_SRV_RULE
{
	unsigned short	ip_family;	// AF_INET for IPv4 and AF_INET6 for IPv6
    int				protocol;	// IPPROTO_TCP, IPPROTO_UDP, ...
    unsigned __int64	interfaceLuid; // Luid of the network interface

	// NF_D_SRC_TO_DST - apply the rule to traffic directed from source to destination
	// NF_D_BOTH - apply the rule to all traffic between 
	//		the specified destination and source IP addresses and ports
	NF_SRV_DIRECTION direction;	

	NF_SRV_PORT_RANGE	srcPort;	// Source port(s)
	NF_SRV_PORT_RANGE	dstPort;	// Destination port(s)
	
	// Source IP (or network if srcIpAddressMask is not zero)
	unsigned char	srcIpAddress[NF_MAX_IP_ADDRESS_LENGTH];	
	// Source IP mask
	unsigned char	srcIpAddressMask[NF_MAX_IP_ADDRESS_LENGTH]; 
	
	// Destination IP (or network if remoteIpAddressMask is not zero)
	unsigned char	dstIpAddress[NF_MAX_IP_ADDRESS_LENGTH]; 
	// Destination IP mask
	unsigned char	dstIpAddressMask[NF_MAX_IP_ADDRESS_LENGTH]; 

	NF_SRV_RULE_ACTION		action;	// Rule action fields
} NF_SRV_RULE, *PNF_SRV_RULE;

typedef UNALIGNED struct _NF_SRV_FLOWCTL_DATA
{
    unsigned __int64 inLimit;
    unsigned __int64 outLimit;
} NF_SRV_FLOWCTL_DATA, *PNF_SRV_FLOWCTL_DATA;

typedef UNALIGNED struct _NF_SRV_FLOWCTL_MODIFY_DATA
{
    unsigned int fcHandle;
    NF_SRV_FLOWCTL_DATA	data;
} NF_SRV_FLOWCTL_MODIFY_DATA, *PNF_SRV_FLOWCTL_MODIFY_DATA;

typedef UNALIGNED struct _NF_SRV_FLOWCTL_STAT
{
    unsigned __int64 inBytes;
    unsigned __int64 outBytes;
} NF_SRV_FLOWCTL_STAT, *PNF_SRV_FLOWCTL_STAT;

typedef struct _NF_SRV_INTERFACE_IP
{
    unsigned __int64	interfaceLuid;
	NF_ADDRESS			address;
} NF_SRV_INTERFACE_IP, *PNF_SRV_INTERFACE_IP;

typedef struct _NF_SRV_UDP_ADDRESSES
{
	NF_ADDRESS	srcAddress;	
	NF_ADDRESS	dstAddress;
} NF_SRV_UDP_ADDRESSES, *PNF_SRV_UDP_ADDRESSES;

typedef struct _NF_SRV_UDP_ADDRESSES_UPDATE
{
	NF_ADDRESS	srcAddress;	
	NF_ADDRESS	dstAddress;
	NF_ADDRESS	newDstAddress;
} NF_SRV_UDP_ADDRESSES_UPDATE, *PNF_SRV_UDP_ADDRESSES_UPDATE;

typedef enum _NF_SRV_TIMEOUT_TYPE
{
	NSTT_NAT_TCP,
	NSTT_NAT_TCP_SYN,
	NSTT_NAT_TCP_CLOSE,
	NSTT_NAT_UDP,
	NSTT_MAX
} NF_SRV_TIMEOUT_TYPE;

typedef struct _NF_SRV_TIMEOUT
{
	unsigned int	type;
	unsigned int	value;
} NF_SRV_TIMEOUT, *PNF_SRV_TIMEOUT;

#pragma pack(pop)

#ifdef _NF_INTERNALS

#define NF_SRV_ADD_FLOW_CTL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 301, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define NF_SRV_DELETE_FLOW_CTL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 302, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define NF_SRV_MODIFY_FLOW_CTL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 303, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define NF_SRV_GET_FLOW_CTL_STAT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 304, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define NF_SRV_INTERFACE_ADD \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 305, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define NF_SRV_INTERFACE_CLEAR \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 306, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define NF_SRV_RULE_ADD_TO_HEAD \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 307, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define NF_SRV_RULE_ADD_TO_TAIL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 308, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define NF_SRV_RULE_CLEAR \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 309, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define NF_SRV_GET_TCP_DST_ADDRESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 310, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define NF_SRV_GET_UDP_DST_ADDRESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 311, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define NF_SRV_SET_TIMEOUT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 312, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define NF_SRV_CLEAR_TEMP_RULES \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 313, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define NF_SRV_ADD_TEMP_RULE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 314, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define NF_SRV_SET_TEMP_RULES \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 315, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define NF_SRV_UPDATE_UDP_DST_ADDRESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 316, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define NF_SRV_ADD_UDP_PORT_IPv4 \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 317, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define NF_SRV_ADD_UDP_PORT_IPv6 \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 318, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define NF_SRV_CLEAR_UDP_PORTS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 319, METHOD_BUFFERED, FILE_ANY_ACCESS)

#endif

#endif // _NFSRVEXT_H