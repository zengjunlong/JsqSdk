unit nfsrvapi;

interface

uses
  NetFilter2API;

const
  nfsrvapi_module = 'nfsrvapi.dll';

  { NF_STATUS }
  NF_STATUS_SUCCESS		= 0;
  NF_STATUS_FAIL			= -1;
  NF_STATUS_INVALID_ENDPOINT_ID	= -2;
  NF_STATUS_NOT_INITIALIZED	= -3;
  NF_STATUS_IO_ERROR		= -4;

  { NF_SRV_DIRECTION }
  NF_SRV_D_SRC_TO_DST = 0;	// Packets directed from source to destination
  NF_SRV_D_BOTH = 1;			// Both directions

  { NF_SRV_FILTERING_FLAG }
  NF_SRV_ALLOW = 0;		// Allow the activity
  NF_SRV_BLOCK = 1;		// Block the activity
  NF_SRV_FILTER = 2;		// Filter the transmitted packets

  { NF_CONSTS }
  NF_MAX_ADDRESS_LENGTH = 28;
  NF_MAX_IP_ADDRESS_LENGTH = 16;

  { NF_SRV_TIMEOUT_TYPE }
  NSTT_NAT_TCP = 0;
  NSTT_NAT_TCP_SYN = 1;
  NSTT_NAT_TCP_CLOSE = 2;
  NSTT_NAT_UDP = 3;
  NSTT_MAX = 4;

  { NF_SRV_FLAGS }
  NSF_NONE = 0;
  NSF_DONT_START_LOCAL_TCP_PROXY = 1;
  NSF_DONT_START_LOCAL_UDP_PROXY = 2;
  NSF_USE_REAL_UDP_RECV_ADDRESS = 4;

  { SRV_PROXY_TYPE }
  SRVPROXY_NONE = 0;
  SRVPROXY_SOCKS5 = 1;

type

  ENDPOINT_ID = Int64;

  NF_SRV_PORT_RANGE = packed record
     valueLow : word;
     valueHigh : word;
  end;

  NF_IP_ADDRESS = packed record
      ip : array [0..15] of byte;
  end;

  NF_ADDRESS = packed record
      ipFamily : byte;
      port : word;
      ip : NF_IP_ADDRESS;
  end;

  NF_SRV_RULE_ACTION = packed record
      tcpRedirectTo : NF_ADDRESS; // Local address for redirecting TCP when NF_SRV_FILTER flag is set in filteringFlag
      udpRedirectTo : NF_ADDRESS; // Local address for redirecting UDP when NF_SRV_FILTER flag is set in filteringFlag
      fcHandle : Longword;	  // Flow control context
      filteringFlag : Longword;	  // See NF_SRV_FILTERING_FLAG
  end;

  NF_SRV_FLOWCTL_DATA = packed record
      inLimit : Int64;
      outLimit : Int64;
  end;

  NF_SRV_FLOWCTL_MODIFY_DATA = packed record
      fcHandle : Longword;
      data : NF_FLOWCTL_DATA;
  end;

  NF_SRV_FLOWCTL_STAT = packed record
      inBytes : Int64;
      outBytes : Int64;
  end;

  NF_SRV_TIMEOUT = packed record
      timeoutType : Longword;
      value : Longword;
  end;

  NF_SRV_OPTIONS = packed record
      flags : Longword;
      defaultProxyPort : word;
      proxyThreadCount : Longword;
  end;

  NF_SRV_RULE = packed record
        ip_family : word;	// AF_INET for IPv4 and AF_INET6 for IPv6
        protocol : integer;	// IPPROTO_TCP, IPPROTO_UDP, ...
        interfaceLuid : Int64; // Luid of the network interface

	    // NF_D_SRC_TO_DST - apply the rule to traffic directed from source to destination
	    // NF_D_BOTH - apply the rule to all traffic between
	    //		the specified destination and source IP addresses and ports
        direction : integer;

        srcPort : NF_SRV_PORT_RANGE;	// Source port(s)
        dstPort : NF_SRV_PORT_RANGE;	// Destination port(s)

	    // Source IP (or network if srcIpAddressMask is not zero)
        srcIpAddress : NF_IP_ADDRESS;

        // Source IP mask
        srcIpAddressMask : NF_IP_ADDRESS;

	    // Destination IP (or network if remoteIpAddressMask is not zero)
        dstIpAddress : NF_IP_ADDRESS;

        // Destination IP mask
        dstIpAddressMask : NF_IP_ADDRESS;

        action : NF_SRV_RULE_ACTION;	// Rule action fields
  end;

  function nf_srv_init(driverName : PAnsiChar; var pHandler : NF_EventHandler; var options : NF_SRV_OPTIONS) : integer; cdecl; external nfsrvapi_module;
  procedure nf_srv_free(); cdecl; external nfsrvapi_module;

  function nf_srv_registerDriver(driverName : PAnsiChar): integer; cdecl; external nfsrvapi_module;
  function nf_srv_unRegisterDriver(driverName : PAnsiChar): integer; cdecl; external nfsrvapi_module;

  function nf_srv_tcpSetConnectionState(id : ENDPOINT_ID; suspended : integer): integer; cdecl; external nfsrvapi_module;
  function nf_srv_tcpPostSend(id : ENDPOINT_ID; buf : PAnsiChar; len : Longword): integer; cdecl; external nfsrvapi_module;
  function nf_srv_tcpPostReceive(id : ENDPOINT_ID; buf : PAnsiChar; len : Longword): integer; cdecl; external nfsrvapi_module;
  function nf_srv_tcpClose(id : ENDPOINT_ID): integer; cdecl; external nfsrvapi_module;
  function nf_srv_tcpSetProxy(id : ENDPOINT_ID; proxyType : integer; proxyAddress : PAnsiChar; proxyAddressLen : Longword; userName : PAnsiChar; userPassword : PAnsiChar) : integer; cdecl; external nfsrvapi_module;

  function nf_srv_udpSetConnectionState(id : ENDPOINT_ID; suspended : integer): integer; cdecl; external nfsrvapi_module;
  function nf_srv_udpPostSend(id : ENDPOINT_ID; remoteAddress : PAnsiChar; buf : PAnsiChar; len : Longword; options : pointer): integer; cdecl; external nfsrvapi_module;
  function nf_srv_udpPostReceive(id : ENDPOINT_ID; remoteAddress : PAnsiChar; buf : PAnsiChar; len : Longword; options : pointer): integer; cdecl; external nfsrvapi_module;
  function nf_srv_udpSetProxy(id : ENDPOINT_ID; proxyType : integer; proxyAddress : PAnsiChar; proxyAddressLen : Longword; userName : PAnsiChar; userPassword : PAnsiChar) : integer; cdecl; external nfsrvapi_module;

  function nf_srv_addRule(var rule : NF_SRV_RULE; toHead : integer): integer; cdecl; external nfsrvapi_module;
  function nf_srv_deleteRules(): integer; cdecl; external nfsrvapi_module;
  function nf_srv_setRules(rules : pointer; count : integer): integer; cdecl; external nfsrvapi_module;

  function nf_srv_setTimeout(timeoutType : Longword; timeout : Longword): integer; cdecl; external nfsrvapi_module;

  { Returns in pConnInfo the properties of TCP connection with specified id. }
  function nf_srv_getTCPConnInfo(id : ENDPOINT_ID; var pConnInfo : NF_TCP_CONN_INFO): integer; cdecl; external nfsrvapi_module;

  { Returns in pConnInfo the properties of UDP socket with specified id. }
  function nf_srv_getUDPConnInfo(id : ENDPOINT_ID; var pConnInfo : NF_UDP_CONN_INFO): integer; cdecl; external nfsrvapi_module;

  { Add flow control context }
  function nf_srv_addFlowCtl(var pData : NF_SRV_FLOWCTL_DATA; var pFcHandle : Longword): integer; cdecl; external nfsrvapi_module;

  { Delete flow control context }
  function nf_srv_deleteFlowCtl(fcHandle : Longword): integer; cdecl; external nfsrvapi_module;

  { Modify flow control context limits }
  function nf_srv_modifyFlowCtl(fcHandle : Longword; var pData : NF_SRV_FLOWCTL_DATA): integer; cdecl; external nfsrvapi_module;

  { Get flow control context statistics as the numbers of in/out bytes }
  function nf_srv_getFlowCtlStat(fcHandle : Longword; var pStat : NF_SRV_FLOWCTL_STAT): integer; cdecl; external nfsrvapi_module;

implementation




end.
