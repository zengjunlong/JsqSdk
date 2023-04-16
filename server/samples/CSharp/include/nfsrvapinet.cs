using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.Diagnostics;
using nfapinet;

namespace nfsrvapinet 
{
    public enum NF_SRV_DIRECTION
    {
	    NF_SRV_D_SRC_TO_DST = 0,	// Packets directed from source to destination
	    NF_SRV_D_BOTH = 1			// Both directions
    };

    public enum NF_SRV_FILTERING_FLAG
    {
	    NF_SRV_ALLOW = 0,		// Allow the activity 
	    NF_SRV_BLOCK = 1,		// Block the activity
	    NF_SRV_FILTER = 2,		// Filter the transmitted packets
    };

    public enum NF_CONSTS
    {
        NF_MAX_ADDRESS_LENGTH = 28,
        NF_MAX_IP_ADDRESS_LENGTH = 16
    };

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct NF_SRV_PORT_RANGE
    {
        public ushort valueLow;
        public ushort valueHigh;
    };

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct NF_IP_ADDRESS
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = (int)16)]
        public byte[] ip;
    };

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct NF_ADDRESS
    {
        public byte ipFamily;
        public ushort port;
        public NF_IP_ADDRESS ip;
    };

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct NF_SRV_RULE_ACTION
    {
        public NF_ADDRESS tcpRedirectTo;		// Local address for redirecting TCP when NF_SRV_FILTER flag is set in filteringFlag
        public NF_ADDRESS udpRedirectTo;		// Local address for redirecting UDP when NF_SRV_FILTER flag is set in filteringFlag
        public uint fcHandle;		// Flow control context
        public uint filteringFlag;	// See NF_SRV_FILTERING_FLAG
    };

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct NF_SRV_FLOWCTL_DATA
    {
        public ulong inLimit;
        public ulong outLimit;
    };

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct NF_SRV_FLOWCTL_MODIFY_DATA
    {
        public UInt32 fcHandle;
        public NF_FLOWCTL_DATA data;
    };

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct NF_SRV_FLOWCTL_STAT
    {
        public ulong inBytes;
        public ulong outBytes;
    };

    public enum NF_SRV_TIMEOUT_TYPE
    {
	    NSTT_NAT_TCP,
	    NSTT_NAT_TCP_SYN,
	    NSTT_NAT_TCP_CLOSE,
	    NSTT_NAT_UDP,
	    NSTT_MAX
    };

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct NF_SRV_TIMEOUT
    {
        public uint type;
        public uint value;
    };

    public enum NF_SRV_FLAGS
    {
	    NSF_NONE = 0,
	    NSF_DONT_START_LOCAL_TCP_PROXY = 1,
	    NSF_DONT_START_LOCAL_UDP_PROXY = 2,
		NSF_USE_REAL_UDP_RECV_ADDRESS = 4
    };

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct NF_SRV_OPTIONS
    {
	    public uint		flags;
        public ushort   defaultProxyPort;
        public uint     proxyThreadCount;
    };

    public enum SRV_PROXY_TYPE
    {
	    SRVPROXY_NONE,
	    SRVPROXY_SOCKS5
    };

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct NF_SRV_RULE
    {
        public ushort ip_family;	// AF_INET for IPv4 and AF_INET6 for IPv6
        public int protocol;	// IPPROTO_TCP, IPPROTO_UDP, ...
        public ulong interfaceLuid; // Luid of the network interface

	    // NF_D_SRC_TO_DST - apply the rule to traffic directed from source to destination
	    // NF_D_BOTH - apply the rule to all traffic between 
	    //		the specified destination and source IP addresses and ports
        public NF_SRV_DIRECTION direction;

        public NF_SRV_PORT_RANGE srcPort;	// Source port(s)
        public NF_SRV_PORT_RANGE dstPort;	// Destination port(s)
	
	    // Source IP (or network if srcIpAddressMask is not zero)
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = (int)NF_CONSTS.NF_MAX_IP_ADDRESS_LENGTH)]
        public byte[] srcIpAddress;	

        // Source IP mask
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = (int)NF_CONSTS.NF_MAX_IP_ADDRESS_LENGTH)]
        public byte[] srcIpAddressMask; 
    	
	    // Destination IP (or network if remoteIpAddressMask is not zero)
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = (int)NF_CONSTS.NF_MAX_IP_ADDRESS_LENGTH)]
        public byte[] dstIpAddress; 
	    
        // Destination IP mask
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = (int)NF_CONSTS.NF_MAX_IP_ADDRESS_LENGTH)]
        public byte[] dstIpAddressMask;

        public NF_SRV_RULE_ACTION action;	// Rule action fields
    };


    // Managed wrapper over API 
	public class NFSRVAPI
	{
        private static IntPtr m_pEventHandlerRaw = (IntPtr)null;
        private static NF_EventHandlerInternal m_pEventHandler;

		/**
		* Initializes the internal data structures and starts the filtering thread.
		* @param driverName The name of hooking driver, without ".sys" extension.
		* @param pHandler Pointer to event handling object
		**/
        [DllImport("nfsrvapi", CallingConvention=CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_srv_init(String driverName, IntPtr pHandler, ref NF_SRV_OPTIONS options);

        public static NF_STATUS nf_srv_init(String driverName, NF_EventHandler pEventHandler, NF_SRV_OPTIONS options)
        {
            NF_EventHandlerFwd.m_pEventHandler = pEventHandler;

            m_pEventHandler = new NF_EventHandlerInternal();
             
            m_pEventHandler.threadStart = new cbd_threadStart(NF_EventHandlerFwd.threadStart);
            m_pEventHandler.threadEnd = new cbd_threadEnd(NF_EventHandlerFwd.threadEnd);
            m_pEventHandler.tcpConnectRequest = new cbd_tcpConnectRequest(NF_EventHandlerFwd.tcpConnectRequest);
            m_pEventHandler.tcpConnected = new cbd_tcpConnected(NF_EventHandlerFwd.tcpConnected);
            m_pEventHandler.tcpClosed = new cbd_tcpClosed(NF_EventHandlerFwd.tcpClosed);
            m_pEventHandler.tcpReceive = new cbd_tcpReceive(NF_EventHandlerFwd.tcpReceive);
            m_pEventHandler.tcpSend = new cbd_tcpSend(NF_EventHandlerFwd.tcpSend);
            m_pEventHandler.tcpCanReceive = new cbd_tcpCanReceive(NF_EventHandlerFwd.tcpCanReceive);
            m_pEventHandler.tcpCanSend = new cbd_tcpCanSend(NF_EventHandlerFwd.tcpCanSend);
            m_pEventHandler.udpCreated = new cbd_udpCreated(NF_EventHandlerFwd.udpCreated);
            m_pEventHandler.udpConnectRequest = new cbd_udpConnectRequest(NF_EventHandlerFwd.udpConnectRequest);
            m_pEventHandler.udpClosed = new cbd_udpClosed(NF_EventHandlerFwd.udpClosed);
            m_pEventHandler.udpReceive = new cbd_udpReceive(NF_EventHandlerFwd.udpReceive);
            m_pEventHandler.udpSend = new cbd_udpSend(NF_EventHandlerFwd.udpSend);
            m_pEventHandler.udpCanReceive = new cbd_udpCanReceive(NF_EventHandlerFwd.udpCanReceive);
            m_pEventHandler.udpCanSend = new cbd_udpCanSend(NF_EventHandlerFwd.udpCanSend);

            m_pEventHandlerRaw = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NF_EventHandlerInternal)));
            Marshal.StructureToPtr(m_pEventHandler, m_pEventHandlerRaw, true);

            return nf_srv_init(driverName, m_pEventHandlerRaw, ref options);
        }

		/**
		* Stops the filtering thread, breaks all filtered connections and closes
		* a connection with the hooking driver.
		**/
        [DllImport("nfsrvapi", CallingConvention = CallingConvention.Cdecl)]
        public static extern void nf_srv_free();

		/**
		* Registers and starts a driver with specified name (without ".sys" extension)
		* @param driverName 
		**/
        [DllImport("nfsrvapi", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_srv_registerDriver(String driverName);

		/**
		* Unregisters a driver with specified name (without ".sys" extension)
		* @param driverName 
		**/
        [DllImport("nfsrvapi", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_srv_unRegisterDriver(String driverName);


		//
		// TCP control routines
		//

		/**
		* Suspends or resumes indicating of sends and receives for specified connection.
		* @param id Connection identifier
		* @param suspended true for suspend, false for resume 
		**/
        [DllImport("nfsrvapi", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_srv_tcpSetConnectionState(ulong id, int suspended);

		/**
		* Sends the buffer to remote server via specified connection.
		* @param id Connection identifier
		* @param buf Pointer to data buffer
		* @param len Buffer length
		**/
        [DllImport("nfsrvapi", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_srv_tcpPostSend(ulong id, IntPtr buf, int len);

		/**
		* Indicates the buffer to local process via specified connection.
		* @param id Unique connection identifier
		* @param buf Pointer to data buffer
		* @param len Buffer length
		**/
        [DllImport("nfsrvapi", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_srv_tcpPostReceive(ulong id, IntPtr buf, int len);

		/**
		* Breaks the connection with given id.
		* @param id Connection identifier
		**/
        [DllImport("nfsrvapi", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_srv_tcpClose(ulong id);

        [DllImport("nfsrvapi", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_srv_tcpSetProxy(ulong id, SRV_PROXY_TYPE proxyType, 
            IntPtr proxyAddress, int proxyAddressLen,
            String userName, String userPassword);
        
        public unsafe static NF_STATUS nf_srv_tcpSetProxy(ulong id, SRV_PROXY_TYPE proxyType,
            byte[] proxyAddress, String userName, String userPassword)
        {
            NF_STATUS result;

            fixed (byte* p = proxyAddress)
            {
                result = nf_srv_tcpSetProxy(id, proxyType, (IntPtr)p, proxyAddress.Length, userName, userPassword);
            }
            return result;
        }

        //
		// UDP control routines
		//

		/**
		* Suspends or resumes indicating of sends and receives for specified socket.
		* @param id Socket identifier
		* @param suspended true for suspend, false for resume 
		**/
        [DllImport("nfsrvapi", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_srv_udpSetConnectionState(ulong id, int suspended);

		/**
		* Sends the buffer to remote server via specified socket.
		* @param id Socket identifier
		* @param remoteAddress Destination address
		* @param buf Pointer to data buffer
		* @param len Buffer length
		**/
        [DllImport("nfsrvapi", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_srv_udpPostSend(ulong id, 
			IntPtr remoteAddress, 
			IntPtr buf, int len,
			IntPtr options);

        /**
        * Indicates the buffer to local process via specified socket.
        * @param id Unique connection identifier
        * @param remoteAddress Source address
        * @param buf Pointer to data buffer
        * @param len Buffer length
        **/
        [DllImport("nfsrvapi", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_srv_udpPostReceive(ulong id, 
			IntPtr remoteAddress, 
			IntPtr buf, int len,
			IntPtr options);

		//
		// Filtering rules 
		//

		/**
		* Add a rule to the head of rules list in driver.
		* @param pRule See <tt>NF_RULE</tt>
		* @param toHead TRUE (1) - add rule to list head, FALSE (0) - add rule to tail
		**/
        [DllImport("nfsrvapi", CallingConvention = CallingConvention.Cdecl)]
        private static extern NF_STATUS nf_srv_addRule(ref NF_SRV_RULE pRule, int toHead);

        private static void updateAddressLength(ref byte[] buf)
        {
            if (buf == null)
            {
                buf = new byte[(int)NF_CONSTS.NF_MAX_IP_ADDRESS_LENGTH];
            }
            else
            {
                if (buf.Length < (int)NF_CONSTS.NF_MAX_IP_ADDRESS_LENGTH)
                {
                    Array.Resize(ref buf, (int)NF_CONSTS.NF_MAX_IP_ADDRESS_LENGTH);
                }
            }
        }

        public static NF_STATUS nf_srv_addRule(NF_SRV_RULE pRule, int toHead)
        {
            updateAddressLength(ref pRule.srcIpAddress);
            updateAddressLength(ref pRule.srcIpAddressMask);
            updateAddressLength(ref pRule.dstIpAddress);
            updateAddressLength(ref pRule.dstIpAddressMask);
            updateAddressLength(ref pRule.action.tcpRedirectTo.ip.ip);
            updateAddressLength(ref pRule.action.udpRedirectTo.ip.ip);

            return nf_srv_addRule(ref pRule, toHead);
        }

        /**
        * Replace the rules in driver with the specified array.
        * @param pRules Array of <tt>NF_SRV_RULE</tt> structures
        * @param count Number of items in array
        **/
        [DllImport("nfapi", CallingConvention = CallingConvention.Cdecl)]
        private static extern NF_STATUS nf_srv_setRules(IntPtr pRules, int count);

        public static NF_STATUS nf_srv_setRules(NF_SRV_RULE[] rules)
        {
            NF_SRV_RULE pRule;

            IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NF_SRV_RULE)) * rules.Length);

            long longPtr = ptr.ToInt64();
            for (int i = 0; i < rules.Length; i++)
            {
                pRule = rules[i];

                updateAddressLength(ref pRule.srcIpAddress);
                updateAddressLength(ref pRule.srcIpAddressMask);
                updateAddressLength(ref pRule.dstIpAddress);
                updateAddressLength(ref pRule.dstIpAddressMask);
                updateAddressLength(ref pRule.action.tcpRedirectTo.ip.ip);
                updateAddressLength(ref pRule.action.udpRedirectTo.ip.ip);

                Marshal.StructureToPtr(pRule, new IntPtr(longPtr), false);

                longPtr += Marshal.SizeOf(typeof(NF_SRV_RULE));
            }

            return nf_srv_setRules(ptr, rules.Length);
        }

        /**
        * Removes all rules from driver.
        **/
        [DllImport("nfsrvapi", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_srv_deleteRules();

		/**
		 *	Sets the timeout for TCP connections and returns old timeout.
		 *	@param timeout Timeout value in milliseconds. Specify zero value to disable timeouts.
		 */
        [DllImport("nfsrvapi", CallingConvention = CallingConvention.Cdecl)]
        public static extern UInt32 nf_srv_setTimeout(NF_SRV_TIMEOUT_TYPE type, UInt32 timeout);

        /**
        * Returns in pConnInfo the properties of TCP connection with specified id.
        **/
        [DllImport("nfsrvapi", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_srv_getTCPConnInfo(ulong id, ref NF_TCP_CONN_INFO pConnInfo);

        /**
        * Returns in pConnInfo the properties of UDP socket with specified id.
        **/
        [DllImport("nfsrvapi", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_srv_getUDPConnInfo(ulong id, ref NF_UDP_CONN_INFO pConnInfo);

        [DllImport("nfsrvapi", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_srv_udpSetProxy(ulong id, SRV_PROXY_TYPE proxyType,
            IntPtr proxyAddress, int proxyAddressLen,
            String userName, String userPassword);

        public unsafe static NF_STATUS nf_srv_udpSetProxy(ulong id, SRV_PROXY_TYPE proxyType,
            byte[] proxyAddress, String userName, String userPassword)
        {
            NF_STATUS result;

            fixed (byte* p = proxyAddress)
            {
                result = nf_srv_udpSetProxy(id, proxyType, (IntPtr)p, proxyAddress.Length, userName, userPassword);
            }
            return result;
        }
        
        /**
        * Add flow control context
        */
        [DllImport("nfsrvapi", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_srv_addFlowCtl(ref NF_SRV_FLOWCTL_DATA pData, ref UInt32 pFcHandle);

        /**
        * Delete flow control context
        */
        [DllImport("nfsrvapi", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_srv_deleteFlowCtl(UInt32 fcHandle);

        /**
        * Modify flow control context limits
        */
        [DllImport("nfsrvapi", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_srv_modifyFlowCtl(UInt32 fcHandle, ref NF_SRV_FLOWCTL_DATA pData);

        /**
        * Get flow control context statistics as the numbers of in/out bytes
        */
        [DllImport("nfsrvapi", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_srv_getFlowCtlStat(UInt32 fcHandle, ref NF_SRV_FLOWCTL_STAT pStat);
    };

}
