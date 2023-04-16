using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using nfsrvapinet;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace SrvPassThroughCS
{
    using ENDPOINT_ID = Int64;
    using nfapinet;

    public unsafe class NFUtil
    {
        public static SocketAddress convertAddress(byte[] buf)
        {
            if (buf == null)
            {
                return new SocketAddress(AddressFamily.InterNetwork);
            }

            SocketAddress addr = new SocketAddress((AddressFamily)(buf[0]), (int)NF_CONSTS.NF_MAX_ADDRESS_LENGTH);

            for (int i = 0; i < (int)NF_CONSTS.NF_MAX_ADDRESS_LENGTH; i++)
            {
                addr[i] = buf[i];
            }

            return addr;
        }

        public static string addressToString(SocketAddress addr)
        {
            IPEndPoint ipep;

            if (addr.Family == AddressFamily.InterNetworkV6)
            {
                ipep = new IPEndPoint(IPAddress.IPv6None, 0);
            }
            else
            {
                ipep = new IPEndPoint(0, 0);
            }
            ipep = (IPEndPoint)ipep.Create(addr);
            return ipep.ToString();
        }
    }

    // API events handler
    unsafe public class EventHandler : NF_EventHandler
    {
        public void threadStart()
        {
            Console.Out.WriteLine("threadStart");
        }
		
        public void threadEnd()
		{
            Console.Out.WriteLine("threadEnd");
        }

        public void tcpConnectRequest(ulong id, ref NF_TCP_CONN_INFO connInfo)
        {
            Console.Out.WriteLine("tcpConnectRequest id=" + id);
        }

        public void tcpConnected(ulong id, NF_TCP_CONN_INFO connInfo)
		{
            string s = "TCP id=" + id + " ";

            s += ((NF_DIRECTION)connInfo.direction == NF_DIRECTION.NF_D_IN) ? "[in]" : "[out]";

            s += "\n";

            try
            {
                SocketAddress localAddr = NFUtil.convertAddress(connInfo.localAddress);
                s += NFUtil.addressToString(localAddr);

                s += "<->";

                SocketAddress remoteAddr = NFUtil.convertAddress(connInfo.remoteAddress);
                s += NFUtil.addressToString(remoteAddr);
            }
            catch (Exception)
            {
            }

            s += " ";

            Console.Out.WriteLine(s);
        }

		public void tcpClosed(ulong id, NF_TCP_CONN_INFO connInfo)
		{
            string s = "TCP id=" + id + " ";

            s += ((NF_DIRECTION)connInfo.direction == NF_DIRECTION.NF_D_IN) ? "[in]" : "[out]";

            s += " closed ";

            Console.Out.WriteLine(s);

        }

        public unsafe void tcpReceive(ulong id, byte[] buf)
        {
            // Filter the data in buf

            fixed (byte* p = buf)
            {
                NFSRVAPI.nf_srv_tcpPostReceive(id, (IntPtr)p, buf.Length);
            }
        }

        public void tcpReceive(ulong id, IntPtr buf, int len)
		{
            string s = "TCP id=" + id + " receive len=" + len;
            Console.Out.WriteLine(s);

            // Copy the data to managed buffer for convenience
            byte[] mbuf = new byte[len];
            if (len > 0)
            {
                Marshal.Copy((IntPtr)buf, mbuf, 0, len);
            }

            tcpReceive(id, mbuf);
		}

        public unsafe void tcpSend(ulong id, byte[] buf)
        {
            // Filter the data in buf

            fixed (byte* p = buf)
            {
                NFSRVAPI.nf_srv_tcpPostSend(id, (IntPtr)p, buf.Length);
            }
        }

        public void tcpSend(ulong id, IntPtr buf, int len)
		{
            string s = "TCP id=" + id + " send len=" + len;
            Console.Out.WriteLine(s);

            byte[] mbuf = new byte[len];
            if (len > 0)
            {
                Marshal.Copy((IntPtr)buf, mbuf, 0, len);
            }
            tcpSend(id, mbuf);
        }

		public void tcpCanReceive(ulong id)
		{
            Console.Out.WriteLine("TCP id=" + id + " tcpCanReceive");
        }

		public void tcpCanSend(ulong id)
		{
            Console.Out.WriteLine("TCP id=" + id + " tcpCanSend");
        }

		public void udpCreated(ulong id, NF_UDP_CONN_INFO connInfo)
		{
            string s = "UDP id=" + id + " socket created ";

            try
            {
                SocketAddress localAddr = NFUtil.convertAddress(connInfo.localAddress);
                s += " localAddr=" + NFUtil.addressToString(localAddr);
            }
            catch (Exception)
            {
            }

            s += "\n";

            Console.Out.WriteLine(s);
        }

        public void udpConnectRequest(ulong id, ref NF_UDP_CONN_REQUEST connReq)
        {
            Console.Out.WriteLine("udpConnectRequest id=" + id);
        }

        public void udpClosed(ulong id, NF_UDP_CONN_INFO connInfo)
		{
            string s = "UDP id=" + id + " socket closed";

            Console.Out.WriteLine(s);
        }

        public void udpReceive(ulong id, IntPtr remoteAddress, IntPtr buf, int len, IntPtr options, int optionsLen)
		{
            string s = "UDP id=" + id + " receive len=" + len;
            
            s += "\n<-";

            try
            {
                byte[] remoteAddressBuf = new byte[(int)NF_CONSTS.NF_MAX_ADDRESS_LENGTH];
                Marshal.Copy((IntPtr)remoteAddress, remoteAddressBuf, 0, (int)NF_CONSTS.NF_MAX_ADDRESS_LENGTH);
                SocketAddress remoteAddr = NFUtil.convertAddress(remoteAddressBuf);
                s += NFUtil.addressToString(remoteAddr);
            }
            catch (Exception)
            {
            }

            Console.Out.WriteLine(s);

            NFSRVAPI.nf_srv_udpPostReceive(id, remoteAddress, buf, len, options);
        }

        public void udpSend(ulong id, IntPtr remoteAddress, IntPtr buf, int len, IntPtr options, int optionsLen)
		{
            string s = "UDP id=" + id + " send len=" + len;
            
            s += "\n->";

            try
            {
                byte[] remoteAddressBuf = new byte[(int)NF_CONSTS.NF_MAX_ADDRESS_LENGTH];
                Marshal.Copy((IntPtr)remoteAddress, remoteAddressBuf, 0, (int)NF_CONSTS.NF_MAX_ADDRESS_LENGTH);
                SocketAddress remoteAddr = NFUtil.convertAddress(remoteAddressBuf);
                s += NFUtil.addressToString(remoteAddr);
            }
            catch (Exception)
            {
            }

            Console.Out.WriteLine(s);

            NFSRVAPI.nf_srv_udpPostSend(id, remoteAddress, buf, len, options);
        }

		public void udpCanReceive(ulong id)
		{
            Console.Out.WriteLine("UDP id=" + id + " udpCanReceive");
        }

		public void udpCanSend(ulong id)
		{
            Console.Out.WriteLine("UDP id=" + id + " udpCanSend");
        }
    }

    class Program
    {
        static EventHandler m_eh = new EventHandler();

        unsafe static void Main(string[] args)
        {
            NF_SRV_OPTIONS options;
            options.flags = 0;
            options.defaultProxyPort = (ushort)IPAddress.HostToNetworkOrder((Int16)10080);
            options.proxyThreadCount = 0;

            if (NFSRVAPI.nf_srv_init("nfsrvfilter", m_eh, options) != NF_STATUS.NF_STATUS_SUCCESS)
                return;

            NF_SRV_RULE rule = new NF_SRV_RULE();
            // Filter all TCP connections and UDP datagrams
            rule.action.filteringFlag = (uint)NF_SRV_FILTERING_FLAG.NF_SRV_FILTER;
             
            NFSRVAPI.nf_srv_addRule(rule, 1);

            Console.In.ReadLine();

            NFSRVAPI.nf_srv_free();
        }
    }
}
