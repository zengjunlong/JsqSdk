//
// Saves classified objects to *.bin files.
//

#include "stdafx.h"
#include <crtdbg.h>
#include <process.h>
#include <map>
#include <queue>
#include "nfsrvapi.h"
#include "ProtocolFilters.h"
#include "PFEventsDefault.h"

using namespace nfsrvapi;
using namespace nfapi;
using namespace ProtocolFilters;

// Change this string after renaming and registering the driver under different name
#define NFDRIVER_NAME "nfsrvfilter"

std::string typeName(tPF_ObjectType t)
{
	switch (t)
	{
	case OT_HTTPS_PROXY_REQUEST:
		return "https_proxy_request";
	case OT_SOCKS4_REQUEST:
		return "socks4_proxy_request";
	case OT_SOCKS5_AUTH_REQUEST:
		return "socks5_proxy_auth_request";
	case OT_SOCKS5_AUTH_UNPW:
		return "socks5_proxy_unpw_request";
	case OT_SOCKS5_REQUEST:
		return "socks5_proxy_request";
	case OT_HTTP_REQUEST:
		return "http_request";
	case OT_HTTP_RESPONSE:
		return "http_response";
	case OT_POP3_MAIL_INCOMING:
		return "incoming_mail";
	case OT_SMTP_MAIL_OUTGOING:
		return "outgoing_mail";
	case OT_RAW_INCOMING:
		return "raw_in";
	case OT_RAW_OUTGOING:
		return "raw_out";
	case OT_FTP_COMMAND:
		return "ftp_command";
	case OT_FTP_RESPONSE:
		return "ftp_response";
	case OT_FTP_DATA_OUTGOING:
		return "ftp_data_outgoing";
	case OT_FTP_DATA_INCOMING:
		return "ftp_data_incoming";
	case OT_FTP_DATA_PART_OUTGOING:
		return "ftp_data_part_outgoing";
	case OT_FTP_DATA_PART_INCOMING:
		return "ftp_data_part_incoming";
	case OT_NNTP_ARTICLE:
		return "nntp_article";
	case OT_NNTP_POST:
		return "nntp_post";
	case OT_ICQ_LOGIN:
		return "icq_login";
	case OT_ICQ_CHAT_MESSAGE_OUTGOING:
		return "icq_chat_outgoing";
	case OT_ICQ_CHAT_MESSAGE_INCOMING:
		return "icq_chat_incoming";
	case OT_ICQ_REQUEST:
		return "icq_request";
	case OT_ICQ_RESPONSE:
		return "icq_response";
	case OT_XMPP_REQUEST:
		return "xmpp_request";
	case OT_XMPP_RESPONSE:
		return "xmpp_response";
	}
	return "";
}

void saveObject(ENDPOINT_ID id, PFObject * object)
{
	char fileName[_MAX_PATH];
	static int c = 0;
	tPF_ObjectType ot = object->getType();
	std::string t = typeName(ot);
	char tempBuf[1000];
	int tempLen;
	PFStream * pStream;

	c++;

	_snprintf(fileName, sizeof(fileName), "%I64u_%.8d_%s.bin", id, c, t.c_str());

	FILE * f = fopen(fileName, "wb");
	if (f)
	{
		for (int i=0; i<object->getStreamCount(); i++)
		{
			pStream = object->getStream(i);
			if (pStream)
			{
				pStream->seek(0, FILE_BEGIN);
				for (;;)
				{
					tempLen = pStream->read(tempBuf, sizeof(tempBuf));
					if (tempLen <= 0)
						break;

					fwrite(tempBuf, tempLen, 1, f);
				}
				pStream->seek(0, FILE_BEGIN);
			}

			if (ot == OT_FTP_DATA_INCOMING ||
				ot == OT_FTP_DATA_OUTGOING ||
				ot == OT_FTP_DATA_PART_INCOMING ||
				ot == OT_FTP_DATA_PART_OUTGOING ||
				ot == OT_ICQ_LOGIN ||
				ot == OT_ICQ_CHAT_MESSAGE_OUTGOING ||
				ot == OT_ICQ_CHAT_MESSAGE_INCOMING)
			{
				break;
			}
		}
		fclose(f);
	}
	
	if (object->getType() == OT_FTP_DATA_INCOMING ||
		object->getType() == OT_FTP_DATA_OUTGOING ||
		object->getType() == OT_FTP_DATA_PART_INCOMING ||
		object->getType() == OT_FTP_DATA_PART_OUTGOING)
	{
		_snprintf(fileName, sizeof(fileName), "%I64u_%.8d_%s.info", id, c, t.c_str());

		f = fopen(fileName, "wb");
		if (f)
		{
			pStream = object->getStream(1);
			if (pStream)
			{
				pStream->seek(0, FILE_BEGIN);
				for (;;)
				{
					tempLen = pStream->read(tempBuf, sizeof(tempBuf));
					if (tempLen <= 0)
						break;

					fwrite(tempBuf, tempLen, 1, f);
				}
				pStream->seek(0, FILE_BEGIN);
			}
			fclose(f);
		}
	} else
	if (object->getType() == OT_ICQ_LOGIN)
	{
		_snprintf(fileName, sizeof(fileName), "%I64u_%.8d_%s.info", id, c, t.c_str());

		f = fopen(fileName, "wb");
		if (f)
		{
			fwrite("User: ", 6, 1, f);

			pStream = object->getStream(ICQS_USER_UIN);
			if (pStream)
			{
				pStream->seek(0, FILE_BEGIN);
				for (;;)
				{
					tempLen = pStream->read(tempBuf, sizeof(tempBuf));
					if (tempLen <= 0)
						break;

					fwrite(tempBuf, tempLen, 1, f);
				}
				pStream->seek(0, FILE_BEGIN);
			}
			fclose(f);
		}
	} else
	if (object->getType() == OT_ICQ_CHAT_MESSAGE_OUTGOING ||
		object->getType() == OT_ICQ_CHAT_MESSAGE_INCOMING)
	{
		_snprintf(fileName, sizeof(fileName), "%I64u_%.8d_%s.info", id, c, t.c_str());

		f = fopen(fileName, "wb");
		if (f)
		{
			fwrite("User: ", 6, 1, f);

			pStream = object->getStream(ICQS_USER_UIN);
			if (pStream)
			{
				pStream->seek(0, FILE_BEGIN);
				for (;;)
				{
					tempLen = pStream->read(tempBuf, sizeof(tempBuf));
					if (tempLen <= 0)
						break;

					fwrite(tempBuf, tempLen, 1, f);
				}
				pStream->seek(0, FILE_BEGIN);
			}

			fwrite("\r\n", 2, 1, f);

			fwrite("Contact: ", 9, 1, f);

			pStream = object->getStream(ICQS_CONTACT_UIN);
			if (pStream)
			{
				pStream->seek(0, FILE_BEGIN);
				for (;;)
				{
					tempLen = pStream->read(tempBuf, sizeof(tempBuf));
					if (tempLen <= 0)
						break;

					fwrite(tempBuf, tempLen, 1, f);
				}
				pStream->seek(0, FILE_BEGIN);
			}

			fwrite("\r\n", 2, 1, f);

			fclose(f);
		}
	
		int textFormat = ICQTF_ANSI;

		pStream = object->getStream(ICQS_TEXT_FORMAT);
		if (pStream && (pStream->size() > 0))
		{
			pStream->seek(0, FILE_BEGIN);
			pStream->read(&textFormat, sizeof(textFormat));
		}

		pStream = object->getStream(ICQS_TEXT);
		if (pStream && (pStream->size() > 0))
		{
			_snprintf(fileName, sizeof(fileName), "%I64u_%.8d_%s_fmt%d.txt", id, c, t.c_str(), textFormat);

			f = fopen(fileName, "wb");
			if (f)
			{
				pStream->seek(0, FILE_BEGIN);
				for (;;)
				{
					tempLen = pStream->read(tempBuf, sizeof(tempBuf));
					if (tempLen <= 0)
						break;

					fwrite(tempBuf, tempLen, 1, f);
				}
				pStream->seek(0, FILE_BEGIN);

				fclose(f);
			}
		}
	}

}

class PFHandler : public PFEvents
{
public:
	PFHandler()
	{
	}

	virtual void threadStart()
	{
	}

	virtual void threadEnd()
	{
	}

	void tcpConnectRequest(nfapi::ENDPOINT_ID id, nfapi::PNF_TCP_CONN_INFO pConnInfo)
	{
	}

	void tcpConnected(nfapi::ENDPOINT_ID id, nfapi::PNF_TCP_CONN_INFO pConnInfo)
	{
			pf_addFilter(id, FT_PROXY, FF_READ_ONLY_OUT | FF_READ_ONLY_IN);
			pf_addFilter(id, FT_SSL, FF_SSL_VERIFY);
			pf_addFilter(id, FT_FTP, FF_SSL_TLS | FF_READ_ONLY_IN | FF_READ_ONLY_OUT);
			pf_addFilter(id, FT_HTTP, FF_READ_ONLY_OUT | FF_READ_ONLY_IN | FF_HTTP_BLOCK_SPDY);
			pf_addFilter(id, FT_POP3, FF_SSL_TLS | FF_READ_ONLY_IN);
			pf_addFilter(id, FT_SMTP, FF_SSL_TLS | FF_READ_ONLY_OUT);
			pf_addFilter(id, FT_NNTP, FF_READ_ONLY_OUT | FF_READ_ONLY_IN);
			pf_addFilter(id, FT_ICQ, FF_READ_ONLY_OUT | FF_READ_ONLY_IN);
			pf_addFilter(id, FT_XMPP, FF_SSL_TLS | FF_READ_ONLY_OUT | FF_READ_ONLY_IN);
			pf_addFilter(id, FT_RAW, FF_READ_ONLY_OUT | FF_READ_ONLY_IN);
	}
	
	void tcpClosed(nfapi::ENDPOINT_ID id, nfapi::PNF_TCP_CONN_INFO pConnInfo)
	{
	}


	void dataAvailable(nfapi::ENDPOINT_ID id, PFObject * object)
	{
		if (object->getStreamCount() > 0)
		{
			saveObject(id, object);
		}

		pf_postObject(id, object);
	}
	
	PF_DATA_PART_CHECK_RESULT dataPartAvailable(nfapi::ENDPOINT_ID id, PFObject * pObject)
	{
		if (pObject->getType() == OT_SSL_INVALID_SERVER_CERTIFICATE)
			return DPCR_BYPASS;

		return DPCR_FILTER_READ_ONLY;
	}

	virtual void udpCreated(nfapi::ENDPOINT_ID id, nfapi::PNF_UDP_CONN_INFO pConnInfo)
	{
	}
		
	virtual void udpConnectRequest(nfapi::ENDPOINT_ID id, nfapi::PNF_UDP_CONN_REQUEST pConnReq)
	{
	}

	virtual void udpClosed(nfapi::ENDPOINT_ID id, nfapi::PNF_UDP_CONN_INFO pConnInfo)
	{
	}

	NF_STATUS tcpPostSend(nfapi::ENDPOINT_ID id, const char * buf, int len)
	{
		return nf_srv_tcpPostSend(id, buf, len);
	}

	NF_STATUS tcpPostReceive(nfapi::ENDPOINT_ID id, const char * buf, int len)
	{
		return nf_srv_tcpPostReceive(id, buf, len);
	}

	NF_STATUS tcpSetConnectionState(nfapi::ENDPOINT_ID id, int suspended)
	{
		return nf_srv_tcpSetConnectionState(id, suspended);
	}

	virtual NF_STATUS udpPostSend(nfapi::ENDPOINT_ID id, const unsigned char * remoteAddress, 
									const char * buf, int len, 
									nfapi::PNF_UDP_OPTIONS options)
	{
		return nf_srv_udpPostSend(id, remoteAddress, buf, len, options);
	}

	virtual NF_STATUS udpPostReceive(nfapi::ENDPOINT_ID id, const unsigned char * remoteAddress, 
			const char * buf, int len, nfapi::PNF_UDP_OPTIONS options)
	{
		return nf_srv_udpPostReceive(id, remoteAddress, buf, len, options);
	}

	virtual NF_STATUS udpSetConnectionState(nfapi::ENDPOINT_ID id, int suspended)
	{
		return nf_srv_udpSetConnectionState(id, suspended);
	}

};



int main(int argc, char* argv[])
{
	PFHandler ph;

#ifdef _DEBUG
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
	_CrtSetReportMode( _CRT_ERROR, _CRTDBG_MODE_DEBUG);
#endif

	if (!pf_init(&ph, L"c:\\netfilter2"))
	{
		printf("Failed to initialize protocolfilters");
		return -1;
	}

	// Don't import root certificate, it must be imported on the client side
	pf_setRootSSLCertImportFlags(RSIF_DONT_IMPORT);

	// Use root certificate with specified name
	pf_setRootSSLCertSubject("Sample CA");

	NF_SRV_OPTIONS options;

	memset(&options, 0, sizeof(options));

	// Initialize the library and start filtering
	if (nf_srv_init(NFDRIVER_NAME, pf_getNFEventHandler(), &options) != NF_STATUS_SUCCESS)
	{
		printf("Failed to connect to driver");
		return -1;
	}

	NF_SRV_RULE rule;

	memset(&rule, 0, sizeof(rule));
//	rule.protocol = IPPROTO_TCP;
	rule.action.filteringFlag = NF_FILTER;

	nf_srv_addRule(&rule, FALSE);

	// Block QUIC
	memset(&rule, 0, sizeof(rule));
	rule.direction = NF_SRV_D_BOTH;
	rule.protocol = IPPROTO_UDP;
	rule.dstPort.valueHigh = rule.dstPort.valueLow = 80;
	rule.action.filteringFlag = NF_SRV_BLOCK;
	nf_srv_addRule(&rule, TRUE);

	rule.dstPort.valueHigh = rule.dstPort.valueLow = 443;
	nf_srv_addRule(&rule, TRUE);

	printf("Press enter to stop...\n\n");
	// Wait for enter
	getchar();

	// Free the library
	nf_srv_free();

	return 0;
}
