//
// 	NetFilterSDK 
// 	Copyright (C) Vitaly Sidorov
//	All rights reserved.
//
//	This file is a part of the NetFilter SDK.
//	The code and information is provided "as-is" without
//	warranty of any kind, either expressed or implied.
//


#pragma once

#ifndef WINVER				// Allow use of features specific to Windows XP or later.
#define WINVER 0x0602		// Change this to the appropriate value to target other versions of Windows.
#endif

#ifndef _WIN32_WINNT		// Allow use of features specific to Windows XP or later.                   
#define _WIN32_WINNT 0x0602	// Change this to the appropriate value to target other versions of Windows.
#endif						

#define _CRT_SECURE_NO_DEPRECATE 1
#define _SECURE_SCL 0

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <process.h>
#include <stdio.h>
#include <stdlib.h>
