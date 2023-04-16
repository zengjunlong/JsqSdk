//
// 	NetFilterSDK 
// 	Copyright (C) Vitaly Sidorov
//	All rights reserved.
//
//	This file is a part of the NetFilter SDK.
//	The code and information is provided "as-is" without
//	warranty of any kind, either expressed or implied.
//


#ifndef _WFPLINK_H
#define _WFPLINK_H

typedef FWPM_SERVICE_STATE (NTAPI * t_FwpmBfeStateGet0)(void);

typedef NTSTATUS (NTAPI * t_FwpmBfeStateSubscribeChanges0)(
   void* deviceObject,
   FWPM_SERVICE_STATE_CHANGE_CALLBACK0 callback,
   void* context,
   HANDLE* changeHandle
   );

typedef NTSTATUS (NTAPI * t_FwpmBfeStateUnsubscribeChanges0)(
   HANDLE changeHandle
   );

typedef NTSTATUS (NTAPI *t_FwpsCalloutRegister1)(
   void* deviceObject,
   const FWPS_CALLOUT1* callout,
   UINT32* calloutId
   );

typedef NTSTATUS (NTAPI * t_FwpsCalloutUnregisterByKey0)(const GUID* calloutKey);

typedef NTSTATUS (NTAPI * t_FwpmTransactionBegin0)(
   HANDLE engineHandle,
   UINT32 flags
   );

typedef NTSTATUS (NTAPI * t_FwpmTransactionCommit0)(HANDLE engineHandle);

typedef NTSTATUS (NTAPI * t_FwpmEngineClose0)(HANDLE engineHandle);

typedef NTSTATUS (NTAPI * t_FwpmCalloutAdd0)(
   HANDLE engineHandle,
   const FWPM_CALLOUT0* callout,
   PSECURITY_DESCRIPTOR sd,
   UINT32* id
   );

typedef NTSTATUS (NTAPI * t_FwpmFilterAdd0)(
   HANDLE engineHandle,
   const FWPM_FILTER0* filter,
   PSECURITY_DESCRIPTOR sd,
   UINT64* id
   );

typedef NTSTATUS (NTAPI * t_FwpmSubLayerCreateEnumHandle0)(
   HANDLE engineHandle,
   const FWPM_SUBLAYER_ENUM_TEMPLATE0* enumTemplate,
   HANDLE* enumHandle
   );

typedef NTSTATUS (NTAPI * t_FwpmSubLayerEnum0)(
   HANDLE engineHandle,
   HANDLE enumHandle,
   UINT32 numEntriesRequested,
   FWPM_SUBLAYER0*** entries,
   UINT32* numEntriesReturned
   );

typedef void (NTAPI * t_FwpmFreeMemory0)(void** p);

typedef NTSTATUS (NTAPI * t_FwpmSubLayerDestroyEnumHandle0)(
   HANDLE engineHandle,
   HANDLE enumHandle
   );

typedef NTSTATUS (NTAPI * t_FwpmSubLayerAdd0)(
   HANDLE engineHandle,
   const FWPM_SUBLAYER0* subLayer,
   PSECURITY_DESCRIPTOR sd
   );

typedef NTSTATUS (NTAPI * t_FwpmTransactionAbort0)(HANDLE engineHandle);

typedef NTSTATUS (NTAPI * t_FwpmEngineOpen0)(
   const wchar_t* serverName,
   UINT32 authnService,
   SEC_WINNT_AUTH_IDENTITY_W* authIdentity,
   const FWPM_SESSION0* session,
   HANDLE* engineHandle
   );

typedef NTSTATUS (NTAPI * t_FwpmProviderAdd0)(
   HANDLE engineHandle,
   const FWPM_PROVIDER0* provider,
   PSECURITY_DESCRIPTOR sd
   );

typedef NTSTATUS (NTAPI * t_FwpmSubLayerDeleteByKey0)(
   HANDLE engineHandle,
   const GUID* key
   );

typedef NTSTATUS (NTAPI * t_FwpmProviderContextDeleteByKey0)(
   HANDLE engineHandle,
   const GUID* key
   );

typedef NTSTATUS (NTAPI * t_FwpsInjectionHandleCreate0)(
   ADDRESS_FAMILY addressFamily,
   UINT32 flags,
   HANDLE* injectionHandle
   );

typedef NTSTATUS (NTAPI * t_FwpsInjectionHandleDestroy0)(HANDLE injectionHandle);

typedef void (NTAPI * t_FwpsCopyStreamDataToBuffer0)(
         const FWPS_STREAM_DATA0* calloutStreamData,
         PVOID buffer,
         SIZE_T bytesToCopy,
         SIZE_T* bytesCopied
         );

typedef void (NTAPI * t_FwpsFreeCloneNetBufferList0)(
   NET_BUFFER_LIST* netBufferList,
   ULONG freeCloneFlags
   );

typedef NTSTATUS (NTAPI * t_FwpsStreamInjectAsync0)(
   HANDLE injectionHandle,
   HANDLE injectionContext,
   UINT32 flags,
   UINT64 flowId,
   UINT32 calloutId,
   UINT16 layerId,
   UINT32 streamFlags,
   NET_BUFFER_LIST* netBufferList,
   SIZE_T dataLength,
   FWPS_INJECT_COMPLETE0 completionFn,
   HANDLE completionContext
   );

typedef NTSTATUS (NTAPI * t_FwpsAllocateNetBufferAndNetBufferList0)(
   NDIS_HANDLE poolHandle,
   USHORT contextSize,
   USHORT contextBackFill,
   MDL* mdlChain,
   ULONG dataOffset,
   SIZE_T dataLength,
   NET_BUFFER_LIST** netBufferList
   );

typedef void (NTAPI * t_FwpsFreeNetBufferList0)(
   NET_BUFFER_LIST* netBufferList
   );

typedef NTSTATUS (NTAPI * t_FwpsConstructIpHeaderForTransportPacket0)(
   NET_BUFFER_LIST* netBufferList,
   ULONG headerIncludeHeaderLength,
   ADDRESS_FAMILY addressFamily,
   const UCHAR* sourceAddress,
   const UCHAR* remoteAddress,
   IPPROTO nextProtocol,
   UINT64 endpointHandle,
   const WSACMSGHDR* controlData,
   ULONG controlDataLength,
   UINT32 flags,
   PVOID reserved,
   IF_INDEX interfaceIndex,
   IF_INDEX subInterfaceIndex
   );

typedef NTSTATUS (NTAPI * t_FwpsInjectNetworkSendAsync0)(
   HANDLE injectionHandle,
   HANDLE injectionContext,
   UINT32 flags,
   COMPARTMENT_ID compartmentId,
   NET_BUFFER_LIST* netBufferList,
   FWPS_INJECT_COMPLETE0 completionFn,
   HANDLE completionContext
   );

typedef NTSTATUS (NTAPI * t_FwpsInjectNetworkReceiveAsync0)(
   HANDLE injectionHandle,
   HANDLE injectionContext,
   UINT32 flags,
   COMPARTMENT_ID compartmentId,
   IF_INDEX interfaceIndex,
   IF_INDEX subInterfaceIndex,
   NET_BUFFER_LIST* netBufferList,
   FWPS_INJECT_COMPLETE0 completionFn,
   HANDLE completionContext
   );

typedef NTSTATUS (NTAPI * t_FwpsInjectTransportSendAsync0)(
   HANDLE injectionHandle,
   HANDLE injectionContext,
   UINT64 endpointHandle,
   UINT32 flags,
   FWPS_TRANSPORT_SEND_PARAMS0* sendArgs,
   ADDRESS_FAMILY addressFamily,
   COMPARTMENT_ID compartmentId,
   NET_BUFFER_LIST* netBufferList,
   FWPS_INJECT_COMPLETE0 completionFn,
   HANDLE completionContext
   );

typedef NTSTATUS (NTAPI * t_FwpsInjectTransportReceiveAsync0)(
   HANDLE injectionHandle,
   HANDLE injectionContext,
   PVOID reserved,
   UINT32 flags,
   ADDRESS_FAMILY addressFamily,
   COMPARTMENT_ID compartmentId,
   IF_INDEX interfaceIndex,
   IF_INDEX subInterfaceIndex,
   NET_BUFFER_LIST* netBufferList,
   FWPS_INJECT_COMPLETE0 completionFn,
   HANDLE completionContext
   );

typedef NTSTATUS (NTAPI * t_FwpsAcquireWritableLayerDataPointer0)(
   UINT64 classifyHandle,
   UINT64 filterId,   
   UINT32 flags,
   PVOID* writableLayerData,
   FWPS_CLASSIFY_OUT0* classifyOut
   );

typedef void (NTAPI * t_FwpsApplyModifiedLayerData0)(
   UINT64 classifyHandle,
   PVOID modifiedLayerData,
   UINT32 flags
   );   

typedef NTSTATUS (NTAPI * t_FwpsFlowAbort0)(
          UINT64 flowId
          );

typedef NTSTATUS (NTAPI * t_FwpsFlowAssociateContext0)(
   UINT64 flowId,
   UINT16 layerId,
   UINT32 calloutId,
   UINT64 flowContext
   );

typedef NTSTATUS (NTAPI * t_FwpsFlowRemoveContext0)(
   UINT64 flowId,
   UINT16 layerId,
   UINT32 calloutId
   );

typedef NTSTATUS (NTAPI * t_FwpsCloneStreamData0)(
   FWPS_STREAM_DATA0* calloutStreamData,
   NDIS_HANDLE netBufferListPoolHandle,
   NDIS_HANDLE netBufferPoolHandle,
   ULONG allocateCloneFlags,
   NET_BUFFER_LIST** netBufferListChain
   );

typedef void (NTAPI * t_FwpsDiscardClonedStreamData0)(
   NET_BUFFER_LIST* netBufferListChain,
   UINT32 allocateCloneFlags,
   BOOLEAN dispatchLevel
   );

typedef void (NTAPI * t_FwpsCompleteClassify0)(
   UINT64 classifyHandle,
   UINT32 flags,
   const FWPS_CLASSIFY_OUT0* classifyOut
   );

typedef void (NTAPI * t_FwpsRedirectHandleDestroy0)(HANDLE redirectHandle);

typedef void (NTAPI * t_FwpsReleaseClassifyHandle0)(
   UINT64 classifyHandle
   );

typedef FWPS_PACKET_INJECTION_STATE (NTAPI * t_FwpsQueryPacketInjectionState0)(
   HANDLE injectionHandle,
   const NET_BUFFER_LIST* netBufferList,
   HANDLE* injectionContext
   );

typedef NTSTATUS (NTAPI * t_FwpsPendClassify0)(
   UINT64 classifyHandle,
   UINT64 filterId,
   UINT32 flags,
   FWPS_CLASSIFY_OUT0* classifyOut
   );

typedef NTSTATUS (NTAPI * t_FwpsRedirectHandleCreate0)(
   const GUID* providerGuid,
   UINT32 flags,
   HANDLE* redirectHandle
   );

typedef NTSTATUS (NTAPI * t_FwpsAcquireClassifyHandle0)(
   void* classifyContext,
   UINT32 flags,
   UINT64* classifyHandle
   );

extern t_FwpmBfeStateGet0 pFwpmBfeStateGet0;
extern t_FwpmBfeStateSubscribeChanges0 pFwpmBfeStateSubscribeChanges0;
extern t_FwpmBfeStateUnsubscribeChanges0 pFwpmBfeStateUnsubscribeChanges0;
extern t_FwpsCalloutRegister1	pFwpsCalloutRegister1;
extern t_FwpsCalloutUnregisterByKey0 pFwpsCalloutUnregisterByKey0;
extern t_FwpmTransactionBegin0	pFwpmTransactionBegin0;
extern t_FwpmTransactionCommit0 pFwpmTransactionCommit0;
extern t_FwpmEngineClose0		pFwpmEngineClose0;
extern t_FwpmCalloutAdd0		pFwpmCalloutAdd0;
extern t_FwpmFilterAdd0			pFwpmFilterAdd0;
extern t_FwpmSubLayerCreateEnumHandle0 pFwpmSubLayerCreateEnumHandle0;
extern t_FwpmSubLayerEnum0		pFwpmSubLayerEnum0;
extern t_FwpmFreeMemory0		pFwpmFreeMemory0;
extern t_FwpmSubLayerDestroyEnumHandle0 pFwpmSubLayerDestroyEnumHandle0;
extern t_FwpmSubLayerAdd0		pFwpmSubLayerAdd0;
extern t_FwpmTransactionAbort0  pFwpmTransactionAbort0;
extern t_FwpmEngineOpen0		pFwpmEngineOpen0;
extern t_FwpmProviderAdd0		pFwpmProviderAdd0;
extern t_FwpmSubLayerDeleteByKey0	pFwpmSubLayerDeleteByKey0;
extern t_FwpmProviderContextDeleteByKey0 pFwpmProviderContextDeleteByKey0;
extern t_FwpsInjectionHandleCreate0	pFwpsInjectionHandleCreate0;
extern t_FwpsInjectionHandleDestroy0 pFwpsInjectionHandleDestroy0;
extern t_FwpsCopyStreamDataToBuffer0 pFwpsCopyStreamDataToBuffer0;
extern t_FwpsFreeCloneNetBufferList0 pFwpsFreeCloneNetBufferList0;
extern t_FwpsStreamInjectAsync0 pFwpsStreamInjectAsync0;
extern t_FwpsAllocateNetBufferAndNetBufferList0 pFwpsAllocateNetBufferAndNetBufferList0;
extern t_FwpsFreeNetBufferList0 pFwpsFreeNetBufferList0;
extern t_FwpsConstructIpHeaderForTransportPacket0 pFwpsConstructIpHeaderForTransportPacket0;
extern t_FwpsInjectNetworkSendAsync0 pFwpsInjectNetworkSendAsync0;
extern t_FwpsInjectNetworkReceiveAsync0 pFwpsInjectNetworkReceiveAsync0;
extern t_FwpsInjectTransportSendAsync0 pFwpsInjectTransportSendAsync0;
extern t_FwpsInjectTransportReceiveAsync0 pFwpsInjectTransportReceiveAsync0;
extern t_FwpsAcquireWritableLayerDataPointer0 pFwpsAcquireWritableLayerDataPointer0;
extern t_FwpsApplyModifiedLayerData0 pFwpsApplyModifiedLayerData0;
extern t_FwpsFlowAbort0 pFwpsFlowAbort0;
extern t_FwpsFlowAssociateContext0 pFwpsFlowAssociateContext0;
extern t_FwpsFlowRemoveContext0 pFwpsFlowRemoveContext0;
extern t_FwpsCloneStreamData0 pFwpsCloneStreamData0;
extern t_FwpsDiscardClonedStreamData0 pFwpsDiscardClonedStreamData0;
extern t_FwpsCompleteClassify0 pFwpsCompleteClassify0;
extern t_FwpsRedirectHandleDestroy0 pFwpsRedirectHandleDestroy0;
extern t_FwpsReleaseClassifyHandle0 pFwpsReleaseClassifyHandle0;
extern t_FwpsQueryPacketInjectionState0 pFwpsQueryPacketInjectionState0;
extern t_FwpsPendClassify0 pFwpsPendClassify0;
extern t_FwpsRedirectHandleCreate0 pFwpsRedirectHandleCreate0;
extern t_FwpsAcquireClassifyHandle0 pFwpsAcquireClassifyHandle0;

BOOLEAN
wfplink_init();

BOOLEAN
wfplink_checkMinimumWindowsVersion(int version);

#endif

