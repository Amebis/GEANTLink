/*
    Copyright 2015-2016 Amebis
    Copyright 2016 GÉANT

    This file is part of GEANTLink.

    GEANTLink is free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    GEANTLink is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with GEANTLink. If not, see <http://www.gnu.org/licenses/>.
*/

#include <WinStd/ETW.h>
#include <WinStd/Win.h>

#include <eaptypes.h>
extern "C" {
#include <eapmethodpeerapis.h>
}

#include <vector>

#include <EAPMethodETW.h>


namespace eap
{
    class session_base;
    class eap_module_base;
    template<class Ts> class peer;
    class peer_ui_base;
};

#pragma once


#define ETW_ERROR(kw, f, ...)   m_ep.write(TRACE_LEVEL_ERROR      , kw, _T(__FUNCTION__) _T(" ") f, ##__VA_ARGS__)
#define ETW_WARNING(kw, f, ...) m_ep.write(TRACE_LEVEL_WARNING    , kw, _T(__FUNCTION__) _T(" ") f, ##__VA_ARGS__)
#define ETW_INFO(kw, f, ...)    m_ep.write(TRACE_LEVEL_INFORMATION, kw, _T(__FUNCTION__) _T(" ") f, ##__VA_ARGS__)
#define ETW_VERBOSE(kw, f, ...) m_ep.write(TRACE_LEVEL_VERBOSE    , kw, _T(__FUNCTION__) _T(" ") f, ##__VA_ARGS__)
#define ETW_FN_VOID             winstd::event_fn_auto    <         &EAPMETHOD_TRACE_EVT_FN_CALL, &EAPMETHOD_TRACE_EVT_FN_RETURN        > _event_auto(m_ep, __FUNCTION__)
#define ETW_FN_DWORD(res)       winstd::event_fn_auto_ret<DWORD  , &EAPMETHOD_TRACE_EVT_FN_CALL, &EAPMETHOD_TRACE_EVT_FN_RETURN_DWORD  > _event_auto(m_ep, __FUNCTION__, res)
#define ETW_FN_HRESULT(res)     winstd::event_fn_auto_ret<HRESULT, &EAPMETHOD_TRACE_EVT_FN_CALL, &EAPMETHOD_TRACE_EVT_FN_RETURN_HRESULT> _event_auto(m_ep, __FUNCTION__, res)


namespace eap
{
    ///
    /// EAP session
    ///
    class session_base
    {
    public:
        ///
        /// Constructor
        ///
        session_base();

        ///
        /// Starts an EAP authentication session on the peer EAPHost using the EAP method.
        ///
        /// \sa [EapPeerBeginSession function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363600.aspx)
        ///
        virtual DWORD begin(_In_ DWORD dwFlags, _In_ const EapAttributes *pAttributeArray, _In_ HANDLE hTokenImpersonateUser, _In_ DWORD dwSizeofConnectionData, _In_count_(dwSizeofConnectionData) BYTE *pConnectionData, _In_ DWORD dwSizeofUserData, _In_count_(dwSizeofUserData) BYTE *pUserData, _In_ DWORD dwMaxSendPacketSize, _Out_ EAP_ERROR **ppEapError);

        ///
        /// Ends an EAP authentication session for the EAP method.
        ///
        /// \sa [EapPeerEndSession function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363604.aspx)
        ///
        virtual DWORD end(_Out_ EAP_ERROR **ppEapError);

        ///
        /// Processes a packet received by EAPHost from a supplicant.
        ///
        /// \sa [EapPeerProcessRequestPacket function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363621.aspx)
        ///
        virtual DWORD process_request_packet(_In_ DWORD dwSizeofReceivePacket, _In_bytecount_(dwSizeofReceivePacket) EapPacket *pReceivePacket, _Out_ EapPeerMethodOutput *pEapOutput, _Out_ EAP_ERROR **ppEapError);

        ///
        /// Obtains a response packet from the EAP method.
        ///
        /// \sa [EapPeerGetResponsePacket function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363610.aspx)
        ///
        virtual DWORD get_response_packet(_Inout_ DWORD *pcbSendPacket, _Out_cap_(*pcbSendPacket) EapPacket *pSendPacket, _Out_ EAP_ERROR **ppEapError);

        ///
        /// Obtains the result of an authentication session from the EAP method.
        ///
        /// \sa [EapPeerGetResult function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363611.aspx)
        ///
        virtual DWORD get_result(_In_ EapPeerMethodResultReason reason, _Out_ EapPeerMethodResult *ppResult, _Out_ EAP_ERROR **ppEapError);

        ///
        /// Obtains the user interface context from the EAP method.
        ///
        /// \note This function is always followed by the `EapPeerInvokeInteractiveUI()` function, which is followed by the `EapPeerSetUIContext()` function.
        ///
        /// \sa [EapPeerGetUIContext function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363612.aspx)
        ///
        virtual DWORD get_ui_context(_Out_ DWORD *dwSizeOfUIContextData, _Out_cap_(*dwSizeOfUIContextData) BYTE **pUIContextData, _Out_ EAP_ERROR **ppEapError);

        ///
        /// Provides a user interface context to the EAP method.
        ///
        /// \note This function is called after the UI has been raised through the `EapPeerGetUIContext()` function.
        ///
        /// \sa [EapPeerSetUIContext function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363626.aspx)
        ///
        virtual DWORD set_ui_context(_In_ DWORD dwSizeOfUIContextData, _In_count_(dwSizeOfUIContextData) const BYTE *pUIContextData, _Out_ EapPeerMethodOutput *pEapOutput, _Out_ EAP_ERROR **ppEapError);

        ///
        /// Obtains an array of EAP response attributes from the EAP method.
        ///
        /// \sa [EapPeerGetResponseAttributes function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363609.aspx)
        ///
        virtual DWORD get_response_attributes(_Out_ EapAttributes *pAttribs, _Out_ EAP_ERROR **ppEapError);

        ///
        /// Provides an updated array of EAP response attributes to the EAP method.
        ///
        /// \sa [EapPeerSetResponseAttributes function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363625.aspx)
        ///
        virtual DWORD set_response_attributes(_In_ EapAttributes *pAttribs, _Out_ EapPeerMethodOutput *pEapOutput, _Out_ EAP_ERROR **ppEapError);
    };


    ///
    /// EAP module base class
    ///
    class eap_module_base
    {
    public:
        inline DWORD create()
        {
            m_ep.create(&EAPMETHOD_TRACE_EVENT_PROVIDER);
            m_ep.write(&EAPMETHOD_TRACE_EVT_MODULE_LOAD, winstd::event_data((BYTE)EAPMETHOD_TYPE), winstd::event_data::blank);

            if (!m_heap.create(0, 0, 0))
                return ERROR_OUTOFMEMORY;

            return ERROR_SUCCESS;
        }


        virtual ~eap_module_base()
        {
            m_ep.write(&EAPMETHOD_TRACE_EVT_MODULE_UNLOAD, winstd::event_data((BYTE)EAPMETHOD_TYPE), winstd::event_data::blank);
        }


        ///
        /// Allocate a EAP_ERROR and fill it according to dwErrorCode
        ///
        EAP_ERROR *make_error(_In_ DWORD dwErrorCode, _In_ DWORD dwReasonCode, _In_ LPCGUID pRootCauseGuid, _In_ LPCGUID pRepairGuid, _In_ LPCGUID pHelpLinkGuid, _In_z_ LPCWSTR pszRootCauseString, _In_z_ LPCWSTR pszRepairString) const
        {
            // Calculate memory size requirement.
            SIZE_T
                nRootCauseSize    = pszRootCauseString != NULL && pszRootCauseString[0] ? (wcslen(pszRootCauseString) + 1)*sizeof(WCHAR) : 0,
                nRepairStringSize = pszRepairString    != NULL && pszRepairString   [0] ? (wcslen(pszRepairString   ) + 1)*sizeof(WCHAR) : 0,
                nEapErrorSize = sizeof(EAP_ERROR) + nRootCauseSize + nRepairStringSize;

            EAP_ERROR *pError = (EAP_ERROR*)HeapAlloc(m_heap, 0, nEapErrorSize);
            if (!pError)
                return NULL;
            BYTE *p = (BYTE*)(pError + 1);

            // Fill the error descriptor.
            pError->dwWinError                = dwErrorCode;
            pError->type.eapType.type         = EAPMETHOD_TYPE;
            pError->type.eapType.dwVendorId   = 0;
            pError->type.eapType.dwVendorType = 0;
            pError->type.dwAuthorId           = 67532;
            pError->dwReasonCode              = dwReasonCode;
            pError->rootCauseGuid             = pRootCauseGuid != NULL ? *pRootCauseGuid : GUID_NULL;
            pError->repairGuid                = pRepairGuid    != NULL ? *pRepairGuid    : GUID_NULL;
            pError->helpLinkGuid              = pHelpLinkGuid  != NULL ? *pHelpLinkGuid  : GUID_NULL;
            if (nRootCauseSize) {
                pError->pRootCauseString = (LPWSTR)p;
                memcpy(pError->pRootCauseString, pszRootCauseString, nRootCauseSize);
                p += nRootCauseSize;
            } else
                pError->pRootCauseString = NULL;
            if (nRepairStringSize) {
                pError->pRepairString = (LPWSTR)p;
                memcpy(pError->pRepairString, pszRepairString, nRepairStringSize);
                p += nRepairStringSize;
            } else
                pError->pRepairString = NULL;

            // Write trace event.
            std::vector<EVENT_DATA_DESCRIPTOR> evt_desc;
            evt_desc.reserve(8);
            evt_desc.push_back(winstd::event_data(pError->dwWinError));
            evt_desc.push_back(winstd::event_data(pError->type.eapType.type));
            evt_desc.push_back(winstd::event_data(pError->dwReasonCode));
            evt_desc.push_back(winstd::event_data(&(pError->rootCauseGuid), sizeof(GUID)));
            evt_desc.push_back(winstd::event_data(&(pError->repairGuid), sizeof(GUID)));
            evt_desc.push_back(winstd::event_data(&(pError->helpLinkGuid), sizeof(GUID)));
            evt_desc.push_back(winstd::event_data(pError->pRootCauseString));
            evt_desc.push_back(winstd::event_data(pError->pRepairString));
            m_ep.write(&EAPMETHOD_TRACE_EAP_ERROR, (ULONG)evt_desc.size(), evt_desc.data());

            return pError;
        }


        ///
        /// Free BLOB allocated with this peer
        ///
        inline void free_memory(_In_ void *ptr)
        {
            ETW_FN_VOID;

            if (ptr) {
                // Since we do security here and some of the BLOBs contain credentials, sanitize every memory block before freeing.
                SecureZeroMemory(ptr, HeapSize(m_heap, 0, ptr));
                HeapFree(m_heap, 0, ptr);
            }
        }


        ///
        /// Free EAP_ERROR allocated with `make_error()` method
        ///
        void free_error_memory(_In_ EAP_ERROR *err)
        {
            ETW_FN_VOID;

            if (err) {
                // pRootCauseString and pRepairString always trail the ppEapError to reduce number of (de)allocations.
                HeapFree(m_heap, 0, err);
            }
        }


    protected:
        winstd::heap m_heap;                    ///< Heap
        mutable winstd::event_provider m_ep;    ///< Event Provider
    };


    ///
    /// EAP peer base class
    ///
    template<class Ts>
    class peer : public eap_module_base
    {
    public:
        ///
        /// Obtains a set of function pointers for an implementation of the EAP peer method currently loaded on the EAPHost service
        ///
        /// \sa [EapPeerGetInfo function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363608.aspx)
        ///
        inline void get_info(_Out_ EAP_PEER_METHOD_ROUTINES *pEapPeerMethodRoutines) const
        {
            ETW_FN_VOID;

            assert(pEapPeerMethodRoutines);

            pEapPeerMethodRoutines->dwVersion                    = PRODUCT_VERSION;
            pEapPeerMethodRoutines->pEapType                     = NULL;

            pEapPeerMethodRoutines->EapPeerInitialize            = initialize;
            pEapPeerMethodRoutines->EapPeerShutdown              = shutdown;
            pEapPeerMethodRoutines->EapPeerBeginSession          = begin_session;
            pEapPeerMethodRoutines->EapPeerEndSession            = end_session;
            pEapPeerMethodRoutines->EapPeerSetCredentials        = NULL;    // Always NULL unless we want to use generic credential UI
            pEapPeerMethodRoutines->EapPeerGetIdentity           = get_identity;
            pEapPeerMethodRoutines->EapPeerProcessRequestPacket  = process_request_packet;
            pEapPeerMethodRoutines->EapPeerGetResponsePacket     = get_response_packet;
            pEapPeerMethodRoutines->EapPeerGetResult             = get_result;
            pEapPeerMethodRoutines->EapPeerGetUIContext          = get_ui_context;
            pEapPeerMethodRoutines->EapPeerSetUIContext          = set_ui_context;
            pEapPeerMethodRoutines->EapPeerGetResponseAttributes = get_response_attributes;
            pEapPeerMethodRoutines->EapPeerSetResponseAttributes = set_response_attributes;
        }

    protected:
        ///
        /// Initializes an EAP peer method for EAPHost.
        ///
        /// \sa [EapPeerGetInfo function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363613.aspx)
        ///
        static DWORD APIENTRY initialize(_Out_ EAP_ERROR **ppEapError)
        {
            UNREFERENCED_PARAMETER(ppEapError);
            return ERROR_SUCCESS;
        }


        ///
        /// Shuts down the EAP method and prepares to unload its corresponding DLL.
        ///
        /// \sa [EapPeerShutdown function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363627.aspx)
        ///
        static DWORD APIENTRY shutdown(_Out_ EAP_ERROR **ppEapError)
        {
            UNREFERENCED_PARAMETER(ppEapError);
            return ERROR_SUCCESS;
        }


        ///
        /// Returns the user data and user identity after being called by EAPHost.
        ///
        /// \sa [EapPeerGetIdentity function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363607.aspx)
        ///
        static DWORD APIENTRY get_identity(_In_ DWORD dwFlags, _In_ DWORD dwSizeofConnectionData, _In_count_(dwSizeofConnectionData) const BYTE *pConnectionData, _In_ DWORD dwSizeofUserData, _In_count_(dwSizeofUserData) const BYTE *pUserData, _In_ HANDLE hTokenImpersonateUser, _Out_ BOOL *pfInvokeUI, _Inout_ DWORD *pdwSizeOfUserDataOut, _Out_cap_(*pdwSizeOfUserDataOut) BYTE **ppUserDataOut, _Out_ WCHAR **ppwszIdentity, _Out_ EAP_ERROR **ppEapError)
        {
            UNREFERENCED_PARAMETER(dwFlags);
            UNREFERENCED_PARAMETER(dwSizeofConnectionData);
            UNREFERENCED_PARAMETER(pConnectionData);
            UNREFERENCED_PARAMETER(dwSizeofUserData);
            UNREFERENCED_PARAMETER(pUserData);
            UNREFERENCED_PARAMETER(hTokenImpersonateUser);
            UNREFERENCED_PARAMETER(pfInvokeUI);
            UNREFERENCED_PARAMETER(pdwSizeOfUserDataOut);
            UNREFERENCED_PARAMETER(ppUserDataOut);
            UNREFERENCED_PARAMETER(ppwszIdentity);
            UNREFERENCED_PARAMETER(ppEapError);

            return ERROR_NOT_SUPPORTED;
        }


        ///
        /// Starts an EAP authentication session on the peer EAPHost using the EAP method.
        ///
        /// \sa [EapPeerBeginSession function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363600.aspx)
        ///
        static DWORD APIENTRY begin_session(_In_ DWORD dwFlags, _In_ const EapAttributes *pAttributeArray, _In_ HANDLE hTokenImpersonateUser, _In_ DWORD dwSizeofConnectionData, _In_count_(dwSizeofConnectionData) BYTE *pConnectionData, _In_ DWORD dwSizeofUserData, _In_count_(dwSizeofUserData) BYTE *pUserData, _In_ DWORD dwMaxSendPacketSize, _Out_ EAP_SESSION_HANDLE *phSession, _Out_ EAP_ERROR **ppEapError)
        {
            // Allocate new session.
            Ts *session = new Ts();
            if (!session)
                return ERROR_OUTOFMEMORY;

            // Begin the session.
            DWORD dwResult = session->begin(dwFlags, pAttributeArray, hTokenImpersonateUser, dwSizeofConnectionData, pConnectionData, dwSizeofUserData, pUserData, dwMaxSendPacketSize, ppEapError);
            if (dwResult == ERROR_SUCCESS) {
                assert(phSession);
                *phSession = session;
                return ERROR_SUCCESS;
            }

            // Cleanup.
            delete session;
            return dwResult;
        }


        ///
        /// Ends an EAP authentication session for the EAP method.
        ///
        /// \sa [EapPeerEndSession function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363604.aspx)
        ///
        static DWORD APIENTRY end_session(_In_ EAP_SESSION_HANDLE hSession, _Out_ EAP_ERROR **ppEapError)
        {
            assert(hSession);

            DWORD dwResult = static_cast<Ts*>(hSession)->end(ppEapError);
            delete static_cast<Ts*>(hSession);

            return dwResult;
        }


        ///
        /// Processes a packet received by EAPHost from a supplicant.
        ///
        /// \sa [EapPeerProcessRequestPacket function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363621.aspx)
        ///
        static DWORD APIENTRY process_request_packet(_In_ EAP_SESSION_HANDLE hSession, _In_ DWORD dwSizeofReceivePacket, _In_bytecount_(dwSizeofReceivePacket) EapPacket *pReceivePacket, _Out_ EapPeerMethodOutput *pEapOutput, _Out_ EAP_ERROR **ppEapError)
        {
            assert(hSession);
            return static_cast<Ts*>(hSession)->process_request_packet(dwSizeofReceivePacket, pReceivePacket, pEapOutput, ppEapError);
        }


        ///
        /// Obtains a response packet from the EAP method.
        ///
        /// \sa [EapPeerGetResponsePacket function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363610.aspx)
        ///
        static DWORD APIENTRY get_response_packet(_In_ EAP_SESSION_HANDLE hSession, _Inout_ DWORD *pcbSendPacket, _Out_cap_(*pcbSendPacket) EapPacket *pSendPacket, _Out_ EAP_ERROR **ppEapError)
        {
            assert(hSession);
            return static_cast<Ts*>(hSession)->get_response_packet(pcbSendPacket, pSendPacket, ppEapError);
        }


        ///
        /// Obtains the result of an authentication session from the EAP method.
        ///
        /// \sa [EapPeerGetResult function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363611.aspx)
        ///
        static DWORD APIENTRY get_result(_In_ EAP_SESSION_HANDLE hSession, _In_ EapPeerMethodResultReason reason, _Out_ EapPeerMethodResult *ppResult, _Out_ EAP_ERROR **ppEapError)
        {
            assert(hSession);
            return static_cast<Ts*>(hSession)->get_result(reason, ppResult, ppEapError);
        }


        ///
        /// Obtains the user interface context from the EAP method.
        ///
        /// \note This function is always followed by the `EapPeerInvokeInteractiveUI()` function, which is followed by the `EapPeerSetUIContext()` function.
        ///
        /// \sa [EapPeerGetUIContext function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363612.aspx)
        ///
        static DWORD APIENTRY get_ui_context(_In_ EAP_SESSION_HANDLE hSession, _Out_ DWORD *dwSizeOfUIContextData, _Out_cap_(*dwSizeOfUIContextData) BYTE **pUIContextData, _Out_ EAP_ERROR **ppEapError)
        {
            assert(hSession);
            return static_cast<Ts*>(hSession)->get_ui_context(dwSizeOfUIContextData, pUIContextData, ppEapError);
        }


        ///
        /// Provides a user interface context to the EAP method.
        ///
        /// \note This function is called after the UI has been raised through the `EapPeerGetUIContext()` function.
        ///
        /// \sa [EapPeerSetUIContext function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363626.aspx)
        ///
        static DWORD APIENTRY set_ui_context(_In_ EAP_SESSION_HANDLE hSession, _In_ DWORD dwSizeOfUIContextData, _In_count_(dwSizeOfUIContextData) const BYTE *pUIContextData, _Out_ EapPeerMethodOutput *pEapOutput, _Out_ EAP_ERROR **ppEapError)
        {
            assert(hSession);
            return static_cast<Ts*>(hSession)->set_ui_context(dwSizeOfUIContextData, pUIContextData, pEapOutput, ppEapError);
        }


        ///
        /// Obtains an array of EAP response attributes from the EAP method.
        ///
        /// \sa [EapPeerGetResponseAttributes function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363609.aspx)
        ///
        static DWORD APIENTRY get_response_attributes(_In_ EAP_SESSION_HANDLE hSession, _Out_ EapAttributes *pAttribs, _Out_ EAP_ERROR **ppEapError)
        {
            assert(hSession);
            return static_cast<Ts*>(hSession)->get_response_attributes(pAttribs, ppEapError);
        }


        ///
        /// Provides an updated array of EAP response attributes to the EAP method.
        ///
        /// \sa [EapPeerSetResponseAttributes function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363625.aspx)
        ///
        static DWORD APIENTRY set_response_attributes(_In_ EAP_SESSION_HANDLE hSession, _In_ EapAttributes *pAttribs, _Out_ EapPeerMethodOutput *pEapOutput, _Out_ EAP_ERROR **ppEapError)
        {
            assert(hSession);
            return static_cast<Ts*>(hSession)->set_response_attributes(pAttribs, pEapOutput, ppEapError);
        }
    };


    ///
    /// EAP peer UI base class
    ///
    class peer_ui_base : public eap_module_base
    {
    public:
        ///
        /// Constructor
        ///
        peer_ui_base();

        ///
        /// Raises the EAP method's specific connection configuration user interface dialog on the client.
        ///
        /// \sa [EapPeerInvokeConfigUI function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363614.aspx)
        ///
        virtual DWORD invoke_config_ui(
            _In_                                 const EAP_METHOD_TYPE *pEapType,
            _In_                                       HWND            hwndParent,
            _In_                                       DWORD           dwFlags,
            _In_                                       DWORD           dwSizeOfConnectionDataIn,
            _In_count_(dwSizeOfConnectionDataIn) const BYTE            *pConnectionDataIn,
            _Out_                                      DWORD           *pdwSizeOfConnectionDataOut,
            _Out_                                      BYTE            **ppConnectionDataOut,
            _Out_                                      EAP_ERROR       **ppEapError) = 0;

        ///
        /// Raises a custom interactive user interface dialog to obtain user identity information for the EAP method on the client.
        ///
        /// \sa [EapPeerInvokeIdentityUI function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363615.aspx)
        ///
        virtual DWORD invoke_identity_ui(
            _In_                               const EAP_METHOD_TYPE *pEapType,
            _In_                                     DWORD           dwFlags,
            _In_                                     HWND            hwndParent,
            _In_                                     DWORD           dwSizeOfConnectionData,
            _In_count_(dwSizeOfConnectionData) const BYTE            *pConnectionData,
            _In_                                     DWORD           dwSizeOfUserData,
            _In_count_(dwSizeOfUserData)       const BYTE            *pUserData,
            _Out_                                    DWORD           *pdwSizeOfUserDataOut,
            _Out_                                    BYTE            **ppUserDataOut,
            _Out_                                    LPWSTR          *ppwszIdentity,
            _Out_                                    EAP_ERROR       **ppEapError) = 0;

        ///
        /// Raises a custom interactive user interface dialog for the EAP method on the client.
        ///
        /// \sa [EapPeerInvokeInteractiveUI function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363616.aspx)
        ///
        virtual DWORD invoke_interactive_ui(
            _In_                              const EAP_METHOD_TYPE *pEapType,
            _In_                                    HWND            hwndParent,
            _In_                                    DWORD           dwSizeofUIContextData,
            _In_count_(dwSizeofUIContextData) const BYTE            *pUIContextData,
            _Out_                                   DWORD           *pdwSizeOfDataFromInteractiveUI,
            _Out_                                   BYTE            **ppDataFromInteractiveUI,
            _Out_                                   EAP_ERROR       **ppEapError) = 0;
    };
};
