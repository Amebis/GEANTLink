/*
    Copyright 2015-2020 Amebis
    Copyright 2016 GÉANT

    This file is part of GÉANTLink.

    GÉANTLink is free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    GÉANTLink is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with GÉANTLink. If not, see <http://www.gnu.org/licenses/>.
*/

#include <StdAfx.h>

using namespace std;
using namespace winstd;

#pragma comment(lib, "Ws2_32.lib")

#if EAPMETHOD_TYPE==21
#define _EAPMETHOD_PEER    eap::peer_ttls
#else
#error Unknown EAP Method type.
#endif

_EAPMETHOD_PEER g_peer;


///
/// DLL main entry point
///
/// \sa [DllMain entry point](https://msdn.microsoft.com/en-us/library/windows/desktop/ms682583.aspx)
///
BOOL WINAPI DllMain(_In_ HINSTANCE hinstDLL, _In_ DWORD fdwReason, _In_ LPVOID lpvReserved)
{
    UNREFERENCED_PARAMETER(lpvReserved);

    if (fdwReason == DLL_PROCESS_ATTACH) {
#ifdef _DEBUG
        //Sleep(10000);
#endif
        g_peer.m_instance = hinstDLL;
    } else if (fdwReason == DLL_PROCESS_DETACH)
        assert(!_CrtDumpMemoryLeaks());

    return TRUE;
}


///
/// Releases all memory associated with an opaque user interface context data buffer.
///
/// \sa [EapPeerFreeMemory function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363606.aspx)
///
_Use_decl_annotations_
VOID WINAPI EapPeerFreeMemory(void *pUIContextData)
{
    event_fn_auto event_auto(g_peer.get_event_fn_auto(__FUNCTION__));

    if (pUIContextData)
        g_peer.free_memory((BYTE*)pUIContextData);
}


///
/// Releases error-specific memory allocated by the EAP peer method.
///
/// \sa [EapPeerFreeErrorMemory function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363605.aspx)
///
_Use_decl_annotations_
VOID WINAPI EapPeerFreeErrorMemory(EAP_ERROR *ppEapError)
{
    event_fn_auto event_auto(g_peer.get_event_fn_auto(__FUNCTION__));

    if (ppEapError)
        g_peer.free_error_memory(ppEapError);
}


///
/// Obtains a set of function pointers for an implementation of the EAP peer method currently loaded on the EapHost service.
///
/// \sa [EapPeerGetInfo function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363608.aspx)
///
_Use_decl_annotations_
DWORD WINAPI EapPeerGetInfo(EAP_TYPE* pEapType, EAP_PEER_METHOD_ROUTINES* pEapPeerMethodRoutines, EAP_ERROR **ppEapError)
{
    DWORD dwResult = ERROR_SUCCESS;
    event_fn_auto_ret<DWORD> event_auto(g_peer.get_event_fn_auto(__FUNCTION__, dwResult));
#ifdef _DEBUG
    //Sleep(10000);
#endif

    // Initialize output parameters.
    if (pEapPeerMethodRoutines)
        memset(pEapPeerMethodRoutines, 0, sizeof(*pEapPeerMethodRoutines));
    if (ppEapError)
        *ppEapError = NULL;

    // Parameter check
    if (!pEapType || !pEapPeerMethodRoutines)
        return dwResult = ERROR_INVALID_PARAMETER;
    if (pEapType->type != EAPMETHOD_TYPE)
        return dwResult = ERROR_NOT_SUPPORTED;

    pEapPeerMethodRoutines->dwVersion                    = PRODUCT_VERSION;
    pEapPeerMethodRoutines->pEapType                     = NULL;

    pEapPeerMethodRoutines->EapPeerInitialize            = EapPeerInitialize;
    pEapPeerMethodRoutines->EapPeerShutdown              = EapPeerShutdown;
    pEapPeerMethodRoutines->EapPeerBeginSession          = EapPeerBeginSession;
    pEapPeerMethodRoutines->EapPeerEndSession            = EapPeerEndSession;
    pEapPeerMethodRoutines->EapPeerSetCredentials        = NULL;    // Always NULL unless we want to use generic credential UI
    pEapPeerMethodRoutines->EapPeerGetIdentity           = EapPeerGetIdentity;
    pEapPeerMethodRoutines->EapPeerProcessRequestPacket  = EapPeerProcessRequestPacket;
    pEapPeerMethodRoutines->EapPeerGetResponsePacket     = EapPeerGetResponsePacket;
    pEapPeerMethodRoutines->EapPeerGetResult             = EapPeerGetResult;
    pEapPeerMethodRoutines->EapPeerGetUIContext          = EapPeerGetUIContext;
    pEapPeerMethodRoutines->EapPeerSetUIContext          = EapPeerSetUIContext;
    pEapPeerMethodRoutines->EapPeerGetResponseAttributes = EapPeerGetResponseAttributes;
    pEapPeerMethodRoutines->EapPeerSetResponseAttributes = EapPeerSetResponseAttributes;

    return dwResult;
}


#pragma warning(push)
#pragma warning(disable: 4702) // Compiler is smart enough to find out the initialize() method is empty => never throws an exception.

///
/// Initializes an EAP peer method for EapHost.
///
/// \sa [EapPeerInitialize function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363613.aspx)
///
//_Use_decl_annotations_
DWORD APIENTRY EapPeerInitialize(EAP_ERROR **ppEapError)
{
    DWORD dwResult = ERROR_SUCCESS;
    event_fn_auto_ret<DWORD> event_auto(g_peer.get_event_fn_auto(__FUNCTION__, dwResult));
#ifdef _DEBUG
    //Sleep(10000);
#endif

    // Initialize output parameters.
    if (ppEapError)
        *ppEapError = NULL;

    try {
        g_peer.initialize();
    } catch (std::exception &err) {
        dwResult = g_peer.log_error(ppEapError, err);
    } catch (...) {
        dwResult = ERROR_INVALID_DATA;
    }

    return dwResult;
}

#pragma warning(pop)


#pragma warning(push)
#pragma warning(disable: 4702) // Compiler is smart enough to find out the shutdown() method is empty => never throws an exception.

///
/// Shuts down the EAP method and prepares to unload its corresponding DLL.
///
/// \sa [EapPeerShutdown function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363627.aspx)
///
//_Use_decl_annotations_
DWORD APIENTRY EapPeerShutdown(EAP_ERROR **ppEapError)
{
    DWORD dwResult = ERROR_SUCCESS;
    event_fn_auto_ret<DWORD> event_auto(g_peer.get_event_fn_auto(__FUNCTION__, dwResult));
#ifdef _DEBUG
    //Sleep(10000);
#endif

    // Initialize output parameters.
    if (ppEapError)
        *ppEapError = NULL;

    try {
        g_peer.shutdown();
    } catch (std::exception &err) {
        dwResult = g_peer.log_error(ppEapError, err);
    } catch (...) {
        dwResult = ERROR_INVALID_DATA;
    }

    return dwResult;
}

#pragma warning(pop)


///
/// Returns the user data and user identity after being called by EapHost.
///
/// \sa [EapPeerGetIdentity function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363607.aspx)
///
_Use_decl_annotations_
DWORD APIENTRY EapPeerGetIdentity(
          DWORD     dwFlags,
          DWORD     dwConnectionDataSize,
    const BYTE      *pConnectionData,
          DWORD     dwUserDataSize,
    const BYTE      *pUserData,
          HANDLE    hTokenImpersonateUser,
          BOOL      *pfInvokeUI,
          DWORD     *pdwUserDataOutSize,
          BYTE      **ppUserDataOut,
          WCHAR     **ppwszIdentity,
          EAP_ERROR **ppEapError)
{
    DWORD dwResult = ERROR_SUCCESS;
    event_fn_auto_ret<DWORD> event_auto(g_peer.get_event_fn_auto(__FUNCTION__, dwResult));
#ifdef _DEBUG
    //Sleep(10000);
#endif

    // Initialize output parameters.
    if (pfInvokeUI)
        *pfInvokeUI = FALSE;
    if (pdwUserDataOutSize)
        *pdwUserDataOutSize = 0;
    if (ppUserDataOut)
        *ppUserDataOut = NULL;
    if (ppwszIdentity)
        *ppwszIdentity = NULL;
    if (ppEapError)
        *ppEapError = NULL;

    // Parameter check
    if (!pConnectionData && dwConnectionDataSize || !pUserData && dwUserDataSize || !pfInvokeUI || !pdwUserDataOutSize || !ppUserDataOut || !ppwszIdentity)
        return dwResult = ERROR_INVALID_PARAMETER;

    try {
        g_peer.get_identity(dwFlags, pConnectionData, dwConnectionDataSize, pUserData, dwUserDataSize, ppUserDataOut, pdwUserDataOutSize, hTokenImpersonateUser, pfInvokeUI, ppwszIdentity);
    } catch (std::exception &err) {
        dwResult = g_peer.log_error(ppEapError, err);
    } catch (...) {
        dwResult = ERROR_INVALID_DATA;
    }

    return dwResult;
}


///
/// Starts an EAP authentication session on the peer EapHost using the EAP method.
///
/// \sa [EapPeerBeginSession function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363600.aspx)
///
//_Use_decl_annotations_
DWORD APIENTRY EapPeerBeginSession(
              DWORD              dwFlags,
      const   EapAttributes      *pAttributeArray,
              HANDLE             hTokenImpersonateUser,
              DWORD              dwConnectionDataSize,
    /*const*/ BYTE               *pConnectionData,
              DWORD              dwUserDataSize,
    /*const*/ BYTE               *pUserData,
              DWORD              dwMaxSendPacketSize,
              EAP_SESSION_HANDLE *phSession,
              EAP_ERROR          **ppEapError)
{
    DWORD dwResult = ERROR_SUCCESS;
    event_fn_auto_ret<DWORD> event_auto(g_peer.get_event_fn_auto(__FUNCTION__, dwResult));
#ifdef _DEBUG
    //Sleep(10000);
#endif

    // Initialize output parameters.
    if (phSession)
        *phSession = NULL;
    if (ppEapError)
        *ppEapError = NULL;

    // Parameter check
    if (!pConnectionData && dwConnectionDataSize || !pUserData && dwUserDataSize || !phSession)
        return dwResult = ERROR_INVALID_PARAMETER;

    try {
        *phSession = g_peer.begin_session(dwFlags, pAttributeArray, hTokenImpersonateUser, pConnectionData, dwConnectionDataSize, pUserData, dwUserDataSize, dwMaxSendPacketSize);
    } catch (std::exception &err) {
        dwResult = g_peer.log_error(ppEapError, err);
    } catch (...) {
        dwResult = ERROR_INVALID_DATA;
    }

    return dwResult;
}


///
/// Ends an EAP authentication session for the EAP method.
///
/// \sa [EapPeerEndSession function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363604.aspx)
///
//_Use_decl_annotations_
DWORD APIENTRY EapPeerEndSession(
    EAP_SESSION_HANDLE hSession,
    EAP_ERROR          **ppEapError)
{
    DWORD dwResult = ERROR_SUCCESS;
    event_fn_auto_ret<DWORD> event_auto(g_peer.get_event_fn_auto(__FUNCTION__, dwResult));
#ifdef _DEBUG
    //Sleep(10000);
#endif

    // Initialize output parameters.
    if (ppEapError)
        *ppEapError = NULL;

    // Parameter check
    if (!hSession)
        return dwResult = ERROR_INVALID_PARAMETER;

    try {
        g_peer.end_session(hSession);
    } catch (std::exception &err) {
        dwResult = g_peer.log_error(ppEapError, err);
    } catch (...) {
        dwResult = ERROR_INVALID_DATA;
    }

    return dwResult;
}


///
/// Processes a packet received by EapHost from a supplicant.
///
/// \sa [EapPeerProcessRequestPacket function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363621.aspx)
///
//_Use_decl_annotations_
DWORD APIENTRY EapPeerProcessRequestPacket(
              EAP_SESSION_HANDLE  hSession,
              DWORD               dwReceivedPacketSize,
    /*const*/ EapPacket           *pReceivedPacket,
              EapPeerMethodOutput *pEapOutput,
              EAP_ERROR           **ppEapError)
{
    DWORD dwResult = ERROR_SUCCESS;
    event_fn_auto_ret<DWORD> event_auto(g_peer.get_event_fn_auto(__FUNCTION__, dwResult));
#ifdef _DEBUG
    //Sleep(10000);
#endif

    // Initialize output parameters.
    if (pEapOutput)
        memset(pEapOutput, 0, sizeof(*pEapOutput));
    if (ppEapError)
        *ppEapError = NULL;

    // Parameter check
    if (!hSession || !pReceivedPacket || dwReceivedPacketSize < 6 || pReceivedPacket->Data[0] != EAPMETHOD_TYPE || !pEapOutput)
        return dwResult = ERROR_INVALID_PARAMETER;

    try {
        g_peer.process_request_packet(hSession, pReceivedPacket, dwReceivedPacketSize, pEapOutput);
    } catch (std::exception &err) {
        dwResult = g_peer.log_error(ppEapError, err);
    } catch (...) {
        dwResult = ERROR_INVALID_DATA;
    }

    return dwResult;
}


///
/// Obtains a response packet from the EAP method.
///
/// \sa [EapPeerGetResponsePacket function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363610.aspx)
///
//_Use_decl_annotations_
DWORD APIENTRY EapPeerGetResponsePacket(
    EAP_SESSION_HANDLE hSession,
    DWORD              *pdwSendPacketSize,
    EapPacket          *pSendPacket,
    EAP_ERROR          **ppEapError)
{
    DWORD dwResult = ERROR_SUCCESS;
    event_fn_auto_ret<DWORD> event_auto(g_peer.get_event_fn_auto(__FUNCTION__, dwResult));
#ifdef _DEBUG
    //Sleep(10000);
#endif

    // Initialize output parameters.
    if (ppEapError)
        *ppEapError = NULL;

    // Parameter check
    if (!hSession || !pdwSendPacketSize || !pSendPacket && *pdwSendPacketSize)
        return dwResult = ERROR_INVALID_PARAMETER;

    try {
        g_peer.get_response_packet(hSession, pSendPacket, pdwSendPacketSize);
    } catch (std::exception &err) {
        dwResult = g_peer.log_error(ppEapError, err);
    } catch (...) {
        dwResult = ERROR_INVALID_DATA;
    }

    return dwResult;
}


///
/// Obtains the result of an authentication session from the EAP method.
///
/// \sa [EapPeerGetResult function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363611.aspx)
///
//_Use_decl_annotations_
DWORD APIENTRY EapPeerGetResult(
    EAP_SESSION_HANDLE        hSession,
    EapPeerMethodResultReason reason,
    EapPeerMethodResult       *pResult,
    EAP_ERROR                 **ppEapError)
{
    DWORD dwResult = ERROR_SUCCESS;
    event_fn_auto_ret<DWORD> event_auto(g_peer.get_event_fn_auto(__FUNCTION__, dwResult));
#ifdef _DEBUG
    //Sleep(10000);
#endif

    // Initialize output parameters.
    if (ppEapError)
        *ppEapError = NULL;

    // Parameter check
    if (!hSession || !pResult)
        return dwResult = ERROR_INVALID_PARAMETER;

    try {
        g_peer.get_result(hSession, reason, pResult);
    } catch (std::exception &err) {
        dwResult = g_peer.log_error(ppEapError, err);
    } catch (...) {
        dwResult = ERROR_INVALID_DATA;
    }

    return dwResult;
}


///
/// Obtains the user interface context from the EAP method.
///
/// \note This function is always followed by the `EapPeerInvokeInteractiveUI()` function, which is followed by the `EapPeerSetUIContext()` function.
///
/// \sa [EapPeerGetUIContext function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363612.aspx)
///
//_Use_decl_annotations_
DWORD APIENTRY EapPeerGetUIContext(
    EAP_SESSION_HANDLE hSession,
    DWORD              *pdwUIContextDataSize,
    BYTE               **ppUIContextData,
    EAP_ERROR          **ppEapError)
{
    DWORD dwResult = ERROR_SUCCESS;
    event_fn_auto_ret<DWORD> event_auto(g_peer.get_event_fn_auto(__FUNCTION__, dwResult));
#ifdef _DEBUG
    //Sleep(10000);
#endif

    // Initialize output parameters.
    if (pdwUIContextDataSize)
        *pdwUIContextDataSize = 0;
    if (ppUIContextData)
        *ppUIContextData = NULL;
    if (ppEapError)
        *ppEapError = NULL;

    // Parameter check
    if (!hSession || !pdwUIContextDataSize || !ppUIContextData)
        return dwResult = ERROR_INVALID_PARAMETER;

    try {
        g_peer.get_ui_context(hSession, ppUIContextData, pdwUIContextDataSize);
    } catch (std::exception &err) {
        dwResult = g_peer.log_error(ppEapError, err);
    } catch (...) {
        dwResult = ERROR_INVALID_DATA;
    }

    return dwResult;
}


///
/// Provides a user interface context to the EAP method.
///
/// \note This function is called after the UI has been raised through the `EapPeerGetUIContext()` function.
///
/// \sa [EapPeerSetUIContext function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363626.aspx)
///
//_Use_decl_annotations_
DWORD APIENTRY EapPeerSetUIContext(
          EAP_SESSION_HANDLE  hSession,
          DWORD               dwUIContextDataSize,
    const BYTE                *pUIContextData,
          EapPeerMethodOutput *pEapOutput,
          EAP_ERROR           **ppEapError)
{
    DWORD dwResult = ERROR_SUCCESS;
    event_fn_auto_ret<DWORD> event_auto(g_peer.get_event_fn_auto(__FUNCTION__, dwResult));
#ifdef _DEBUG
    //Sleep(10000);
#endif

    // Initialize output parameters.
    if (pEapOutput)
        memset(pEapOutput, 0, sizeof(*pEapOutput));
    if (ppEapError)
        *ppEapError = NULL;

    // Parameter check
    if (!hSession || !pUIContextData && dwUIContextDataSize || !pEapOutput)
        return dwResult = ERROR_INVALID_PARAMETER;

    try {
        g_peer.set_ui_context(hSession, pUIContextData, dwUIContextDataSize, pEapOutput);
    } catch (std::exception &err) {
        dwResult = g_peer.log_error(ppEapError, err);
    } catch (...) {
        dwResult = ERROR_INVALID_DATA;
    }

    return dwResult;
}


///
/// Obtains an array of EAP response attributes from the EAP method.
///
/// \sa [EapPeerGetResponseAttributes function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363609.aspx)
///
//_Use_decl_annotations_
DWORD APIENTRY EapPeerGetResponseAttributes(
    EAP_SESSION_HANDLE hSession,
    EapAttributes      *pAttribs,
    EAP_ERROR          **ppEapError)
{
    DWORD dwResult = ERROR_SUCCESS;
    event_fn_auto_ret<DWORD> event_auto(g_peer.get_event_fn_auto(__FUNCTION__, dwResult));
#ifdef _DEBUG
    //Sleep(10000);
#endif

    // Initialize output parameters.
    if (pAttribs)
        memset(pAttribs, 0, sizeof(*pAttribs));
    if (ppEapError)
        *ppEapError = NULL;

    // Parameter check
    if (!hSession || !pAttribs)
        return dwResult = ERROR_INVALID_PARAMETER;

    try {
        g_peer.get_response_attributes(hSession, pAttribs);
    } catch (std::exception &err) {
        dwResult = g_peer.log_error(ppEapError, err);
    } catch (...) {
        dwResult = ERROR_INVALID_DATA;
    }

    return dwResult;
}


///
/// Provides an updated array of EAP response attributes to the EAP method.
///
/// \sa [EapPeerSetResponseAttributes function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363625.aspx)
///
//_Use_decl_annotations_
DWORD APIENTRY EapPeerSetResponseAttributes(
              EAP_SESSION_HANDLE  hSession,
    /*const*/ EapAttributes       *pAttribs,
              EapPeerMethodOutput *pEapOutput,
              EAP_ERROR           **ppEapError)
{
    DWORD dwResult = ERROR_SUCCESS;
    event_fn_auto_ret<DWORD> event_auto(g_peer.get_event_fn_auto(__FUNCTION__, dwResult));
#ifdef _DEBUG
    //Sleep(10000);
#endif

    // Initialize output parameters.
    if (pEapOutput)
        memset(pEapOutput, 0, sizeof(*pEapOutput));
    if (ppEapError)
        *ppEapError = NULL;

    // Parameter check
    if (!hSession || !pEapOutput)
        return dwResult = ERROR_INVALID_PARAMETER;

    try {
        g_peer.set_response_attributes(hSession, pAttribs, pEapOutput);
    } catch (std::exception &err) {
        dwResult = g_peer.log_error(ppEapError, err);
    } catch (...) {
        dwResult = ERROR_INVALID_DATA;
    }

    return dwResult;
}


///
/// Defines the implementation of an EAP method-specific function that retrieves the properties of an EAP method given the connection and user data.
///
/// \sa [EapPeerGetMethodProperties function](https://msdn.microsoft.com/en-us/library/windows/desktop/hh706636.aspx)
///
_Use_decl_annotations_
DWORD WINAPI EapPeerGetMethodProperties(
              DWORD                     dwVersion,
              DWORD                     dwFlags,
              EAP_METHOD_TYPE           eapMethodType,
              HANDLE                    hUserImpersonationToken,
              DWORD                     dwConnectionDataSize,
    /*const*/ BYTE                      *pConnectionData,
              DWORD                     dwUserDataSize,
    /*const*/ BYTE                      *pUserData,
              EAP_METHOD_PROPERTY_ARRAY *pMethodPropertyArray,
              EAP_ERROR                 **ppEapError)
{
    DWORD dwResult = ERROR_SUCCESS;
    event_fn_auto_ret<DWORD> event_auto(g_peer.get_event_fn_auto(__FUNCTION__, dwResult));
#ifdef _DEBUG
    //Sleep(10000);
#endif

    // Initialize output parameters.
    if (pMethodPropertyArray)
        memset(pMethodPropertyArray, 0, sizeof(*pMethodPropertyArray));
    if (ppEapError)
        *ppEapError = NULL;

    // Parameter check
    if (eapMethodType.eapType.type != EAPMETHOD_TYPE || eapMethodType.dwAuthorId != 67532)
        return dwResult = ERROR_NOT_SUPPORTED;
    if (!pConnectionData && dwConnectionDataSize || !pUserData && dwUserDataSize || !pMethodPropertyArray)
        return dwResult = ERROR_INVALID_PARAMETER;

    try {
        g_peer.get_method_properties(dwVersion, dwFlags, hUserImpersonationToken, pConnectionData, dwConnectionDataSize, pUserData, dwUserDataSize, pMethodPropertyArray);
    } catch (std::exception &err) {
        dwResult = g_peer.log_error(ppEapError, err);
    } catch (...) {
        dwResult = ERROR_INVALID_DATA;
    }

    return dwResult;
}


///
/// Converts XML into the configuration BLOB. The XML based credentials can come from group policy or from a system administrator.
///
/// \sa [EapPeerCredentialsXml2Blob function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363603.aspx)
///
_Use_decl_annotations_
DWORD WINAPI EapPeerCredentialsXml2Blob(
          DWORD            dwFlags,
          EAP_METHOD_TYPE  eapMethodType,
          IXMLDOMDocument2 *pCredentialsDoc,
    const BYTE             *pConnectionData,
          DWORD            dwConnectionDataSize,
          BYTE             **ppCredentialsOut,
          DWORD            *pdwCredentialsOutSize,
          EAP_ERROR        **ppEapError)
{
    DWORD dwResult = ERROR_SUCCESS;
    event_fn_auto_ret<DWORD> event_auto(g_peer.get_event_fn_auto(__FUNCTION__, dwResult));
#ifdef _DEBUG
    //Sleep(10000);
#endif

    // Initialize output parameters.
    if (ppCredentialsOut)
        *ppCredentialsOut = NULL;
    if (pdwCredentialsOutSize)
        *pdwCredentialsOutSize = 0;
    if (ppEapError)
        *ppEapError = NULL;

    // Parameter check
    if (eapMethodType.eapType.type != EAPMETHOD_TYPE || eapMethodType.dwAuthorId != 67532)
        return dwResult = ERROR_NOT_SUPPORTED;
    if (!pCredentialsDoc || !pConnectionData && dwConnectionDataSize || !ppCredentialsOut || !pdwCredentialsOutSize)
        return dwResult = ERROR_INVALID_PARAMETER;

    // <Credentials>
    com_obj<IXMLDOMNode> pXmlElCredentials;
    if (FAILED(eapxml::select_node(pCredentialsDoc, bstr(L"//EapHostUserCredentials/Credentials"), pXmlElCredentials)))
        return dwResult = g_peer.log_error(ppEapError, ERROR_NOT_FOUND, _T(__FUNCTION__) _T(" Error selecting <EapHostUserCredentials><Credentials> element."));

    // Load credentials.
    pCredentialsDoc->setProperty(bstr(L"SelectionNamespaces"), variant(L"xmlns:eap-metadata=\"urn:ietf:params:xml:ns:yang:ietf-eap-metadata\""));
    try {
        g_peer.credentials_xml2blob(dwFlags, pXmlElCredentials, pConnectionData, dwConnectionDataSize, ppCredentialsOut, pdwCredentialsOutSize);
    } catch (std::exception &err) {
        dwResult = g_peer.log_error(ppEapError, err);
    } catch (...) {
        dwResult = ERROR_INVALID_DATA;
    }

    return dwResult;
}


///
/// Defines the implementation of an EAP method-specific function that obtains the EAP Single-Sign-On (SSO) credential input fields for an EAP method.
///
/// \sa [EapPeerQueryCredentialInputFields function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363622.aspx)
///
_Use_decl_annotations_
DWORD WINAPI EapPeerQueryCredentialInputFields(
              HANDLE                       hUserImpersonationToken,
              EAP_METHOD_TYPE              eapMethodType,
              DWORD                        dwFlags,
              DWORD                        dwConnectionDataSize,
    /*const*/ BYTE                         *pConnectionData,
              EAP_CONFIG_INPUT_FIELD_ARRAY *pEapConfigInputFieldsArray,
              EAP_ERROR                    **ppEapError)
{
    DWORD dwResult = ERROR_SUCCESS;
    event_fn_auto_ret<DWORD> event_auto(g_peer.get_event_fn_auto(__FUNCTION__, dwResult));
#ifdef _DEBUG
    //Sleep(10000);
#endif

    // Initialize output parameters.
    if (pEapConfigInputFieldsArray)
        memset(pEapConfigInputFieldsArray, 0, sizeof(*pEapConfigInputFieldsArray));
    if (ppEapError)
        *ppEapError = NULL;

    // Parameter check
    if (eapMethodType.eapType.type != EAPMETHOD_TYPE || eapMethodType.dwAuthorId != 67532)
        return dwResult = ERROR_NOT_SUPPORTED;
    if (!pConnectionData && dwConnectionDataSize || !pEapConfigInputFieldsArray)
        return dwResult = ERROR_INVALID_PARAMETER;

    try {
        g_peer.query_credential_input_fields(hUserImpersonationToken, dwFlags, dwConnectionDataSize, pConnectionData, pEapConfigInputFieldsArray);
    } catch (std::exception &err) {
        dwResult = g_peer.log_error(ppEapError, err);
    } catch (...) {
        dwResult = ERROR_INVALID_DATA;
    }

    return dwResult;
}


///
/// Defines the implementation of an EAP method function that obtains the user BLOB data provided in an interactive Single-Sign-On (SSO) UI raised on the supplicant.
///
/// \sa [EapPeerQueryUserBlobFromCredentialInputFields function](https://msdn.microsoft.com/en-us/library/windows/desktop/bb204697.aspx)
///
#pragma warning(suppress: 6101) // Function is incorrectly annotated and code analysis gets confused
_Use_decl_annotations_
DWORD WINAPI EapPeerQueryUserBlobFromCredentialInputFields(
              HANDLE                       hUserImpersonationToken,
              EAP_METHOD_TYPE              eapMethodType,
              DWORD                        dwFlags,
              DWORD                        dwConnectionDataSize,
    /*const*/ BYTE                         *pConnectionData,
      const   EAP_CONFIG_INPUT_FIELD_ARRAY *pEapConfigInputFieldArray,
              DWORD                        *pdwUsersBlobSize,
              BYTE                         **ppUserBlob,
              EAP_ERROR                    **ppEapError)
{
    DWORD dwResult = ERROR_SUCCESS;
    event_fn_auto_ret<DWORD> event_auto(g_peer.get_event_fn_auto(__FUNCTION__, dwResult));
#ifdef _DEBUG
    //Sleep(10000);
#endif

    // Initialize output parameters.
    if (ppEapError)
        *ppEapError = NULL;

    // Parameter check
    if (eapMethodType.eapType.type != EAPMETHOD_TYPE || eapMethodType.dwAuthorId != 67532)
        return dwResult = ERROR_NOT_SUPPORTED;
    if (!pConnectionData && dwConnectionDataSize || !pEapConfigInputFieldArray || !pdwUsersBlobSize || !ppUserBlob)
        return dwResult = ERROR_INVALID_PARAMETER;

    try {
        g_peer.query_user_blob_from_credential_input_fields(hUserImpersonationToken, dwFlags, dwConnectionDataSize, pConnectionData, pEapConfigInputFieldArray, pdwUsersBlobSize, ppUserBlob);
    } catch (std::exception &err) {
        dwResult = g_peer.log_error(ppEapError, err);
    } catch (...) {
        dwResult = ERROR_INVALID_DATA;
    }

    return dwResult;
}


///
/// Defines the implementation of an EAP method API that provides the input fields for interactive UI components to be raised on the supplicant.
///
/// \sa [EapPeerQueryInteractiveUIInputFields function](https://msdn.microsoft.com/en-us/library/windows/desktop/bb204695.aspx)
///
_Use_decl_annotations_
DWORD WINAPI EapPeerQueryInteractiveUIInputFields(
          DWORD                   dwVersion,
          DWORD                   dwFlags,
          DWORD                   dwUIContextDataSize,
    const BYTE                    *pUIContextData,
          EAP_INTERACTIVE_UI_DATA *pEapInteractiveUIData,
          EAP_ERROR               **ppEapError,
          LPVOID                  *ppvReserved)
{
    UNREFERENCED_PARAMETER(ppvReserved);

    DWORD dwResult = ERROR_SUCCESS;
    event_fn_auto_ret<DWORD> event_auto(g_peer.get_event_fn_auto(__FUNCTION__, dwResult));
#ifdef _DEBUG
    //Sleep(10000);
#endif

    // Initialize output parameters.
    if (pEapInteractiveUIData)
        memset(pEapInteractiveUIData, 0, sizeof(*pEapInteractiveUIData));
    if (ppEapError)
        *ppEapError = NULL;

    // Parameter check
    if (!pUIContextData && dwUIContextDataSize || !pEapInteractiveUIData)
        return dwResult = ERROR_INVALID_PARAMETER;

    try {
        g_peer.query_interactive_ui_input_fields(dwVersion, dwFlags, dwUIContextDataSize, pUIContextData, pEapInteractiveUIData);
    } catch (std::exception &err) {
        dwResult = g_peer.log_error(ppEapError, err);
    } catch (...) {
        dwResult = ERROR_INVALID_DATA;
    }

    return dwResult;
}


///
/// Converts user information into a user BLOB that can be consumed by EapHost run-time functions.
///
/// \sa [EapPeerQueryUIBlobFromInteractiveUIInputFields function](https://msdn.microsoft.com/en-us/library/windows/desktop/bb204696.aspx)
///
#pragma warning(suppress: 6387) // Function is incorrectly annotated and code analysis gets confused
#pragma warning(suppress: 28196)
_Use_decl_annotations_
DWORD WINAPI EapPeerQueryUIBlobFromInteractiveUIInputFields(
          DWORD                   dwVersion,
          DWORD                   dwFlags,
          DWORD                   dwUIContextDataSize,
    const BYTE                    *pUIContextData,
    const EAP_INTERACTIVE_UI_DATA *pEapInteractiveUIData,
          DWORD                   *pdwDataFromInteractiveUISize,
          BYTE                    **ppDataFromInteractiveUI,
          EAP_ERROR               **ppEapError,
          LPVOID                  *ppvReserved)
{
    UNREFERENCED_PARAMETER(ppvReserved);

    DWORD dwResult = ERROR_SUCCESS;
    event_fn_auto_ret<DWORD> event_auto(g_peer.get_event_fn_auto(__FUNCTION__, dwResult));
#ifdef _DEBUG
    //Sleep(10000);
#endif

    // Initialize output parameters.
    if (pdwDataFromInteractiveUISize)
        *pdwDataFromInteractiveUISize = 0;
    if (ppDataFromInteractiveUI)
        *ppDataFromInteractiveUI = NULL;
    if (ppEapError)
        *ppEapError = NULL;

    // Parameter check
    if (!pUIContextData && dwUIContextDataSize || !pEapInteractiveUIData || !pdwDataFromInteractiveUISize || !ppDataFromInteractiveUI)
        return dwResult = ERROR_INVALID_PARAMETER;

    try {
        g_peer.query_ui_blob_from_interactive_ui_input_fields(dwVersion, dwFlags, dwUIContextDataSize, pUIContextData, pEapInteractiveUIData, pdwDataFromInteractiveUISize, ppDataFromInteractiveUI);
    } catch (std::exception &err) {
        dwResult = g_peer.log_error(ppEapError, err);
    } catch (...) {
        dwResult = ERROR_INVALID_DATA;
    }

    return dwResult;
}
