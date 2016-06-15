/*
    Copyright 2015-2016 Amebis
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

#pragma comment(lib, "msxml6.lib")


#if EAPMETHOD_TYPE==21
#define _EAPMETHOD_PEER_UI eap::peer_ttls_ui
#else
#error Unknown EAP Method type.
#endif

HANDLE g_act_ctx = NULL;
_EAPMETHOD_PEER_UI g_peer;


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

        // Save current activation context, as proper activation context is set at this time only (LoadLibrary() call).
        GetCurrentActCtx(&g_act_ctx);
    } else if (fdwReason == DLL_PROCESS_DETACH) {
        if (g_act_ctx)
            ReleaseActCtx(g_act_ctx);

        // wxWidgets library has some global objects allocating data on heap in constructors,
        // causing false-positive memory leak reports.
        //assert(!_CrtDumpMemoryLeaks());
    }

    return TRUE;
}


///
/// Releases all memory associated with an opaque user interface context data buffer.
///
/// \sa [EapPeerFreeMemory function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363606.aspx)
///
VOID WINAPI EapPeerFreeMemory(_In_ void *pUIContextData)
{
    if (pUIContextData)
        g_peer.free_memory((BYTE*)pUIContextData);
}


///
/// Releases error-specific memory allocated by the EAP peer method.
///
/// \sa [EapPeerFreeErrorMemory function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363605.aspx)
///
VOID WINAPI EapPeerFreeErrorMemory(_In_ EAP_ERROR *ppEapError)
{
    if (ppEapError)
        g_peer.free_error_memory(ppEapError);
}


///
/// Converts XML into the configuration BLOB.
///
/// \sa [EapPeerConfigXml2Blob function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363602.aspx)
///
DWORD WINAPI EapPeerConfigXml2Blob(
    _In_  DWORD            dwFlags,
    _In_  EAP_METHOD_TYPE  eapMethodType,
    _In_  IXMLDOMDocument2 *pConfigDoc,
    _Out_ BYTE             **ppConfigOut,
    _Out_ DWORD            *pdwConfigOutSize,
    _Out_ EAP_ERROR        **ppEapError)
{
    DWORD dwResult = ERROR_SUCCESS;
#ifdef _DEBUG
    //Sleep(10000);
#endif

    // Parameter check
    if (!ppEapError)
        dwResult = ERROR_INVALID_PARAMETER;
    else if (eapMethodType.eapType.type != EAPMETHOD_TYPE)
        *ppEapError = g_peer.make_error(dwResult = ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, winstd::wstring_printf(_T(__FUNCTION__) _T(" Input EAP type (%d) does not match the supported EAP type (%d)."), (int)eapMethodType.eapType.type, (int)EAPMETHOD_TYPE).c_str(), NULL);
    else if (eapMethodType.dwAuthorId != 67532)
        *ppEapError = g_peer.make_error(dwResult = ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, winstd::wstring_printf(_T(__FUNCTION__) _T(" EAP author (%d) does not match the supported author (%d)."), (int)eapMethodType.dwAuthorId, (int)67532).c_str(), NULL);
    else if (!pConfigDoc)
        *ppEapError = g_peer.make_error(dwResult = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pConfigDoc is NULL."), NULL);
    else if (!ppConfigOut)
        *ppEapError = g_peer.make_error(dwResult = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" ppConfigOut is NULL."), NULL);
    else if (!pdwConfigOutSize)
        *ppEapError = g_peer.make_error(dwResult = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pdwConfigOutSize is NULL."), NULL);
    else {
        UNREFERENCED_PARAMETER(dwFlags);

        // <Config>
        pConfigDoc->setProperty(winstd::bstr(L"SelectionNamespaces"), winstd::variant(L"xmlns:eaphostconfig=\"http://www.microsoft.com/provisioning/EapHostConfig\""));
        winstd::com_obj<IXMLDOMElement> pXmlElConfig;
        if ((dwResult = eapxml::select_element(pConfigDoc, winstd::bstr(L"//eaphostconfig:Config"), &pXmlElConfig)) != ERROR_SUCCESS)
            return dwResult;

        // Load configuration.
        pConfigDoc->setProperty(winstd::bstr(L"SelectionNamespaces"), winstd::variant(L"xmlns:eap-metadata=\"urn:ietf:params:xml:ns:yang:ietf-eap-metadata\""));
        _EAPMETHOD_PEER_UI::config_type cfg(g_peer);
        if (!cfg.load(pXmlElConfig, ppEapError))
            return dwResult = *ppEapError ? (*ppEapError)->dwWinError : ERROR_INVALID_DATA;

        // Allocate BLOB for configuration.
        assert(ppConfigOut);
        assert(pdwConfigOutSize);
        *pdwConfigOutSize = (DWORD)eapserial::get_pk_size(cfg);
        *ppConfigOut = g_peer.alloc_memory(*pdwConfigOutSize);
        if (!*ppConfigOut) {
            *ppEapError = g_peer.make_error(dwResult = ERROR_OUTOFMEMORY, 0, NULL, NULL, NULL, winstd::tstring_printf(_T(__FUNCTION__) _T(" Error allocating memory for configuration BLOB (%uB)."), *pdwConfigOutSize).c_str(), NULL);
            return dwResult;
        }

        // Pack BLOB to output.
        unsigned char *cursor = *ppConfigOut;
        eapserial::pack(cursor, cfg);
        assert(cursor - *ppConfigOut <= (ptrdiff_t)*pdwConfigOutSize);
    }

    return dwResult;
}


///
/// Converts the configuration BLOB to XML.
///
/// The configuration BLOB is returned in the ppConnectionDataOut parameter of the EapPeerInvokeConfigUI function.
///
/// \sa [EapPeerConfigBlob2Xml function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363601.aspx)
///
DWORD WINAPI EapPeerConfigBlob2Xml(
    _In_                             DWORD            dwFlags,
    _In_                             EAP_METHOD_TYPE  eapMethodType,
    _In_count_(dwConfigInSize) const BYTE             *pConfigIn,
    _In_                             DWORD            dwConfigInSize,
    _Out_                            IXMLDOMDocument2 **ppConfigDoc,
    _Out_                            EAP_ERROR        **ppEapError)
{
    DWORD dwResult = ERROR_SUCCESS;
#ifdef _DEBUG
    //Sleep(10000);
#endif

    // Parameter check
    if (!ppEapError)
        dwResult = ERROR_INVALID_PARAMETER;
    else if (eapMethodType.eapType.type != EAPMETHOD_TYPE)
        *ppEapError = g_peer.make_error(dwResult = ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, winstd::wstring_printf(_T(__FUNCTION__) _T(" Input EAP type (%d) does not match the supported EAP type (%d)."), (int)eapMethodType.eapType.type, (int)EAPMETHOD_TYPE).c_str(), NULL);
    else if (eapMethodType.dwAuthorId != 67532)
        *ppEapError = g_peer.make_error(dwResult = ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, winstd::wstring_printf(_T(__FUNCTION__) _T(" EAP author (%d) does not match the supported author (%d)."), (int)eapMethodType.dwAuthorId, (int)67532).c_str(), NULL);
    else if (!pConfigIn && dwConfigInSize)
        *ppEapError = g_peer.make_error(dwResult = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pConfigIn is NULL."), NULL);
    else if (!ppConfigDoc)
        *ppEapError = g_peer.make_error(dwResult = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" ppConfigDoc is NULL."), NULL);
    else {
        UNREFERENCED_PARAMETER(dwFlags);
        HRESULT hr;

        // Unpack configuration.
        _EAPMETHOD_PEER_UI::config_type cfg(g_peer);
        if (pConfigIn || !dwConfigInSize) {
            const unsigned char *cursor = pConfigIn;
            eapserial::unpack(cursor, cfg);
            assert(cursor - pConfigIn <= (ptrdiff_t)dwConfigInSize);
        }

        // Create configuration XML document.
        winstd::com_obj<IXMLDOMDocument2> pDoc;
        if (FAILED(hr = pDoc.create(CLSID_DOMDocument60, NULL, CLSCTX_INPROC_SERVER))) {
            *ppEapError = g_peer.make_error(dwResult = HRESULT_CODE(hr), 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error creating XML document."), NULL);
            return dwResult;
        }

        pDoc->put_async(VARIANT_FALSE);

        // Load empty XML configuration.
        VARIANT_BOOL isSuccess = VARIANT_FALSE;
        if (FAILED((hr = pDoc->loadXML(L"<Config xmlns=\"http://www.microsoft.com/provisioning/EapHostConfig\"><EAPIdentityProviderList xmlns=\"urn:ietf:params:xml:ns:yang:ietf-eap-metadata\"></EAPIdentityProviderList></Config>", &isSuccess))))
            return dwResult = HRESULT_CODE(hr);
        if (!isSuccess) {
            *ppEapError = g_peer.make_error(dwResult = ERROR_XML_PARSE_ERROR, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Loading XML template failed."), NULL);
            return dwResult;
        }

        // Select <Config> node.
        winstd::com_obj<IXMLDOMNode> pXmlElConfig;
        pDoc->setProperty(winstd::bstr(L"SelectionNamespaces"), winstd::variant(L"xmlns:eaphostconfig=\"http://www.microsoft.com/provisioning/EapHostConfig\""));
        if ((dwResult = eapxml::select_node(pDoc, winstd::bstr(L"eaphostconfig:Config"), &pXmlElConfig)) != ERROR_SUCCESS) {
            *ppEapError = g_peer.make_error(dwResult = ERROR_NOT_FOUND, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error selecting <Config> element."), NULL);
            return dwResult;
        }

        // Save all providers.
        pDoc->setProperty(winstd::bstr(L"SelectionNamespaces"), winstd::variant(L"xmlns:eap-metadata=\"urn:ietf:params:xml:ns:yang:ietf-eap-metadata\""));
        if (!cfg.save(pDoc, pXmlElConfig, ppEapError))
            return dwResult = *ppEapError ? (*ppEapError)->dwWinError : ERROR_INVALID_DATA;

        *ppConfigDoc = pDoc.detach();
    }

    return dwResult;
}


///
/// Raises the EAP method's specific connection configuration user interface dialog on the client.
///
/// \sa [EapPeerInvokeConfigUI function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363614.aspx)
///
DWORD WINAPI EapPeerInvokeConfigUI(
    _In_                               const EAP_METHOD_TYPE *pEapType,
    _In_                                     HWND            hwndParent,
    _In_                                     DWORD           dwFlags,
    _In_                                     DWORD           dwConnectionDataInSize,
    _In_count_(dwConnectionDataInSize) const BYTE            *pConnectionDataIn,
    _Out_                                    DWORD           *pdwConnectionDataOutSize,
    _Out_                                    BYTE            **ppConnectionDataOut,
    _Out_                                    EAP_ERROR       **ppEapError)
{
    UNREFERENCED_PARAMETER(dwFlags);
    DWORD dwResult = ERROR_SUCCESS;
    winstd::actctx_activator actctx(g_act_ctx);
#ifdef _DEBUG
    //Sleep(10000);
#endif

    // Parameter check
    if (!ppEapError)
        dwResult = ERROR_INVALID_PARAMETER;
    else if (!pEapType)
        *ppEapError = g_peer.make_error(dwResult = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pEapType is NULL."), NULL);
    else if (pEapType->eapType.type != EAPMETHOD_TYPE)
        *ppEapError = g_peer.make_error(dwResult = ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, winstd::wstring_printf(_T(__FUNCTION__) _T(" Input EAP type (%d) does not match the supported EAP type (%d)."), (int)pEapType->eapType.type, (int)EAPMETHOD_TYPE).c_str(), NULL);
    else if (pEapType->dwAuthorId != 67532)
        *ppEapError = g_peer.make_error(dwResult = ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, winstd::wstring_printf(_T(__FUNCTION__) _T(" EAP author (%d) does not match the supported author (%d)."), (int)pEapType->dwAuthorId, (int)67532).c_str(), NULL);
    else if (!pConnectionDataIn && dwConnectionDataInSize)
        *ppEapError = g_peer.make_error(dwResult = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pConnectionDataIn is NULL."), NULL);
    else if (!pdwConnectionDataOutSize)
        *ppEapError = g_peer.make_error(dwResult = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pdwConnectionDataOutSize is NULL."), NULL);
    else if (!ppConnectionDataOut)
        *ppEapError = g_peer.make_error(dwResult = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" ppConnectionDataOut is NULL."), NULL);
    else {
        // Unpack configuration.
        _EAPMETHOD_PEER_UI::config_type cfg(g_peer);
        if (pConnectionDataIn || !dwConnectionDataInSize) {
            const unsigned char *cursor = pConnectionDataIn;
            eapserial::unpack(cursor, cfg);
            assert(cursor - pConnectionDataIn <= (ptrdiff_t)dwConnectionDataInSize);
        }

        if (!g_peer.invoke_config_ui(hwndParent, cfg, ppEapError))
            return dwResult = *ppEapError ? (*ppEapError)->dwWinError : ERROR_INVALID_DATA;

        // Allocate BLOB for configuration.
        assert(ppConnectionDataOut);
        assert(pdwConnectionDataOutSize);
        *pdwConnectionDataOutSize = (DWORD)eapserial::get_pk_size(cfg);
        *ppConnectionDataOut = g_peer.alloc_memory(*pdwConnectionDataOutSize);
        if (!*ppConnectionDataOut) {
            *ppEapError = g_peer.make_error(dwResult = ERROR_OUTOFMEMORY, 0, NULL, NULL, NULL, winstd::tstring_printf(_T(__FUNCTION__) _T(" Error allocating memory for configuration BLOB (%uB)."), *pdwConnectionDataOutSize).c_str(), NULL);
            return dwResult;
        }

        // Pack BLOB to output.
        unsigned char *cursor = *ppConnectionDataOut;
        eapserial::pack(cursor, cfg);
        assert(cursor - *ppConnectionDataOut <= (ptrdiff_t)*pdwConnectionDataOutSize);
    }

    return dwResult;
}


///
/// Raises a custom interactive user interface dialog to obtain user identity information for the EAP method on the client.
///
/// \sa [EapPeerInvokeIdentityUI function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363615.aspx)
///
DWORD WINAPI EapPeerInvokeIdentityUI(
    _In_                             const EAP_METHOD_TYPE *pEapType,
    _In_                                   DWORD           dwFlags,
    _In_                                   HWND            hwndParent,
    _In_                                   DWORD           dwConnectionDataSize,
    _In_count_(dwConnectionDataSize) const BYTE            *pConnectionData,
    _In_                                   DWORD           dwUserDataSize,
    _In_count_(dwUserDataSize)       const BYTE            *pUserData,
    _Out_                                  DWORD           *pdwUserDataOutSize,
    _Out_                                  BYTE            **ppUserDataOut,
    _Out_                                  LPWSTR          *ppwszIdentity,
    _Out_                                  EAP_ERROR       **ppEapError)
{
    DWORD dwResult = ERROR_SUCCESS;
    winstd::actctx_activator actctx(g_act_ctx);
#ifdef _DEBUG
    //Sleep(10000);
#endif

    // Parameter check
    if (!ppEapError)
        dwResult = ERROR_INVALID_PARAMETER;
    else if (!pEapType)
        *ppEapError = g_peer.make_error(dwResult = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pEapType is NULL."), NULL);
    else if (pEapType->eapType.type != EAPMETHOD_TYPE)
        *ppEapError = g_peer.make_error(dwResult = ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, winstd::wstring_printf(_T(__FUNCTION__) _T(" Input EAP type (%d) does not match the supported EAP type (%d)."), (int)pEapType->eapType.type, (int)EAPMETHOD_TYPE).c_str(), NULL);
    else if (pEapType->dwAuthorId != 67532)
        *ppEapError = g_peer.make_error(dwResult = ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, winstd::wstring_printf(_T(__FUNCTION__) _T(" EAP author (%d) does not match the supported author (%d)."), (int)pEapType->dwAuthorId, (int)67532).c_str(), NULL);
    else if (!pConnectionData && dwConnectionDataSize)
        *ppEapError = g_peer.make_error(dwResult = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pConnectionData is NULL."), NULL);
    else if (!pUserData && dwUserDataSize)
        *ppEapError = g_peer.make_error(dwResult = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pUserData is NULL."), NULL);
    else if (!pdwUserDataOutSize)
        *ppEapError = g_peer.make_error(dwResult = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pdwUserDataOutSize is NULL."), NULL);
    else if (!ppUserDataOut)
        *ppEapError = g_peer.make_error(dwResult = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" ppUserDataOut is NULL."), NULL);
    else if (!ppwszIdentity)
        *ppEapError = g_peer.make_error(dwResult = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" ppwszIdentity is NULL."), NULL);
    else {
        // Unpack configuration.
        _EAPMETHOD_PEER_UI::config_type cfg(g_peer);
        if (pConnectionData || !dwConnectionDataSize) {
            const unsigned char *cursor = pConnectionData;
            eapserial::unpack(cursor, cfg);
            assert(cursor - pConnectionData <= (ptrdiff_t)dwConnectionDataSize);
        }

        // Unpack configuration.
        _EAPMETHOD_PEER_UI::identity_type usr(g_peer);
        if (pUserData || !dwUserDataSize) {
            const unsigned char *cursor = pUserData;
            eapserial::unpack(cursor, usr);
            assert(cursor - pUserData <= (ptrdiff_t)dwUserDataSize);
        }

        if (!g_peer.invoke_identity_ui(hwndParent, dwFlags, cfg, usr, ppwszIdentity, ppEapError))
            return dwResult = *ppEapError ? (*ppEapError)->dwWinError : ERROR_INVALID_DATA;

        // Allocate BLOB for user data.
        assert(ppUserDataOut);
        assert(pdwUserDataOutSize);
        *pdwUserDataOutSize = (DWORD)eapserial::get_pk_size(usr);
        *ppUserDataOut = g_peer.alloc_memory(*pdwUserDataOutSize);
        if (!*ppUserDataOut) {
            *ppEapError = g_peer.make_error(dwResult = ERROR_OUTOFMEMORY, 0, NULL, NULL, NULL, winstd::tstring_printf(_T(__FUNCTION__) _T(" Error allocating memory for configuration BLOB (%uB)."), *pdwUserDataOutSize).c_str(), NULL);
            return dwResult;
        }

        // Pack BLOB to output.
        unsigned char *cursor = *ppUserDataOut;
        eapserial::pack(cursor, usr);
        assert(cursor - *ppUserDataOut <= (ptrdiff_t)*pdwUserDataOutSize);
    }

    return dwResult;
}


///
/// Raises a custom interactive user interface dialog for the EAP method on the client.
///
/// \sa [EapPeerInvokeInteractiveUI function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363616.aspx)
///
DWORD WINAPI EapPeerInvokeInteractiveUI(
    _In_                            const EAP_METHOD_TYPE *pEapType,
    _In_                                  HWND            hwndParent,
    _In_                                  DWORD           dwUIContextDataSize,
    _In_count_(dwUIContextDataSize) const BYTE            *pUIContextData,
    _Out_                                 DWORD           *pdwDataFromInteractiveUISize,
    _Out_                                 BYTE            **ppDataFromInteractiveUI,
    _Out_                                 EAP_ERROR       **ppEapError)
{
    DWORD dwResult = ERROR_SUCCESS;
    winstd::actctx_activator actctx(g_act_ctx);
#ifdef _DEBUG
    //Sleep(10000);
#endif

    // Parameter check
    if (!ppEapError)
        dwResult = ERROR_INVALID_PARAMETER;
    else if (!pEapType)
        *ppEapError = g_peer.make_error(dwResult = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pEapType is NULL."), NULL);
    else if (pEapType->eapType.type != EAPMETHOD_TYPE)
        *ppEapError = g_peer.make_error(dwResult = ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, winstd::wstring_printf(_T(__FUNCTION__) _T(" Input EAP type (%d) does not match the supported EAP type (%d)."), (int)pEapType->eapType.type, (int)EAPMETHOD_TYPE).c_str(), NULL);
    else if (pEapType->dwAuthorId != 67532)
        *ppEapError = g_peer.make_error(dwResult = ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, winstd::wstring_printf(_T(__FUNCTION__) _T(" EAP author (%d) does not match the supported author (%d)."), (int)pEapType->dwAuthorId, (int)67532).c_str(), NULL);
    else if (!pUIContextData && dwUIContextDataSize)
        *ppEapError = g_peer.make_error(dwResult = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pUIContextData is NULL."), NULL);
    else if (!pdwDataFromInteractiveUISize)
        *ppEapError = g_peer.make_error(dwResult = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pdwDataFromInteractiveUISize is NULL."), NULL);
    else if (!ppDataFromInteractiveUI)
        *ppEapError = g_peer.make_error(dwResult = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" ppDataFromInteractiveUI is NULL."), NULL);
    else {
        // Unpack request.
        _EAPMETHOD_PEER_UI::interactive_request_type req;
        if (pUIContextData || !dwUIContextDataSize) {
            const unsigned char *cursor = pUIContextData;
            eapserial::unpack(cursor, req);
            assert(cursor - pUIContextData <= (ptrdiff_t)dwUIContextDataSize);
        }

        _EAPMETHOD_PEER_UI::interactive_response_type res;
        if (!g_peer.invoke_interactive_ui(hwndParent, req, res, ppEapError))
            return dwResult = *ppEapError ? (*ppEapError)->dwWinError : ERROR_INVALID_DATA;

        // Allocate BLOB for user data.
        assert(ppDataFromInteractiveUI);
        assert(pdwDataFromInteractiveUISize);
        *pdwDataFromInteractiveUISize = (DWORD)eapserial::get_pk_size(res);
        *ppDataFromInteractiveUI = g_peer.alloc_memory(*pdwDataFromInteractiveUISize);
        if (!*ppDataFromInteractiveUI) {
            *ppEapError = g_peer.make_error(dwResult = ERROR_OUTOFMEMORY, 0, NULL, NULL, NULL, winstd::tstring_printf(_T(__FUNCTION__) _T(" Error allocating memory for interactive response (%uB)."), *pdwDataFromInteractiveUISize).c_str(), NULL);
            return dwResult;
        }

        // Pack BLOB to output.
        unsigned char *cursor = *ppDataFromInteractiveUI;
        eapserial::pack(cursor, res);
        assert(cursor - *ppDataFromInteractiveUI <= (ptrdiff_t)*pdwDataFromInteractiveUISize);
    }

    return dwResult;
}
