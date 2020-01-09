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

#include "StdAfx_UI.h"

#pragma comment(lib, "msxml6.lib")

using namespace std;
using namespace winstd;


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

#if _WIN32_WINNT >= _WIN32_WINNT_VISTA
        // Declare our DllHost process as DPI-aware.
        SetProcessDPIAware();
#endif

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
/// Converts XML into the configuration BLOB.
///
/// \sa [EapPeerConfigXml2Blob function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363602.aspx)
///
_Use_decl_annotations_
DWORD WINAPI EapPeerConfigXml2Blob(
    DWORD            dwFlags,
    EAP_METHOD_TYPE  eapMethodType,
    IXMLDOMDocument2 *pConfigDoc,
    BYTE             **pConnectionDataOut,
    DWORD            *pdwConnectionDataOutSize,
    EAP_ERROR        **ppEapError)
{
    DWORD dwResult = ERROR_SUCCESS;
    event_fn_auto_ret<DWORD> event_auto(g_peer.get_event_fn_auto(__FUNCTION__, dwResult));
#ifdef _DEBUG
    //Sleep(10000);
#endif

    // Initialize output parameters.
    if (pConnectionDataOut)
        *pConnectionDataOut = NULL;
    if (pdwConnectionDataOutSize)
        *pdwConnectionDataOutSize = 0;
    if (ppEapError)
        *ppEapError = NULL;

    // Parameter check
    if (eapMethodType.eapType.type != EAPMETHOD_TYPE || eapMethodType.dwAuthorId != EAPMETHOD_AUTHOR_ID)
        return dwResult = ERROR_NOT_SUPPORTED;
    if (!pConfigDoc || !pConnectionDataOut || !pdwConnectionDataOutSize)
        return dwResult = ERROR_INVALID_PARAMETER;

    // Configure XML selection namespaces used.
    pConfigDoc->setProperty(bstr(L"SelectionNamespaces"), variant(L"xmlns:eap-metadata=\"urn:ietf:params:xml:ns:yang:ietf-eap-metadata\" xmlns:eaphostconfig=\"http://www.microsoft.com/provisioning/EapHostConfig\""));

    // <Config>
    com_obj<IXMLDOMElement> pXmlElConfig;
    if (FAILED(eapxml::select_element(pConfigDoc, bstr(L"//eaphostconfig:Config"), pXmlElConfig)))
        return dwResult = g_peer.log_error(ppEapError, ERROR_INVALID_PARAMETER, _T(__FUNCTION__) _T(" Error reading <Config> element."));

    // Load configuration.
    try {
        g_peer.config_xml2blob(dwFlags, pXmlElConfig, pConnectionDataOut, pdwConnectionDataOutSize);
    } catch (std::exception &err) {
        dwResult = g_peer.log_error(ppEapError, err);
    } catch (...) {
        dwResult = ERROR_INVALID_DATA;
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
_Use_decl_annotations_
DWORD WINAPI EapPeerConfigBlob2Xml(
          DWORD            dwFlags,
          EAP_METHOD_TYPE  eapMethodType,
    const BYTE             *pConnectionData,
          DWORD            dwConnectionDataSize,
          IXMLDOMDocument2 **ppConfigDoc,
          EAP_ERROR        **ppEapError)
{
    DWORD dwResult = ERROR_SUCCESS;
    event_fn_auto_ret<DWORD> event_auto(g_peer.get_event_fn_auto(__FUNCTION__, dwResult));
#ifdef _DEBUG
    //Sleep(10000);
#endif

    // Initialize output parameters.
    if (ppConfigDoc)
        *ppConfigDoc = NULL;
    if (ppEapError)
        *ppEapError = NULL;

    // Parameter check
    if (eapMethodType.eapType.type != EAPMETHOD_TYPE || eapMethodType.dwAuthorId != EAPMETHOD_AUTHOR_ID)
        return dwResult = ERROR_NOT_SUPPORTED;
    if (!pConnectionData && dwConnectionDataSize || !ppConfigDoc)
        return dwResult = ERROR_INVALID_PARAMETER;

    HRESULT hr;

    // Create configuration XML document.
    com_obj<IXMLDOMDocument2> pConfigDoc;
    if (FAILED(hr = pConfigDoc.create(CLSID_DOMDocument60, NULL, CLSCTX_INPROC_SERVER)))
        return dwResult = g_peer.log_error(ppEapError, HRESULT_CODE(hr), _T(__FUNCTION__) _T(" Error creating XML document."));

    pConfigDoc->put_async(VARIANT_FALSE);

    // Load empty XML configuration.
    VARIANT_BOOL isSuccess = VARIANT_FALSE;
    if (FAILED((hr = pConfigDoc->loadXML(L"<Config xmlns=\"http://www.microsoft.com/provisioning/EapHostConfig\"></Config>", &isSuccess))))
        return dwResult = g_peer.log_error(ppEapError, HRESULT_CODE(hr), _T(__FUNCTION__) _T(" Error loading XML document template."));
    if (!isSuccess)
        return dwResult = g_peer.log_error(ppEapError, ERROR_XML_PARSE_ERROR, _T(__FUNCTION__) _T(" Loading XML template failed."));

    // Configure XML selection namespaces used.
    pConfigDoc->setProperty(bstr(L"SelectionNamespaces"), variant(L"xmlns:eap-metadata=\"urn:ietf:params:xml:ns:yang:ietf-eap-metadata\" xmlns:eaphostconfig=\"http://www.microsoft.com/provisioning/EapHostConfig\""));

    // Select <Config> node.
    com_obj<IXMLDOMNode> pXmlElConfig;
    if (FAILED(eapxml::select_node(pConfigDoc, bstr(L"eaphostconfig:Config"), pXmlElConfig)))
        return dwResult = g_peer.log_error(ppEapError, ERROR_NOT_FOUND, _T(__FUNCTION__) _T(" Error selecting <Config> element."));

    // Save configuration.
    pConfigDoc->setProperty(bstr(L"SelectionNamespaces"), variant(L"xmlns:eap-metadata=\"urn:ietf:params:xml:ns:yang:ietf-eap-metadata\""));
    try {
        g_peer.config_blob2xml(dwFlags, pConnectionData, dwConnectionDataSize, pConfigDoc, pXmlElConfig);
    } catch (std::exception &err) {
        dwResult = g_peer.log_error(ppEapError, err);
    } catch (...) {
        return dwResult = ERROR_INVALID_DATA;
    }

    *ppConfigDoc = pConfigDoc.detach();

    return dwResult;
}


///
/// Raises the EAP method's specific connection configuration user interface dialog on the client.
///
/// \sa [EapPeerInvokeConfigUI function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363614.aspx)
///
//_Use_decl_annotations_
DWORD WINAPI EapPeerInvokeConfigUI(
    const EAP_METHOD_TYPE *pEapType,
          HWND            hwndParent,
          DWORD           dwFlags,
          DWORD           dwConnectionDataInSize,
    const BYTE            *pConnectionDataIn,
          DWORD           *pdwConnectionDataOutSize,
          BYTE            **ppConnectionDataOut,
          EAP_ERROR       **ppEapError)
{
    UNREFERENCED_PARAMETER(dwFlags);
    DWORD dwResult = ERROR_SUCCESS;
    event_fn_auto_ret<DWORD> event_auto(g_peer.get_event_fn_auto(__FUNCTION__, dwResult));
    actctx_activator actctx(g_act_ctx);
#ifdef _DEBUG
    //Sleep(10000);
#endif

    // Initialize output parameters.
    if (pdwConnectionDataOutSize)
        *pdwConnectionDataOutSize = 0;
    if (ppConnectionDataOut)
        *ppConnectionDataOut = NULL;
    if (ppEapError)
        *ppEapError = NULL;

    // Parameter check
    if (!pEapType || !pConnectionDataIn && dwConnectionDataInSize || !pdwConnectionDataOutSize || !ppConnectionDataOut)
        return dwResult = ERROR_INVALID_PARAMETER;
    if (pEapType->eapType.type != EAPMETHOD_TYPE || pEapType->dwAuthorId != EAPMETHOD_AUTHOR_ID)
        return dwResult = ERROR_NOT_SUPPORTED;

    try {
        g_peer.invoke_config_ui(hwndParent, pConnectionDataIn, dwConnectionDataInSize, ppConnectionDataOut, pdwConnectionDataOutSize);
    } catch (std::exception &err) {
        dwResult = g_peer.log_error(ppEapError, err);
    } catch (...) {
        dwResult = ERROR_INVALID_DATA;
    }

    return dwResult;
}


///
/// Raises a custom interactive user interface dialog to obtain user identity information for the EAP method on the client.
///
/// \sa [EapPeerInvokeIdentityUI function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363615.aspx)
///
//_Use_decl_annotations_
DWORD WINAPI EapPeerInvokeIdentityUI(
    const EAP_METHOD_TYPE *pEapType,
          DWORD           dwFlags,
          HWND            hwndParent,
          DWORD           dwConnectionDataSize,
    const BYTE            *pConnectionData,
          DWORD           dwUserDataSize,
    const BYTE            *pUserData,
          DWORD           *pdwUserDataOutSize,
          BYTE            **ppUserDataOut,
          LPWSTR          *ppwszIdentity,
          EAP_ERROR       **ppEapError)
{
    DWORD dwResult = ERROR_SUCCESS;
    event_fn_auto_ret<DWORD> event_auto(g_peer.get_event_fn_auto(__FUNCTION__, dwResult));
    actctx_activator actctx(g_act_ctx);
#ifdef _DEBUG
    //Sleep(10000);
#endif

    // Initialize output parameters.
    if (pdwUserDataOutSize)
        *pdwUserDataOutSize = 0;
    if (ppUserDataOut)
        *ppUserDataOut = NULL;
    if (ppwszIdentity)
        *ppwszIdentity = NULL;
    if (ppEapError)
        *ppEapError = NULL;

    // Parameter check
    if (!pEapType || !pConnectionData && dwConnectionDataSize || !pUserData && dwUserDataSize || !pdwUserDataOutSize || !ppUserDataOut || !ppwszIdentity)
        return dwResult = ERROR_INVALID_PARAMETER;
    if (pEapType->eapType.type != EAPMETHOD_TYPE || pEapType->dwAuthorId != EAPMETHOD_AUTHOR_ID)
        return dwResult = ERROR_NOT_SUPPORTED;

    try {
        g_peer.invoke_identity_ui(hwndParent, dwFlags, pConnectionData, dwConnectionDataSize, pUserData, dwUserDataSize, ppUserDataOut, pdwUserDataOutSize, ppwszIdentity);
    } catch (std::exception &err) {
        dwResult = g_peer.log_error(ppEapError, err);
    } catch (...) {
        dwResult = ERROR_INVALID_DATA;
    }

    return dwResult;
}


///
/// Raises a custom interactive user interface dialog for the EAP method on the client.
///
/// \sa [EapPeerInvokeInteractiveUI function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363616.aspx)
///
//_Use_decl_annotations_
DWORD WINAPI EapPeerInvokeInteractiveUI(
    const EAP_METHOD_TYPE *pEapType,
          HWND            hwndParent,
          DWORD           dwUIContextDataSize,
    const BYTE            *pUIContextData,
          DWORD           *pdwDataFromInteractiveUISize,
          BYTE            **ppDataFromInteractiveUI,
          EAP_ERROR       **ppEapError)
{
    DWORD dwResult = ERROR_SUCCESS;
    event_fn_auto_ret<DWORD> event_auto(g_peer.get_event_fn_auto(__FUNCTION__, dwResult));
    actctx_activator actctx(g_act_ctx);
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
    if (!pEapType || !pUIContextData && dwUIContextDataSize || !pdwDataFromInteractiveUISize || !ppDataFromInteractiveUI)
        return dwResult = ERROR_INVALID_PARAMETER;
    if (pEapType->eapType.type != EAPMETHOD_TYPE || pEapType->dwAuthorId != EAPMETHOD_AUTHOR_ID)
        return dwResult = ERROR_NOT_SUPPORTED;

    try {
        g_peer.invoke_interactive_ui(hwndParent, pUIContextData, dwUIContextDataSize, ppDataFromInteractiveUI, pdwDataFromInteractiveUISize);
    } catch (std::exception &err) {
        dwResult = g_peer.log_error(ppEapError, err);
    } catch (...) {
        dwResult = ERROR_INVALID_DATA;
    }

    return dwResult;
}
