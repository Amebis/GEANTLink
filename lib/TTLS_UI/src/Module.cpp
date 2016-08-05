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

#include "StdAfx.h"


//////////////////////////////////////////////////////////////////////
// eap::peer_ttls_ui
//////////////////////////////////////////////////////////////////////

eap::peer_ttls_ui::peer_ttls_ui() : peer_ui(winstd::eap_type_ttls)
{
}


eap::config_method* eap::peer_ttls_ui::make_config_method()
{
    return new config_method_ttls(this);
}


bool eap::peer_ttls_ui::config_xml2blob(
    _In_  DWORD       dwFlags,
    _In_  IXMLDOMNode *pConfigRoot,
    _Out_ BYTE        **pConnectionDataOut,
    _Out_ DWORD       *pdwConnectionDataOutSize,
    _Out_ EAP_ERROR   **ppEapError)
{
    UNREFERENCED_PARAMETER(dwFlags);

    // Load configuration from XML.
    eap::config_providers cfg(this);
    if (!cfg.load(pConfigRoot, ppEapError))
        return false;

    // Pack configuration.
    return pack(cfg, pConnectionDataOut, pdwConnectionDataOutSize, ppEapError);
}


bool eap::peer_ttls_ui::config_blob2xml(
    _In_                                   DWORD           dwFlags,
    _In_count_(dwConnectionDataSize) const BYTE            *pConnectionData,
    _In_                                   DWORD           dwConnectionDataSize,
    _In_                                   IXMLDOMDocument *pDoc,
    _In_                                   IXMLDOMNode     *pConfigRoot,
    _Out_                                  EAP_ERROR       **ppEapError)
{
    UNREFERENCED_PARAMETER(dwFlags);

    // Unpack configuration.
    eap::config_providers cfg(this);
    if (!unpack(cfg, pConnectionData, dwConnectionDataSize, ppEapError))
        return false;

    // Save configuration to XML.
    return cfg.save(pDoc, pConfigRoot, ppEapError);
}


bool eap::peer_ttls_ui::invoke_config_ui(
    _In_                                     HWND      hwndParent,
    _In_count_(dwConnectionDataInSize) const BYTE      *pConnectionDataIn,
    _In_                                     DWORD     dwConnectionDataInSize,
    _Out_                                    BYTE      **ppConnectionDataOut,
    _Out_                                    DWORD     *pdwConnectionDataOutSize,
    _Out_                                    EAP_ERROR **ppEapError)
{
    // Unpack configuration.
    eap::config_providers cfg(this);
    if (dwConnectionDataInSize && !unpack(cfg, pConnectionDataIn, dwConnectionDataInSize, ppEapError))
        return false;

    // Initialize application.
    new wxApp();
    wxEntryStart(m_instance);

    int result;
    {
        // Create wxWidget-approved parent window.
        wxWindow parent;
        parent.SetHWND((WXHWND)hwndParent);
        parent.AdoptAttributesFromHWND();
        wxTopLevelWindows.Append(&parent);

        // Create and launch configuration dialog.
        wxEAPConfigDialog<wxTTLSConfigWindow> dlg(cfg, &parent);
        result = dlg.ShowModal();

        wxTopLevelWindows.DeleteObject(&parent);
        parent.SetHWND((WXHWND)NULL);
    }

    // Clean-up and return.
    wxEntryCleanup();
    if (result != wxID_OK) {
        *ppEapError = make_error(ERROR_CANCELLED, _T(__FUNCTION__) _T(" Cancelled."));
        return false;
    }

    // Pack new configuration.
    return pack(cfg, ppConnectionDataOut, pdwConnectionDataOutSize, ppEapError);
}


bool eap::peer_ttls_ui::invoke_identity_ui(
    _In_                                   HWND      hwndParent,
    _In_                                   DWORD     dwFlags,
    _In_count_(dwConnectionDataSize) const BYTE      *pConnectionData,
    _In_                                   DWORD     dwConnectionDataSize,
    _In_count_(dwUserDataSize)       const BYTE      *pUserData,
    _In_                                   DWORD     dwUserDataSize,
    _Out_                                  BYTE      **ppUserDataOut,
    _Out_                                  DWORD     *pdwUserDataOutSize,
    _Out_                                  LPWSTR    *ppwszIdentity,
    _Out_                                  EAP_ERROR **ppEapError)
{
    eap::config_providers cfg(this);
    if (!unpack(cfg, pConnectionData, dwConnectionDataSize, ppEapError))
        return false;
    else if (cfg.m_providers.empty() || cfg.m_providers.front().m_methods.empty()) {
        *ppEapError = make_error(ERROR_INVALID_PARAMETER, _T(__FUNCTION__) _T(" Configuration has no providers and/or methods."));
        return false;
    }

    credentials_ttls cred(this);
    if (dwUserDataSize && !unpack(cred, pUserData, dwUserDataSize, ppEapError))
        return false;

    const config_provider &cfg_prov(cfg.m_providers.front());
    config_method_ttls *cfg_method = dynamic_cast<config_method_ttls*>(cfg_prov.m_methods.front().get());
    assert(cfg_method);
    config_method_pap *cfg_inner_pap = dynamic_cast<config_method_pap*>(cfg_method->m_inner.get());

    if (dwFlags & EAP_FLAG_GUEST_ACCESS) {
        // Disable credential saving for guests.
        cfg_method->m_outer.m_allow_save = false;
        if (cfg_inner_pap)
            cfg_inner_pap->m_allow_save = false;
        else
            assert(0); // Unsupported inner authentication method type.
    }

    // Initialize application.
    new wxApp();
    wxEntryStart(m_instance);

    int result;
    {
        // Create wxWidget-approved parent window.
        wxWindow parent;
        parent.SetHWND((WXHWND)hwndParent);
        parent.AdoptAttributesFromHWND();
        wxTopLevelWindows.Append(&parent);

        // Create and launch credentials dialog.
        wxEAPCredentialsDialog dlg(cfg_prov, &parent);
        wxTTLSCredentialsPanel *panel = new wxTTLSCredentialsPanel(cfg_prov, *cfg_method, cred, cfg_prov.m_id.c_str(), &dlg);
        dlg.AddContents((wxPanel**)&panel, 1);
        dlg.Centre(wxBOTH);
        result = dlg.ShowModal();

        wxTopLevelWindows.DeleteObject(&parent);
        parent.SetHWND((WXHWND)NULL);
    }

    // Clean-up and return.
    wxEntryCleanup();
    if (result != wxID_OK) {
        *ppEapError = make_error(ERROR_CANCELLED, _T(__FUNCTION__) _T(" Cancelled."));
        return false;
    }

    // Build our identity. ;)
    std::wstring identity(std::move(cfg_method->get_public_identity(cred)));
    log_event(&EAPMETHOD_TRACE_EVT_CRED_OUTER_ID, winstd::event_data(L"TTLS"), winstd::event_data(identity), winstd::event_data::blank);
    size_t size = sizeof(WCHAR)*(identity.length() + 1);
    *ppwszIdentity = (WCHAR*)alloc_memory(size);
    memcpy(*ppwszIdentity, identity.c_str(), size);

    // Pack credentials.
    return pack(cred, ppUserDataOut, pdwUserDataOutSize, ppEapError);
}


bool eap::peer_ttls_ui::invoke_interactive_ui(
    _In_                                  HWND      hwndParent,
    _In_count_(dwUIContextDataSize) const BYTE      *pUIContextData,
    _In_                                  DWORD     dwUIContextDataSize,
    _Out_                                 BYTE      **ppDataFromInteractiveUI,
    _Out_                                 DWORD     *pdwDataFromInteractiveUISize,
    _Out_                                 EAP_ERROR **ppEapError)
{
    UNREFERENCED_PARAMETER(pUIContextData);
    UNREFERENCED_PARAMETER(dwUIContextDataSize);
    UNREFERENCED_PARAMETER(ppDataFromInteractiveUI);
    UNREFERENCED_PARAMETER(pdwDataFromInteractiveUISize);
    UNREFERENCED_PARAMETER(ppEapError);

    InitCommonControls();
    MessageBox(hwndParent, _T(PRODUCT_NAME_STR) _T(" interactive UI goes here!"), _T(PRODUCT_NAME_STR) _T(" Prompt"), MB_OK);

    return true;
}
