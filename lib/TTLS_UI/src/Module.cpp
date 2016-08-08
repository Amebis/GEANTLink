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

using namespace std;
using namespace winstd;


//////////////////////////////////////////////////////////////////////
// eap::peer_ttls_ui
//////////////////////////////////////////////////////////////////////

eap::peer_ttls_ui::peer_ttls_ui() : peer_ui(eap_type_ttls)
{
}


eap::config_method* eap::peer_ttls_ui::make_config_method()
{
    return new config_method_ttls(*this);
}


void eap::peer_ttls_ui::config_xml2blob(
    _In_    DWORD       dwFlags,
    _In_    IXMLDOMNode *pConfigRoot,
    _Inout_ BYTE        **pConnectionDataOut,
    _Inout_ DWORD       *pdwConnectionDataOutSize)
{
    UNREFERENCED_PARAMETER(dwFlags);

    // Load configuration from XML.
    config_provider_list cfg(*this);
    cfg.load(pConfigRoot);

    // Pack configuration.
    pack(cfg, pConnectionDataOut, pdwConnectionDataOutSize);
}


void eap::peer_ttls_ui::config_blob2xml(
    _In_                                   DWORD           dwFlags,
    _In_count_(dwConnectionDataSize) const BYTE            *pConnectionData,
    _In_                                   DWORD           dwConnectionDataSize,
    _In_                                   IXMLDOMDocument *pDoc,
    _In_                                   IXMLDOMNode     *pConfigRoot)
{
    UNREFERENCED_PARAMETER(dwFlags);

    // Unpack configuration.
    config_provider_list cfg(*this);
    unpack(cfg, pConnectionData, dwConnectionDataSize);

    // Save configuration to XML.
    cfg.save(pDoc, pConfigRoot);
}


void eap::peer_ttls_ui::invoke_config_ui(
    _In_                                     HWND  hwndParent,
    _In_count_(dwConnectionDataInSize) const BYTE  *pConnectionDataIn,
    _In_                                     DWORD dwConnectionDataInSize,
    _Inout_                                  BYTE  **ppConnectionDataOut,
    _Inout_                                  DWORD *pdwConnectionDataOutSize)
{
    // Unpack configuration.
    config_provider_list cfg(*this);
    if (dwConnectionDataInSize)
        unpack(cfg, pConnectionDataIn, dwConnectionDataInSize);

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
    if (result != wxID_OK)
        throw win_runtime_error(ERROR_CANCELLED, __FUNCTION__ " Cancelled.");

    // Pack new configuration.
    pack(cfg, ppConnectionDataOut, pdwConnectionDataOutSize);
}


void eap::peer_ttls_ui::invoke_identity_ui(
    _In_                                   HWND   hwndParent,
    _In_                                   DWORD  dwFlags,
    _In_count_(dwConnectionDataSize) const BYTE   *pConnectionData,
    _In_                                   DWORD  dwConnectionDataSize,
    _In_count_(dwUserDataSize)       const BYTE   *pUserData,
    _In_                                   DWORD  dwUserDataSize,
    _Inout_                                BYTE   **ppUserDataOut,
    _Inout_                                DWORD  *pdwUserDataOutSize,
    _Inout_                                LPWSTR *ppwszIdentity)
{
    config_provider_list cfg(*this);
    unpack(cfg, pConnectionData, dwConnectionDataSize);
    if (cfg.m_providers.empty() || cfg.m_providers.front().m_methods.empty())
        throw invalid_argument(__FUNCTION__ " Configuration has no providers and/or methods.");

    credentials_ttls cred(*this);
    if (dwUserDataSize)
        unpack(cred, pUserData, dwUserDataSize);

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
    if (result != wxID_OK)
        throw win_runtime_error(ERROR_CANCELLED, __FUNCTION__ " Cancelled.");

    // Build our identity. ;)
    wstring identity(move(cfg_method->get_public_identity(cred)));
    log_event(&EAPMETHOD_TRACE_EVT_CRED_OUTER_ID1, event_data((unsigned int)eap_type_ttls), event_data(identity), event_data::blank);
    size_t size = sizeof(WCHAR)*(identity.length() + 1);
    *ppwszIdentity = (WCHAR*)alloc_memory(size);
    memcpy(*ppwszIdentity, identity.c_str(), size);

    // Pack credentials.
    pack(cred, ppUserDataOut, pdwUserDataOutSize);
}


void eap::peer_ttls_ui::invoke_interactive_ui(
    _In_                                  HWND  hwndParent,
    _In_count_(dwUIContextDataSize) const BYTE  *pUIContextData,
    _In_                                  DWORD dwUIContextDataSize,
    _Inout_                               BYTE  **ppDataFromInteractiveUI,
    _Inout_                               DWORD *pdwDataFromInteractiveUISize)
{
    UNREFERENCED_PARAMETER(pUIContextData);
    UNREFERENCED_PARAMETER(dwUIContextDataSize);
    UNREFERENCED_PARAMETER(ppDataFromInteractiveUI);
    UNREFERENCED_PARAMETER(pdwDataFromInteractiveUISize);

    InitCommonControls();
    MessageBox(hwndParent, _T(PRODUCT_NAME_STR) _T(" interactive UI goes here!"), _T(PRODUCT_NAME_STR) _T(" Prompt"), MB_OK);
}
