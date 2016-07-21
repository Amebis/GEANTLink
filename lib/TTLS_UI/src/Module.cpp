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

eap::peer_ttls_ui::peer_ttls_ui() : peer_ui<eap::config_method_ttls, eap::credentials_ttls, bool, bool>(type_ttls)
{
}


bool eap::peer_ttls_ui::invoke_config_ui(
    _In_    HWND             hwndParent,
    _Inout_ config_providers &cfg,
    _Out_   EAP_ERROR        **ppEapError)
{
    UNREFERENCED_PARAMETER(ppEapError);

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

    return true;
}


bool eap::peer_ttls_ui::invoke_identity_ui(
            _In_    HWND             hwndParent,
            _In_    DWORD            dwFlags,
            _Inout_ config_providers &cfg,
            _Inout_ credentials_type &cred,
            _Out_   LPWSTR           *ppwszIdentity,
            _Out_   EAP_ERROR        **ppEapError)
{
    UNREFERENCED_PARAMETER(dwFlags);

    if (cfg.m_providers.empty() || cfg.m_providers.front().m_methods.empty()) {
        *ppEapError = make_error(ERROR_INVALID_PARAMETER, _T(__FUNCTION__) _T(" Configuration has no providers and/or methods."));
        return false;
    }

    const config_provider &cfg_prov(cfg.m_providers.front());
    const config_method_ttls *cfg_method = dynamic_cast<const config_method_ttls*>(cfg_prov.m_methods.front().get());
    assert(cfg_method);

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
        wxTTLSCredentialsPanel *panel = new wxTTLSCredentialsPanel(cfg_prov, *cfg_method, cred, cfg_prov.m_id.c_str(), &dlg, true);
        dlg.AddContents((wxPanel**)&panel, 1);
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

    return true;
}


bool eap::peer_ttls_ui::invoke_interactive_ui(
            _In_        HWND                      hwndParent,
            _In_  const interactive_request_type  &req,
            _Out_       interactive_response_type &res,
            _Out_       EAP_ERROR                 **ppEapError)
{
    UNREFERENCED_PARAMETER(req);
    UNREFERENCED_PARAMETER(res);
    UNREFERENCED_PARAMETER(ppEapError);

    InitCommonControls();
    MessageBox(hwndParent, _T(PRODUCT_NAME_STR) _T(" interactive UI goes here!"), _T(PRODUCT_NAME_STR) _T(" Prompt"), MB_OK);

    return true;
}
