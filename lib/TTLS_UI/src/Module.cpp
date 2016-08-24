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
    config_connection cfg(*this);
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
    config_connection cfg(*this);
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
    config_connection cfg(*this);
    if (dwConnectionDataInSize) {
        // Load existing configuration.
        unpack(cfg, pConnectionDataIn, dwConnectionDataInSize);
    } else {
        // This is a blank network profile. Create default configuraton.
        CoCreateGuid(&(cfg.m_connection_id));

        // Start with PAP inner configuration.
        unique_ptr<config_method_ttls> cfg_method(new config_method_ttls(*this));
        cfg_method->m_inner.reset(new config_method_pap(*this));
        cfg_method->m_anonymous_identity = L"@";
        cfg_method->m_use_preshared = true;
        cfg_method->m_preshared.reset(new credentials_tls(*this));

        // Start with one method.
        config_provider cfg_provider(*this);
        cfg_provider.m_methods.push_back(std::move(cfg_method));

        // Start with one provider.
        cfg.m_providers.push_back(std::move(cfg_provider));
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
    assert(ppwszIdentity);

    // Unpack configuration.
    config_connection cfg(*this);
    unpack(cfg, pConnectionData, dwConnectionDataSize);
    if (cfg.m_providers.empty() || cfg.m_providers.front().m_methods.empty())
        throw invalid_argument(__FUNCTION__ " Configuration has no providers and/or methods.");

    // Get method configuration.
    const config_provider &cfg_prov(cfg.m_providers.front());
    config_method_ttls *cfg_method = dynamic_cast<config_method_ttls*>(cfg_prov.m_methods.front().get());
    assert(cfg_method);

#ifdef EAP_USE_NATIVE_CREDENTIAL_CACHE
    // Unpack cached credentials.
    credentials_ttls cred_in(*this);
    if (dwUserDataSize)
        unpack(cred_in, pUserData, dwUserDataSize);
#else
    UNREFERENCED_PARAMETER(pUserData);
    UNREFERENCED_PARAMETER(dwUserDataSize);
#endif

    credentials_ttls cred_out(*this);

    // Determine inner credential type.
    eap_type_t type_inner;
    if (dynamic_cast<const config_method_pap*>(cfg_method->m_inner.get())) {
        cred_out.m_inner.reset(new credentials_pap(*this));
        type_inner = eap_type_pap;
    } else {
        assert(0); // Unsupported inner authentication method type.
        type_inner = eap_type_undefined;
    }

    // Combine credentials.
    pair<eap::credentials::source_t, eap::credentials::source_t> cred_source(cred_out.combine(
#ifdef EAP_USE_NATIVE_CREDENTIAL_CACHE
        &cred_in,
#else
        NULL,
#endif
        *cfg_method,
        (dwFlags & EAP_FLAG_GUEST_ACCESS) == 0 ? cfg_prov.m_id.c_str() : NULL));

    if (dwFlags & EAP_FLAG_GUEST_ACCESS) {
        // Disable credential saving for guests.
        cfg_method->m_allow_save = false;
        cfg_method->m_inner->m_allow_save = false;
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

        // Create credentials dialog.
        wxEAPCredentialsDialog dlg(cfg_prov, &parent);
        wxTTLSCredentialsPanel *panel = new wxTTLSCredentialsPanel(cfg_prov, *cfg_method, cred_out, cfg_prov.m_id.c_str(), &dlg);
        dlg.AddContent(panel);

        // Set "Remember" checkboxes according to credential source,
        panel->m_outer_cred->SetRememberValue(cred_source.first == eap::credentials::source_storage);
        wxPAPCredentialsPanel *panel_inner_cred_pap = dynamic_cast<wxPAPCredentialsPanel*>(panel->m_inner_cred);
        if (panel_inner_cred_pap)
            panel_inner_cred_pap->SetRememberValue(cred_source.second == eap::credentials::source_storage);

        // Centre and display dialog.
        dlg.Centre(wxBOTH);
        result = dlg.ShowModal();
        if (result == wxID_OK) {
            // Write credentials to credential manager.
            if (panel->m_outer_cred->GetRememberValue()) {
                try {
                    cred_out.credentials_tls::store(cfg_prov.m_id.c_str());
                } catch (winstd::win_runtime_error &err) {
                    wxLogError(winstd::tstring_printf(_("Error writing credentials to Credential Manager: %hs (error %u)"), err.what(), err.number()).c_str());
                } catch (...) {
                    wxLogError(_("Writing credentials failed."));
                }
            }

            if (panel_inner_cred_pap && panel_inner_cred_pap->GetRememberValue()) {
                try {
                    cred_out.m_inner->store(cfg_prov.m_id.c_str());
                } catch (winstd::win_runtime_error &err) {
                    wxLogError(winstd::tstring_printf(_("Error writing credentials to Credential Manager: %hs (error %u)"), err.what(), err.number()).c_str());
                } catch (...) {
                    wxLogError(_("Writing credentials failed."));
                }
            }
        }

        wxTopLevelWindows.DeleteObject(&parent);
        parent.SetHWND((WXHWND)NULL);
    }

    // Clean-up and return.
    wxEntryCleanup();
    if (result != wxID_OK)
        throw win_runtime_error(ERROR_CANCELLED, __FUNCTION__ " Cancelled.");

    // Build our identity. ;)
    wstring identity(move(cfg_method->get_public_identity(cred_out)));
    log_event(&EAPMETHOD_TRACE_EVT_CRED_OUTER_ID1, event_data((unsigned int)eap_type_ttls), event_data(identity), event_data::blank);
    size_t size = sizeof(WCHAR)*(identity.length() + 1);
    *ppwszIdentity = (WCHAR*)alloc_memory(size);
    memcpy(*ppwszIdentity, identity.c_str(), size);

    // Pack credentials.
    pack(cred_out, ppUserDataOut, pdwUserDataOutSize);
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
