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
// wxInitializerPeer
//////////////////////////////////////////////////////////////////////

class wxInitializerPeer
{
public:
    wxInitializerPeer(_In_ HINSTANCE instance);
    virtual ~wxInitializerPeer();

protected:
    static wxCriticalSection s_lock;        ///< Initialization lock
    static unsigned long s_init_ref_count;  ///< Initialization reference counter
    static wxLocale s_locale;               ///< Locale
};


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
        // This is a blank network profile. `cfg` is already set to defaults.
    }

    int result;
    {
        // Initialize application.
        wxInitializerPeer init(m_instance);

        {
            // Create wxWidget-approved parent window.
            wxWindow parent;
            parent.SetHWND((WXHWND)(hwndParent ? hwndParent : GetForegroundWindow()));
            parent.AdoptAttributesFromHWND();
            wxTopLevelWindows.Append(&parent);

            // Create and launch configuration dialog.
            wxEAPConfigDialog<wxTTLSConfigWindow> dlg(cfg, &parent);
            result = dlg.ShowModal();

            wxTopLevelWindows.DeleteObject(&parent);
            parent.SetHWND((WXHWND)NULL);
        }
    }

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

#ifdef EAP_USE_NATIVE_CREDENTIAL_CACHE
    // Unpack cached credentials.
    credentials_connection cred_in(*this, cfg);
    if (dwUserDataSize)
        unpack(cred_in, pUserData, dwUserDataSize);
#else
    UNREFERENCED_PARAMETER(pUserData);
    UNREFERENCED_PARAMETER(dwUserDataSize);
#endif

    credentials_connection cred_out(*this, cfg);
    config_method_ttls *cfg_method = NULL;

    vector<pair<config_method_ttls*, credentials_connection> > cred_method_store;
    cred_method_store.reserve(cfg.m_providers.size());

    int result;
    {
        // Initialize application.
        wxInitializerPeer init(m_instance);

        {
            // Create wxWidget-approved parent window.
            wxWindow parent;
            parent.SetHWND((WXHWND)(hwndParent ? hwndParent : GetForegroundWindow()));
            parent.AdoptAttributesFromHWND();
            wxTopLevelWindows.Append(&parent);

            // Create credentials dialog and populate it with providers.
            bool combined = false;
            wxEAPCredentialsConnectionDialog dlg(&parent);
            for (config_connection::provider_list::iterator cfg_prov = cfg.m_providers.begin(), cfg_prov_end = cfg.m_providers.end(); cfg_prov != cfg_prov_end; ++cfg_prov) {
                // Get method configuration.
                if (cfg_prov->m_methods.empty()) {
                    log_event(&EAPMETHOD_TRACE_EVT_CRED_NO_METHOD, event_data(cfg_prov->m_id), event_data::blank);
                    continue;
                }
                config_method_ttls *cfg_method = dynamic_cast<config_method_ttls*>(cfg_prov->m_methods.front().get());
                assert(cfg_method);

                // Prepare new set of credentials for given provider.
                credentials_connection cred_method(*this, cfg);
                cred_method.m_id = cfg_prov->m_id;
                credentials_ttls *_cred_method = (credentials_ttls*)cfg_method->make_credentials();
                cred_method.m_cred.reset(_cred_method);
#ifdef EAP_USE_NATIVE_CREDENTIAL_CACHE
                bool is_own = cred_in.m_cred && _wcsicmp(cred_in.m_id.c_str(), cfg_prov->m_id.c_str()) == 0;
#endif

                // Combine outer credentials.
                LPCTSTR target_name = (dwFlags & EAP_FLAG_GUEST_ACCESS) == 0 ? cfg_prov->m_id.c_str() : NULL;
                eap::credentials::source_t src_outer = _cred_method->credentials_tls::combine(
#ifdef EAP_USE_NATIVE_CREDENTIAL_CACHE
                    is_own ? cred_in.m_cred.get() : NULL,
#else
                    NULL,
#endif
                    *cfg_method,
                    target_name);

                // Combine inner credentials.
                eap::credentials::source_t src_inner = _cred_method->m_inner->combine(
#ifdef EAP_USE_NATIVE_CREDENTIAL_CACHE
                    is_own ? ((credentials_ttls*)cred_in.m_cred.get())->m_inner.get() : NULL,
#else
                    NULL,
#endif
                    *cfg_method->m_inner,
                    target_name);

                if (dwFlags & EAP_FLAG_GUEST_ACCESS) {
                    // Disable credential saving for guests.
                    cfg_method->m_allow_save = false;
                    cfg_method->m_inner->m_allow_save = false;
                }

                // Create method credentials panel.
                wxTTLSCredentialsPanel *panel = new wxTTLSCredentialsPanel(*cfg_prov, *cfg_method, *_cred_method, cfg_prov->m_id.c_str(), dlg.m_providers);

                // Set "Remember" checkboxes according to credential source,
                panel->m_outer_cred->SetRemember(src_outer == eap::credentials::source_storage);
                panel->m_inner_cred->SetRemember(src_inner == eap::credentials::source_storage);

                // Add panel to choice-book. Select the first one to have known sources.
                if (!combined && src_outer != eap::credentials::source_unknown && src_inner != eap::credentials::source_unknown) {
                    if (dlg.m_providers->AddPage(panel, wxEAPGetProviderName(cfg_prov->m_name), true)) {
                        cred_method_store.push_back(pair<config_method_ttls*, credentials_connection>(cfg_method, std::move(cred_method)));
                        combined = true;
                    }
                } else
                    if (dlg.m_providers->AddPage(panel, wxEAPGetProviderName(cfg_prov->m_name), false))
                        cred_method_store.push_back(pair<config_method_ttls*, credentials_connection>(cfg_method, std::move(cred_method)));
            }

            // Update dialog layout.
            dlg.Layout();
            dlg.GetSizer()->Fit(&dlg);

            // Centre and display dialog.
            dlg.Centre(wxBOTH);
            result = dlg.ShowModal();
            if (result == wxID_OK) {
                int idx_prov = dlg.m_providers->GetSelection();
                if (idx_prov != wxNOT_FOUND) {
                    wxTTLSCredentialsPanel *panel = dynamic_cast<wxTTLSCredentialsPanel*>(dlg.m_providers->GetPage(idx_prov));
                    pair<config_method_ttls*, credentials_connection> &res = cred_method_store[idx_prov];
                    cfg_method = res.first;
                    cred_out = res.second;
                    credentials_ttls *_cred_out = dynamic_cast<credentials_ttls*>(cred_out.m_cred.get());

                    // Write credentials to credential manager.
                    if (panel->m_outer_cred->GetRemember()) {
                        try {
                            _cred_out->credentials_tls::store(cred_out.m_id.c_str());
                        } catch (winstd::win_runtime_error &err) {
                            wxLogError(winstd::tstring_printf(_("Error writing credentials to Credential Manager: %hs (error %u)"), err.what(), err.number()).c_str());
                        } catch (...) {
                            wxLogError(_("Writing credentials failed."));
                        }
                    }

                    if (panel->m_inner_cred->GetRemember()) {
                        try {
                            _cred_out->m_inner->store(cred_out.m_id.c_str());
                        } catch (winstd::win_runtime_error &err) {
                            wxLogError(winstd::tstring_printf(_("Error writing credentials to Credential Manager: %hs (error %u)"), err.what(), err.number()).c_str());
                        } catch (...) {
                            wxLogError(_("Writing credentials failed."));
                        }
                    }
                } else
                    result = wxID_CANCEL;
            }

            wxTopLevelWindows.DeleteObject(&parent);
            parent.SetHWND((WXHWND)NULL);
        }
    }

    if (result != wxID_OK)
        throw win_runtime_error(ERROR_CANCELLED, __FUNCTION__ " Cancelled.");

    // Build our identity. ;)
    wstring identity(std::move(cfg_method->get_public_identity((const credentials_ttls&)*cred_out.m_cred)));
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


//////////////////////////////////////////////////////////////////////
// wxInitializerPeer
//////////////////////////////////////////////////////////////////////

wxInitializerPeer::wxInitializerPeer(_In_ HINSTANCE instance)
{
    wxCriticalSectionLocker locker(s_lock);
    if (s_init_ref_count++)
        return;

    // Initialize application.
    new wxApp();
    wxEntryStart(instance);

    // Do our wxWidgets configuration and localization initialization.
    wxInitializeConfig();
    if (wxInitializeLocale(s_locale)) {
        //s_locale.AddCatalog(wxT("wxExtend") wxT(wxExtendVersion));
        s_locale.AddCatalog(wxT("EAPTTLSUI"));
    }
}


wxInitializerPeer::~wxInitializerPeer()
{
    wxCriticalSectionLocker locker(s_lock);
    if (--s_init_ref_count)
        return;

    wxEntryCleanup();
}


wxCriticalSection wxInitializerPeer::s_lock;
unsigned long wxInitializerPeer::s_init_ref_count = 0;
wxLocale wxInitializerPeer::s_locale;
