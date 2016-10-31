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


///
/// Peer initializer
///
class wxInitializerPeer
{
public:
    ///
    /// Initialize peer
    ///
    wxInitializerPeer(_In_ HINSTANCE instance);

    ///
    /// Uninitialize peer
    ///
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
    return new config_method_ttls(*this, 0);
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
    config_provider *cfg_prov = NULL;
    config_method_ttls *cfg_method = NULL;

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

            if (cfg.m_providers.size() > 1) {
                // Multiple identity providers: User has to select one first.
                wxEAPProviderSelectDialog dlg(cfg, &parent);

                // Centre and display dialog.
                dlg.Centre(wxBOTH);
                if ((result = dlg.ShowModal()) == wxID_OK) {
                    cfg_prov = dlg.GetSelection();
                    assert(cfg_prov);
                }
            } else if (!cfg.m_providers.empty()) {
                // Single identity provider. No need to ask user to select one.
                result = wxID_OK;
                cfg_prov = &cfg.m_providers.front();
            } else {
                // No identity provider. Bail out.
                result = wxID_CANCEL;
            }

            if (cfg_prov) {
                // The identity provider is selected.
                cfg_method = dynamic_cast<config_method_ttls*>(cfg_prov->m_methods.front().get());
                assert(cfg_method);

                // Configure output credentials.
                cred_out.m_namespace = cfg_prov->m_namespace;
                cred_out.m_id        = cfg_prov->m_id;
                auto cred = dynamic_cast<credentials_ttls*>(cfg_method->make_credentials());
                cred_out.m_cred.reset(cred);
#ifdef EAP_USE_NATIVE_CREDENTIAL_CACHE
                bool has_cached = cred_in.m_cred && cred_in.match(*cfg_prov);
#endif

                if (dwFlags & EAP_FLAG_GUEST_ACCESS) {
                    // Disable credential saving for guests.
                    cfg_method->         m_allow_save = false;
                    cfg_method->m_inner->m_allow_save = false;
                }

                // Combine outer credentials.
                wstring target_name(std::move(cfg_prov->get_id()));
                eap::credentials::source_t src_outer = cred->credentials_tls::combine(
                    dwFlags,
                    NULL,
#ifdef EAP_USE_NATIVE_CREDENTIAL_CACHE
                    has_cached ? cred_in.m_cred.get() : NULL,
#else
                    NULL,
#endif
                    *cfg_method,
                    cfg_method->m_allow_save ? target_name.c_str() : NULL);
                if (src_outer == eap::credentials::source_unknown ||
                    src_outer != eap::credentials::source_config && eap::config_method::status_cred_begin <= cfg_method->m_last_status && cfg_method->m_last_status < eap::config_method::status_cred_end)
                {
                    // Build dialog to prompt for outer credentials.
                    wxEAPCredentialsDialog dlg(*cfg_prov, &parent);
                    if (eap::config_method::status_cred_begin <= cfg_method->m_last_status && cfg_method->m_last_status < eap::config_method::status_cred_end)
                        dlg.AddContent(new wxEAPCredentialWarningPanel(*cfg_prov, cfg_method->m_last_status, &dlg));
                    auto panel = new wxTLSCredentialsPanel(*cfg_prov, *cfg_method, *cred, &dlg, false);
                    panel->SetRemember(src_outer == eap::credentials::source_storage);
                    dlg.AddContent(panel);

                    // Update dialog layout.
                    dlg.Layout();
                    dlg.GetSizer()->Fit(&dlg);

                    // Centre and display dialog.
                    dlg.Centre(wxBOTH);
                    if ((result = dlg.ShowModal()) == wxID_OK) {
                        // Write credentials to credential manager.
                        if (panel->GetRemember()) {
                            try {
                                cred->credentials_tls::store(target_name.c_str(), 0);
                            } catch (winstd::win_runtime_error &err) {
                                wxLogError(winstd::tstring_printf(_("Error writing credentials to Credential Manager: %hs (error %u)"), err.what(), err.number()).c_str());
                            } catch (...) {
                                wxLogError(_("Writing credentials failed."));
                            }
                        }
                    }
                } else
                    result = wxID_OK;

                if (result == wxID_OK) {
                    // Combine inner credentials.
                    eap::credentials::source_t src_inner = cred->m_inner->combine(
                        dwFlags,
                        NULL,
#ifdef EAP_USE_NATIVE_CREDENTIAL_CACHE
                        has_cached ? dynamic_cast<credentials_ttls*>(cred_in.m_cred.get())->m_inner.get() : NULL,
#else
                        NULL,
#endif
                        *cfg_method->m_inner,
                        cfg_method->m_inner->m_allow_save ? target_name.c_str() : NULL);
                    if (src_inner == eap::credentials::source_unknown ||
                        src_inner != eap::credentials::source_config && eap::config_method::status_cred_begin <= cfg_method->m_inner->m_last_status && cfg_method->m_inner->m_last_status < eap::config_method::status_cred_end)
                    {
                        // Prompt for inner credentials.
                        auto cfg_inner_eaphost = dynamic_cast<config_method_eaphost*>(cfg_method->m_inner.get());
                        if (!cfg_inner_eaphost) {
                            // Native inner methods. Build dialog to prompt for inner credentials.
                            wxEAPCredentialsDialog dlg(*cfg_prov, &parent);
                            if (eap::config_method::status_cred_begin <= cfg_method->m_inner->m_last_status && cfg_method->m_inner->m_last_status < eap::config_method::status_cred_end)
                                dlg.AddContent(new wxEAPCredentialWarningPanel(*cfg_prov, cfg_method->m_inner->m_last_status, &dlg));
                            wxEAPCredentialsPanelBase *panel = NULL;
                            const eap::config_method_pap      *cfg_inner_pap;
                            const eap::config_method_mschapv2 *cfg_inner_mschapv2;
                            if ((cfg_inner_pap = dynamic_cast<const eap::config_method_pap*>(cfg_method->m_inner.get())) != NULL)
                                panel = new wxPAPCredentialsPanel(*cfg_prov, *cfg_inner_pap, *dynamic_cast<eap::credentials_pass*>(cred->m_inner.get()), &dlg, false);
                            else if ((cfg_inner_mschapv2 = dynamic_cast<const eap::config_method_mschapv2*>(cfg_method->m_inner.get())) != NULL)
                                panel = new wxMSCHAPv2CredentialsPanel(*cfg_prov, *cfg_inner_mschapv2, *dynamic_cast<eap::credentials_pass*>(cred->m_inner.get()), &dlg, false);
                            else
                                assert(0); // Unsupported inner authentication method type.
                            panel->SetRemember(src_inner == eap::credentials::source_storage);
                            dlg.AddContent(panel);

                            // Update dialog layout.
                            dlg.Layout();
                            dlg.GetSizer()->Fit(&dlg);

                            // Centre and display dialog.
                            dlg.Centre(wxBOTH);
                            if ((result = dlg.ShowModal()) == wxID_OK) {
                                // Write credentials to credential manager.
                                if (panel->GetRemember()) {
                                    try {
                                        cred->m_inner->store(target_name.c_str(), 1);
                                    } catch (winstd::win_runtime_error &err) {
                                        wxLogError(winstd::tstring_printf(_("Error writing credentials to Credential Manager: %hs (error %u)"), err.what(), err.number()).c_str());
                                    } catch (...) {
                                        wxLogError(_("Writing credentials failed."));
                                    }
                                }
                            }
                        } else {
                            // EapHost inner method
                            auto cred_inner = dynamic_cast<eap::credentials_eaphost*>(cred->m_inner.get());
                            DWORD cred_data_size = 0;
                            winstd::eap_blob cred_data;
                            unique_ptr<WCHAR[], EapHostPeerFreeMemory_delete> identity;
                            winstd::eap_error error;
                            DWORD dwResult = EapHostPeerInvokeIdentityUI(
                                0,
                                cfg_inner_eaphost->get_type(),
                                dwFlags,
                                hwndParent,
                                (DWORD)cfg_inner_eaphost->m_cfg_blob.size(), cfg_inner_eaphost->m_cfg_blob.data(),
                                (DWORD)cred_inner->m_cred_blob.size(), cred_inner->m_cred_blob.data(),
                                &cred_data_size, &cred_data._Myptr,
                                &identity._Myptr,
                                &error._Myptr,
                                NULL);
                            if (dwResult == ERROR_SUCCESS) {
                                // Inner EAP method provided credentials.
                                cred_inner->m_identity = identity.get();
                                cred_inner->m_cred_blob.assign(cred_data.get(), cred_data.get() + cred_data_size);
                                SecureZeroMemory(cred_data.get(), cred_data_size);
                            } else if (dwResult == ERROR_CANCELLED) {
                                // Not really an error.
                                result = wxID_CANCEL;
                            } else if (error)
                                wxLogError(_("Invoking EAP identity failed (error %u, %s, %s)."), error->dwWinError, error->pRootCauseString, error->pRepairString);
                            else
                                wxLogError(_("Invoking EAP identity failed (error %u)."), dwResult);
                        }
                    } else
                        result = wxID_OK;
                }
            }

            wxTopLevelWindows.DeleteObject(&parent);
            parent.SetHWND((WXHWND)NULL);
        }
    }

    if (result != wxID_OK)
        throw win_runtime_error(ERROR_CANCELLED, __FUNCTION__ " Cancelled.");

    // Build our identity. ;)
    wstring identity(std::move(cfg_method->get_public_identity(*dynamic_cast<const credentials_ttls*>(cred_out.m_cred.get()))));
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
        s_locale.AddCatalog(wxT("wxExtend") wxT(wxExtendVersion));
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
