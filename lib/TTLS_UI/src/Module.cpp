/*
    Copyright 2015-2018 Amebis
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
    wxInitializerPeer(_In_ HINSTANCE instance, _In_opt_ HWND hwndParent);

    ///
    /// Uninitialize peer
    ///
    virtual ~wxInitializerPeer();

public:
    wxWindow* m_parent;                     ///< Parent window

protected:
    static wxCriticalSection s_lock;        ///< Initialization lock
    static unsigned long s_init_ref_count;  ///< Initialization reference counter
    static wxLocale *s_locale;              ///< Locale
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
    _In_  DWORD       dwFlags,
    _In_  IXMLDOMNode *pConfigRoot,
    _Out_ BYTE        **pConnectionDataOut,
    _Out_ DWORD       *pdwConnectionDataOutSize)
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
    if (dwConnectionDataSize)
        unpack(cfg, pConnectionData, dwConnectionDataSize);

    // Save configuration to XML.
    cfg.save(pDoc, pConfigRoot);
}


void eap::peer_ttls_ui::invoke_config_ui(
    _In_                                     HWND  hwndParent,
    _In_count_(dwConnectionDataInSize) const BYTE  *pConnectionDataIn,
    _In_                                     DWORD dwConnectionDataInSize,
    _Out_                                    BYTE  **ppConnectionDataOut,
    _Out_                                    DWORD *pdwConnectionDataOutSize)
{
    // Unpack configuration.
    config_connection cfg(*this);
    if (dwConnectionDataInSize) {
        // Load existing configuration.
        unpack(cfg, pConnectionDataIn, dwConnectionDataInSize);
    } else {
        // This is a blank network profile. `cfg` is already set to defaults.
    }

    // Initialize application.
    wxInitializerPeer init(m_instance, hwndParent);

    // Create and launch configuration dialog.
    wxEAPConfigDialog<wxTTLSConfigWindow> dlg(cfg, init.m_parent);
    if (!init.m_parent) {
        FLASHWINFO fwi = { sizeof(FLASHWINFO), dlg.GetHWND(), FLASHW_ALL | FLASHW_TIMERNOFG };
        ::FlashWindowEx(&fwi);
    }
    if (dlg.ShowModal() != wxID_OK)
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
    _Out_                                  BYTE   **ppUserDataOut,
    _Out_                                  DWORD  *pdwUserDataOutSize,
    _Out_                                  LPWSTR *ppwszIdentity)
{
    static HWND volatile hWndCurrent = NULL;

    class ui_canceller
    {
    public:
        ui_canceller(_In_ HWND hWnd)
        {
            HWND hWndPrev = (HWND)InterlockedCompareExchangePointer((PVOID volatile *)&hWndCurrent, hWnd, NULL);
            if (hWndPrev) {
                PostMessage(hWndPrev, WM_CLOSE, 0, 0);
                throw win_runtime_error(ERROR_CANCELLED, __FUNCTION__ " Aborted.");
            }
        }

        ~ui_canceller()
        {
            InterlockedExchangePointer((PVOID volatile *)&hWndCurrent, NULL);
        }
    };

    assert(ppwszIdentity);

    // Unpack configuration.
    config_connection cfg(*this);
    unpack(cfg, pConnectionData, dwConnectionDataSize);

#if EAP_USE_NATIVE_CREDENTIAL_CACHE
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

    // Initialize application.
    wxInitializerPeer init(m_instance, hwndParent);

    if (cfg.m_providers.size() > 1) {
        // Multiple identity providers: User has to select one first.
        wxEAPProviderSelectDialog dlg(cfg, init.m_parent);
        ui_canceller lock(dlg.GetHWND());

        // Centre and display dialog.
        dlg.Centre(wxBOTH);
        if (!init.m_parent) {
            FLASHWINFO fwi = { sizeof(FLASHWINFO), dlg.GetHWND(), FLASHW_ALL | FLASHW_TIMERNOFG };
            ::FlashWindowEx(&fwi);
        }
        if (dlg.ShowModal() != wxID_OK)
            throw win_runtime_error(ERROR_CANCELLED, __FUNCTION__ " Cancelled.");

        cfg_prov = dlg.GetSelection();
        assert(cfg_prov);
    } else if (!cfg.m_providers.empty()) {
        // Single identity provider. No need to ask user to select one.
        cfg_prov = &cfg.m_providers.front();
    } else {
        // No identity provider. Bail out.
        throw invalid_argument(__FUNCTION__ " Configuration has no identity providers.");
    }

    // The identity provider is selected.
    assert(cfg_prov);
    cfg_method = dynamic_cast<config_method_ttls*>(cfg_prov->m_methods.front().get());
    assert(cfg_method);

    // Configure output credentials.
    cred_out.m_namespace = cfg_prov->m_namespace;
    cred_out.m_id        = cfg_prov->m_id;
    auto cred = dynamic_cast<credentials_ttls*>(cfg_method->make_credentials());
    cred_out.m_cred.reset(cred);
#if EAP_USE_NATIVE_CREDENTIAL_CACHE
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
#if EAP_USE_NATIVE_CREDENTIAL_CACHE
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
        wxEAPCredentialsDialog dlg(*cfg_prov, init.m_parent);
        ui_canceller lock(dlg.GetHWND());
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
        if (!init.m_parent) {
            FLASHWINFO fwi = { sizeof(FLASHWINFO), dlg.GetHWND(), FLASHW_ALL | FLASHW_TIMERNOFG };
            ::FlashWindowEx(&fwi);
        }
        if (dlg.ShowModal() != wxID_OK)
            throw win_runtime_error(ERROR_CANCELLED, __FUNCTION__ " Cancelled.");

        if (panel->GetRemember()) {
            // Write credentials to credential manager.
            try {
                cred->credentials_tls::store(target_name.c_str(), 0);
            } catch (winstd::win_runtime_error &err) {
                wxLogError(winstd::tstring_printf(_("Error writing credentials to Credential Manager: %hs (error %u)"), err.what(), err.number()).c_str());
            } catch (...) {
                wxLogError(_("Writing credentials failed."));
            }
        }
    }

    // Combine inner credentials.
    eap::credentials::source_t src_inner = cred->m_inner->combine(
        dwFlags,
        NULL,
#if EAP_USE_NATIVE_CREDENTIAL_CACHE
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
#if EAP_INNER_EAPHOST
        auto cfg_inner_eaphost = dynamic_cast<config_method_eaphost*>(cfg_method->m_inner.get());
        if (!cfg_inner_eaphost)
#endif
        {
            // Native inner methods. Build dialog to prompt for inner credentials.
            wxEAPCredentialsDialog dlg(*cfg_prov, init.m_parent);
            ui_canceller lock(dlg.GetHWND());
            if (eap::config_method::status_cred_begin <= cfg_method->m_inner->m_last_status && cfg_method->m_inner->m_last_status < eap::config_method::status_cred_end)
                dlg.AddContent(new wxEAPCredentialWarningPanel(*cfg_prov, cfg_method->m_inner->m_last_status, &dlg));
            wxEAPCredentialsPanelBase *panel = NULL;
            switch (cfg_method->m_inner->get_method_id()) {
                case eap_type_legacy_pap     : panel = new wxPAPCredentialsPanel     (*cfg_prov, *dynamic_cast<const eap::config_method_pap        *>(cfg_method->m_inner.get()), *dynamic_cast<eap::credentials_pass    *>(cred->m_inner.get()), &dlg, false); break;
                case eap_type_legacy_mschapv2: panel = new wxMSCHAPv2CredentialsPanel(*cfg_prov, *dynamic_cast<const eap::config_method_mschapv2   *>(cfg_method->m_inner.get()), *dynamic_cast<eap::credentials_pass    *>(cred->m_inner.get()), &dlg, false); break;
                case eap_type_mschapv2       : panel = new wxMSCHAPv2CredentialsPanel(*cfg_prov, *dynamic_cast<const eap::config_method_eapmschapv2*>(cfg_method->m_inner.get()), *dynamic_cast<eap::credentials_pass    *>(cred->m_inner.get()), &dlg, false); break;
                case eap_type_gtc            : {
                    // EAP-GTC credential prompt differes for "Challenge/Response" and "Password" authentication modes.
                    eap::credentials_identity *cred_resp;
                    eap::credentials_pass     *cred_pass;
                    if ((cred_resp = dynamic_cast<eap::credentials_identity*>(cred->m_inner.get())) != NULL)
                        panel = new wxGTCResponseCredentialsPanel(*cfg_prov, *dynamic_cast<const eap::config_method_eapgtc*>(cfg_method->m_inner.get()), *cred_resp, &dlg, false);
                    else if ((cred_pass = dynamic_cast<eap::credentials_pass*>(cred->m_inner.get())) != NULL)
                        panel = new wxGTCPasswordCredentialsPanel(*cfg_prov, *dynamic_cast<const eap::config_method_eapgtc*>(cfg_method->m_inner.get()), *cred_pass, &dlg, false);
                    else
                        wxLogError("Unsupported authentication mode.");
                    break;
                }
                default: wxLogError("Unsupported inner authentication method.");
            }
            if (!panel)
                throw invalid_argument("Invalid authentication mode");
            panel->SetRemember(src_inner == eap::credentials::source_storage);
            dlg.AddContent(panel);

            // Update dialog layout.
            dlg.Layout();
            dlg.GetSizer()->Fit(&dlg);

            // Centre and display dialog.
            dlg.Centre(wxBOTH);
            if (!init.m_parent) {
                FLASHWINFO fwi = { sizeof(FLASHWINFO), dlg.GetHWND(), FLASHW_ALL | FLASHW_TIMERNOFG };
                ::FlashWindowEx(&fwi);
            }
            if (dlg.ShowModal() != wxID_OK)
                throw win_runtime_error(ERROR_CANCELLED, __FUNCTION__ " Cancelled.");

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
#if EAP_INNER_EAPHOST
        else {
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
                &cred_data_size, get_ptr(cred_data),
                get_ptr(identity),
                get_ptr(error),
                NULL);
            if (dwResult == ERROR_SUCCESS) {
                // Inner EAP method provided credentials.
                cred_inner->m_identity = identity.get();
                BYTE *_cred_data = cred_data.get();
                cred_inner->m_cred_blob.assign(_cred_data, _cred_data + cred_data_size);
                SecureZeroMemory(_cred_data, cred_data_size);

                // TODO: If we ever choose to store EapHost credentials to Windows Credential Manager, add a "Save credentials? Yes/No" prompt here and write them to Credential Manager.
            } else if (dwResult == ERROR_CANCELLED) {
                // Not really an error.
                throw win_runtime_error(ERROR_CANCELLED, __FUNCTION__ " Cancelled.");
            } else if (error) {
                wxLogError(_("Invoking EAP identity UI failed (error %u, %s, %s)."), error->dwWinError, error->pRootCauseString, error->pRepairString);
                throw eap_runtime_error(*error  , __FUNCTION__ " EapHostPeerInvokeIdentityUI failed.");
            } else {
                wxLogError(_("Invoking EAP identity UI failed (error %u)."), dwResult);
                throw win_runtime_error(dwResult, __FUNCTION__ " EapHostPeerInvokeIdentityUI failed.");
            }
        }
#endif
    }

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
    // Unpack context data.
    config_connection cfg(*this);
    credentials_connection cred(*this, cfg);
    ui_context_ttls ctx(cfg, cred);
    unpack(ctx, pUIContextData, dwUIContextDataSize);

    // Look-up the provider.
    config_provider *cfg_prov;
    config_method_ttls *cfg_method;
    for (auto _cfg_prov = cfg.m_providers.begin(), cfg_prov_end = cfg.m_providers.end();; ++_cfg_prov) {
        if (_cfg_prov != cfg_prov_end) {
            if (cred.match(*_cfg_prov)) {
                // Matching provider found.
                if (_cfg_prov->m_methods.empty())
                    throw invalid_argument(string_printf(__FUNCTION__ " %ls provider has no methods.", _cfg_prov->get_id().c_str()));
                cfg_prov   = &*_cfg_prov;
                cfg_method = dynamic_cast<config_method_ttls*>(_cfg_prov->m_methods.front().get());
                break;
            }
        } else
            throw invalid_argument(string_printf(__FUNCTION__ " Credentials do not match to any provider within this connection configuration (provider: %ls).", cred.get_id().c_str()));
    }

#if EAP_INNER_EAPHOST
    auto cfg_inner_eaphost = dynamic_cast<config_method_eaphost*>(cfg_method->m_inner.get());
    if (!cfg_inner_eaphost)
#endif
    {
        // Initialize application.
        wxInitializerPeer init(m_instance, hwndParent);

        sanitizing_wstring
            challenge(reinterpret_cast<sanitizing_wstring::const_pointer>(ctx.m_data.data()), ctx.m_data.size()/sizeof(sanitizing_wstring::value_type)),
            response;

        // Build dialog to prompt for response.
        wxGTCResponseDialog dlg(*cfg_prov, init.m_parent);
        auto panel = new wxGTCResponsePanel(response, challenge.c_str(), &dlg);
        dlg.AddContent(panel);

        // Update dialog layout.
        dlg.Layout();
        dlg.GetSizer()->Fit(&dlg);

        // Centre and display dialog.
        dlg.Centre(wxBOTH);
        if (!init.m_parent) {
            FLASHWINFO fwi = { sizeof(FLASHWINFO), dlg.GetHWND(), FLASHW_ALL | FLASHW_TIMERNOFG };
            ::FlashWindowEx(&fwi);
        }
        if (dlg.ShowModal() != wxID_OK)
            throw win_runtime_error(ERROR_CANCELLED, __FUNCTION__ " Cancelled.");

        // Save response.
        ctx.m_data.assign(
            reinterpret_cast<sanitizing_blob::const_pointer>(response.data()                    ),
            reinterpret_cast<sanitizing_blob::const_pointer>(response.data() + response.length()));
    }
#if EAP_INNER_EAPHOST
    else {
        // EapHost inner method
        DWORD dwSizeofDataFromInteractiveUI;
        BYTE *pDataFromInteractiveUI;
        winstd::eap_error error;
        DWORD dwResult = EapHostPeerInvokeInteractiveUI(
            hwndParent,
            (DWORD)ctx.m_data.size(),
            ctx.m_data.data(),
            &dwSizeofDataFromInteractiveUI,
            &pDataFromInteractiveUI,
            get_ptr(error));
        if (dwResult == ERROR_SUCCESS) {
            // Inner EAP method provided response.
            ctx.m_data.assign(pDataFromInteractiveUI, pDataFromInteractiveUI + dwSizeofDataFromInteractiveUI);
        } else if (dwResult == ERROR_CANCELLED) {
            // Not really an error.
            throw win_runtime_error(ERROR_CANCELLED, __FUNCTION__ " Cancelled.");
        } else if (error) {
            wxLogError(_("Invoking EAP interactive UI failed (error %u, %s, %s)."), error->dwWinError, error->pRootCauseString, error->pRepairString);
            throw eap_runtime_error(*error  , __FUNCTION__ " EapHostPeerInvokeInteractiveUI failed.");
        } else {
            wxLogError(_("Invoking EAP interactive UI failed (error %u)."), dwResult);
            throw win_runtime_error(dwResult, __FUNCTION__ " EapHostPeerInvokeInteractiveUI failed.");
        }
    }
#endif

    // Pack output data.
    pack(ctx.m_data, ppDataFromInteractiveUI, pdwDataFromInteractiveUISize);
}


//////////////////////////////////////////////////////////////////////
// wxInitializerPeer
//////////////////////////////////////////////////////////////////////

wxInitializerPeer::wxInitializerPeer(_In_ HINSTANCE instance, _In_opt_ HWND hwndParent)
{
    wxCriticalSectionLocker locker(s_lock);

    if (s_init_ref_count++ == 0) {
        // Initialize application.
        new wxApp();
        wxEntryStart(instance);

        // Do our wxWidgets configuration and localization initialization.
        wxInitializeConfig();
        s_locale = new wxLocale;
        if (wxInitializeLocale(*s_locale)) {
            s_locale->AddCatalog(wxT("wxExtend") wxT(wxExtendVersion));
            s_locale->AddCatalog(wxT("EAPTTLSUI"));
        }
    }

    if (hwndParent) {
        // Create wxWidget-approved parent window.
        m_parent = new wxWindow;
        m_parent->SetHWND((WXHWND)hwndParent);
        m_parent->AdoptAttributesFromHWND();
        wxTopLevelWindows.Append(m_parent);
    } else
        m_parent = NULL;
}


wxInitializerPeer::~wxInitializerPeer()
{
    wxCriticalSectionLocker locker(s_lock);

    if (m_parent) {
        wxTopLevelWindows.DeleteObject(m_parent);
        m_parent->SetHWND((WXHWND)NULL);
    }

    if (--s_init_ref_count == 0) {
        wxEntryCleanup();

        if (s_locale) {
            delete s_locale;
            s_locale = NULL;
        }
    }
}


wxCriticalSection wxInitializerPeer::s_lock;
unsigned long wxInitializerPeer::s_init_ref_count = 0;
wxLocale *wxInitializerPeer::s_locale = NULL;
