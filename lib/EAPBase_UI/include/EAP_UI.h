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

#include <wx/hyperlink.h>
#include <wx/icon.h>
#include <wx/statbmp.h>
#include <Windows.h>


///
/// Reusable EAP dialog banner for `wxEAPConfigDialog` and `wxEAPCredentialsDialog`
///
class wxEAPBannerPanel;

///
/// EAP top-most configuration dialog
///
template <class _wxT> class wxEAPConfigDialog;

///
/// EAP top-most credential dialog
///
class wxEAPCredentialsDialog;

///
/// EAP Provider-locked congifuration note
///
class wxEAPProviderLockedPanel;

///
/// Base template for credential configuration panel
///
template <class _wxT> class wxEAPCredentialsConfigPanel;

///
/// Base template for all credential entry panels
///
template <class _Tbase> class wxEAPCredentialsPanelBase;

///
/// Generic password credential entry panel
///
class wxPasswordCredentialsPanel;

///
/// Sets icon from resource
///
inline bool wxSetIconFromResource(wxStaticBitmap *bmp, wxIcon &icon, HINSTANCE hinst, PCWSTR pszName);

#pragma once

#include <wx/msw/winundef.h> // Fixes `CreateDialog` name collision
#include "../res/wxEAP_UI.h"

#include "../../EAPBase/include/Config.h"
#include "../../EAPBase/include/Credentials.h"

#include <WinStd/Common.h>
#include <WinStd/Cred.h>
#include <WinStd/Win.h>

#include <wx/log.h>

#include <CommCtrl.h>

#include <list>
#include <memory>


class wxEAPBannerPanel : public wxEAPBannerPanelBase
{
public:
    ///
    /// Constructs a banner pannel and set the title text to product name
    ///
    wxEAPBannerPanel(wxWindow* parent);

protected:
    /// \cond internal
    virtual bool AcceptsFocusFromKeyboard() const;
    /// \endcond
};


template <class _wxT>
class wxEAPConfigDialog : public wxEAPConfigDialogBase
{
public:
    ///
    /// Constructs a configuration dialog
    ///
    wxEAPConfigDialog(eap::config_providers &cfg, wxWindow* parent) :
        m_cfg(cfg),
        wxEAPConfigDialogBase(parent)
    {
        // Set extra style here, as wxFormBuilder overrides all default flags.
        this->SetExtraStyle(this->GetExtraStyle() | wxWS_EX_VALIDATE_RECURSIVELY);

        for (std::list<eap::config_provider>::iterator provider = m_cfg.m_providers.begin(), provider_end = m_cfg.m_providers.end(); provider != provider_end; ++provider) {
            bool is_single = provider->m_methods.size() == 1;
            std::list<std::unique_ptr<eap::config_method> >::size_type count = 0;
            std::list<std::unique_ptr<eap::config_method> >::iterator method = provider->m_methods.begin(), method_end = provider->m_methods.end();
            for (; method != method_end; ++method, count++)
                m_providers->AddPage(
                    new _wxT(
                        *provider,
                        *method->get(),
                        provider->m_id.c_str(),
                        m_providers),
                    is_single ? provider->m_id : winstd::tstring_printf(_T("%s (%u)"), provider->m_id.c_str(), count));
        }

        this->Layout();
        this->GetSizer()->Fit(this);

        m_buttonsOK->SetDefault();
    }


protected:
    /// \cond internal
    virtual void OnInitDialog(wxInitDialogEvent& event)
    {
        // Forward the event to child panels.
        for (wxWindowList::compatibility_iterator provider = m_providers->GetChildren().GetFirst(); provider; provider = provider->GetNext()) {
            wxWindow *prov = wxDynamicCast(provider->GetData(), wxWindow);
            if (prov)
                prov->GetEventHandler()->ProcessEvent(event);
        }
    }
    /// \endcond


protected:
    eap::config_providers &m_cfg;  ///< EAP providers configuration
};


class wxEAPCredentialsDialog : public wxEAPCredentialsDialogBase
{
public:
    ///
    /// Constructs a credential dialog
    ///
    wxEAPCredentialsDialog(const eap::config_provider &prov, wxWindow* parent);

    ///
    /// Adds panels to the dialog
    ///
    void AddContents(wxPanel **contents, size_t content_count);

protected:
    /// \cond internal
    virtual void OnInitDialog(wxInitDialogEvent& event);
    /// \endcond
};


class wxEAPProviderLockedPanel : public wxEAPProviderLockedPanelBase
{
public:
    ///
    /// Constructs a notice pannel and set the title text
    ///
    wxEAPProviderLockedPanel(const eap::config_provider &prov, wxWindow* parent);

protected:
    /// \cond internal

    virtual bool AcceptsFocusFromKeyboard() const;

    template<class _Elem, class _Traits, class _Ax>
    static std::basic_string<_Elem, _Traits, _Ax> GetPhoneNumber(_In_z_ const _Elem *num)
    {
        assert(num);

        std::basic_string<_Elem, _Traits, _Ax> str;
        for (; *num; num++) {
            _Elem c = *num;
            if ('0' <= c && c <= '9' || c == '+' || c == '*' || c == '#')
                str += c;
        }

        return str;
    }

    template<class _Elem>
    static std::basic_string<_Elem, std::char_traits<_Elem>, std::allocator<_Elem> > GetPhoneNumber(_In_z_ const _Elem *num)
    {
        return GetPhoneNumber<_Elem, std::char_traits<_Elem>, std::allocator<_Elem> >(num);
    }

    /// \endcond

protected:
    const eap::config_provider &m_prov; ///< EAP provider
    winstd::library m_shell32;          ///< shell32.dll resource library reference
    wxIcon m_icon;                      ///< Panel icon
};


template <class _wxT>
class wxEAPCredentialsConfigPanel : public wxEAPCredentialsConfigPanelBase
{
public:
    ///
    /// Constructs a credential configuration panel
    ///
    /// \param[inout] prov           Provider configuration data
    /// \param[inout] cfg            Configuration data
    /// \param[in]    pszCredTarget  Target name of credentials in Windows Credential Manager. Can be further decorated to create final target name.
    /// \param[in]    parent         Parent window
    ///
    wxEAPCredentialsConfigPanel(const eap::config_provider &prov, eap::config_method &cfg, LPCTSTR pszCredTarget, wxWindow *parent) :
        m_prov(prov),
        m_cfg(cfg),
        m_target(pszCredTarget),
        m_cred(cfg.make_credentials()),
        wxEAPCredentialsConfigPanelBase(parent)
    {
        // Load and set icon.
        if (m_shell32.load(_T("shell32.dll"), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE))
            wxSetIconFromResource(m_credentials_icon, m_icon, m_shell32, MAKEINTRESOURCE(/*16770*/269));
    }

protected:
    /// \cond internal

    virtual bool TransferDataToWindow()
    {
        if (m_prov.m_read_only) {
            // This is provider-locked configuration. Disable controls.
            m_own               ->Enable(false);
            m_preshared         ->Enable(false);
            m_preshared_identity->Enable(false);
            m_preshared_set     ->Enable(false);
        }

        if (!m_cfg.m_preshared) {
            m_own->SetValue(true);
        } else {
            m_preshared->SetValue(true);
            m_cred.reset((eap::credentials*)m_cfg.m_preshared->clone());
        }

        return wxEAPCredentialsConfigPanelBase::TransferDataToWindow();
    }


    virtual bool TransferDataFromWindow()
    {
        wxCHECK(wxEAPCredentialsConfigPanelBase::TransferDataFromWindow(), false);

        if (!m_prov.m_read_only) {
            // This is not a provider-locked configuration. Save the data.
            m_cfg.m_preshared.reset(m_own->GetValue() ? nullptr : (eap::credentials*)m_cred->clone());
        }

        return true;
    }


    virtual void OnUpdateUI(wxUpdateUIEvent& event)
    {
        UNREFERENCED_PARAMETER(event);
        DWORD dwResult;

        if (m_cfg.m_allow_save) {
            bool has_own;
            std::unique_ptr<CREDENTIAL, winstd::CredFree_delete<CREDENTIAL> > cred;
            if (CredRead(m_cred->target_name(m_target.c_str()).c_str(), CRED_TYPE_GENERIC, 0, (PCREDENTIAL*)&cred)) {
                m_own_identity->SetValue(cred->UserName && cred->UserName[0] != 0 ? cred->UserName : _("<blank>"));
                has_own = true;
            } else if ((dwResult = GetLastError()) == ERROR_NOT_FOUND) {
                m_own_identity->Clear();
                has_own = false;
            } else {
                m_own_identity->SetValue(wxString::Format(_("<error %u>"), dwResult));
                has_own = true;
            }

            if (m_own->GetValue()) {
                m_own_identity->Enable(true);
                m_own_set     ->Enable(true);
                m_own_clear   ->Enable(has_own);
            } else {
                m_own_identity->Enable(false);
                m_own_set     ->Enable(false);
                m_own_clear   ->Enable(false);
            }
        } else {
            m_own_identity->Clear();

            m_own_identity->Enable(false);
            m_own_set     ->Enable(false);
            m_own_clear   ->Enable(false);
        }

        m_preshared_identity->SetValue(!m_cred->empty() ? m_cred->get_name() : _("<blank>"));

        if (!m_prov.m_read_only) {
            // This is not a provider-locked configuration. Selectively enable/disable controls.
            if (m_own->GetValue()) {
                m_preshared_identity->Enable(false);
                m_preshared_set     ->Enable(false);
            } else {
                m_preshared_identity->Enable(true);
                m_preshared_set     ->Enable(true);
            }
        }
    }


    virtual void OnSetOwn(wxCommandEvent& event)
    {
        UNREFERENCED_PARAMETER(event);

        wxEAPCredentialsDialog dlg(m_prov, this);

        _wxT *panel = new _wxT(m_prov, *m_cred, m_target.c_str(), &dlg, true);

        dlg.AddContents((wxPanel**)&panel, 1);
        dlg.ShowModal();
    }


    virtual void OnClearOwn(wxCommandEvent& event)
    {
        UNREFERENCED_PARAMETER(event);

        if (!CredDelete(m_cred->target_name(m_target.c_str()).c_str(), CRED_TYPE_GENERIC, 0))
            wxLogError(_("Deleting credentials failed (error %u)."), GetLastError());
    }


    virtual void OnSetPreshared(wxCommandEvent& event)
    {
        UNREFERENCED_PARAMETER(event);

        wxEAPCredentialsDialog dlg(m_prov, this);

        _wxT *panel = new _wxT(m_prov, *m_cred, _T(""), &dlg, true);

        dlg.AddContents((wxPanel**)&panel, 1);
        dlg.ShowModal();
    }

    /// \endcond

protected:
    const eap::config_provider &m_prov;         ///< EAP provider
    eap::config_method &m_cfg;                  ///< EAP method configuration
    winstd::library m_shell32;                  ///< shell32.dll resource library reference
    wxIcon m_icon;                              ///< Panel icon
    winstd::tstring m_target;                   ///< Credential Manager target

private:
    std::unique_ptr<eap::credentials> m_cred;   ///< Temporary credential data
};


template <class _Tbase>
class wxEAPCredentialsPanelBase : public _Tbase
{
public:
    ///
    /// Constructs a credentials panel
    ///
    /// \param[inout] cred           Credentials data
    /// \param[in]    pszCredTarget  Target name of credentials in Windows Credential Manager. Can be further decorated to create final target name.
    /// \param[in]    parent         Parent window
    /// \param[in]    is_config      Is this panel used to pre-enter credentials? When \c true, the "Remember" checkbox is always selected and disabled.
    ///
    wxEAPCredentialsPanelBase(eap::credentials &cred, LPCTSTR pszCredTarget, wxWindow* parent, bool is_config = false) :
        m_cred(cred),
        m_target(pszCredTarget),
        _Tbase(parent)
    {
        if (m_target.empty() || is_config) {
            // No Credential Manager, or user is setting credentials via configuration UI.
            // => Pointless if not stored to Credential Manager
            m_remember->SetValue(true);
            m_remember->Enable(false);
        }
    }

protected:
    /// \cond internal

    virtual bool TransferDataToWindow()
    {
        if (!m_target.empty()) {
            // Read credentials from Credential Manager
            EAP_ERROR *pEapError;
            if (m_cred.retrieve(m_target.c_str(), &pEapError)) {
                m_remember->SetValue(true);
            } else if (pEapError) {
                if (pEapError->dwWinError != ERROR_NOT_FOUND)
                    wxLogError(winstd::tstring_printf(_("Error reading credentials from Credential Manager: %ls (error %u)"), pEapError->pRootCauseString, pEapError->dwWinError).c_str());
                m_cred.m_module.free_error_memory(pEapError);
            } else
                wxLogError(_("Reading credentials failed."));
        }

        return _Tbase::TransferDataToWindow();
    }


    virtual bool TransferDataFromWindow()
    {
        wxCHECK(_Tbase::TransferDataFromWindow(), false);

        if (!m_target.empty()) {
            // Write credentials to credential manager.
            if (m_remember->GetValue()) {
                EAP_ERROR *pEapError;
                if (!m_cred.store(m_target.c_str(), &pEapError)) {
                    if (pEapError) {
                        wxLogError(winstd::tstring_printf(_("Error writing credentials to Credential Manager: %ls (error %u)"), pEapError->pRootCauseString, pEapError->dwWinError).c_str());
                        m_cred.m_module.free_error_memory(pEapError);
                    } else
                        wxLogError(_("Writing credentials failed."));
                }
            }
        }

        return true;
    }

    /// \endcond

protected:
    eap::credentials &m_cred;   ///< Generic credentials
    winstd::tstring m_target;   ///< Credential Manager target
};


class wxPasswordCredentialsPanel : public wxEAPCredentialsPanelBase<wxEAPCredentialsPanelPassBase>
{
public:
    ///
    /// Constructs a password credentials panel
    ///
    /// \param[inout] prov           EAP provider
    /// \param[inout] cred           Credentials data
    /// \param[in]    pszCredTarget  Target name of credentials in Windows Credential Manager. Can be further decorated to create final target name.
    /// \param[in]    parent         Parent window
    /// \param[in]    is_config      Is this panel used to pre-enter credentials? When \c true, the "Remember" checkbox is always selected and disabled.
    ///
    wxPasswordCredentialsPanel(const eap::config_provider &prov, eap::credentials &cred, LPCTSTR pszCredTarget, wxWindow* parent, bool is_config = false);

protected:
    /// \cond internal
    virtual bool TransferDataToWindow();
    virtual bool TransferDataFromWindow();
    /// \endcond

protected:
    eap::credentials_pass &m_cred;  ///< Password credentials
    winstd::library m_shell32;      ///< shell32.dll resource library reference
    wxIcon m_icon;                  ///< Panel icon

private:
    static const wxStringCharType *s_dummy_password;
};


inline bool wxSetIconFromResource(wxStaticBitmap *bmp, wxIcon &icon, HINSTANCE hinst, PCWSTR pszName)
{
    wxASSERT(bmp);

    HICON hIcon;
    if (SUCCEEDED(LoadIconWithScaleDown(hinst, pszName, GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON), &hIcon))) {
        icon.CreateFromHICON(hIcon);
        bmp->SetIcon(icon);
        return true;
    } else
        return false;
}
