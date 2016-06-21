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
/// EAP configuration dialog
///
template <class _Tmeth, class _wxT> class wxEAPConfigDialog;

///
/// EAP credentials dialog
///
template <class _Tprov> class wxEAPCredentialsDialog;

///
/// EAP dialog banner
///
class wxEAPBannerPanel;

///
/// EAP Provider-locked congifuration note
///
template <class _Tprov> class wxEAPProviderLocked;

///
/// Base template for credentials configuration panel
///
template <class _Tprov, class _Tmeth, class _wxT> class wxEAPCredentialsConfigPanel;

///
/// Base template for all credential panels
///
template <class _Tcred, class _Tbase> class wxCredentialsPanel;

///
/// Password credentials panel
///
template <class _Tprov> class wxPasswordCredentialsPanel;

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


template <class _Tmeth, class _wxT>
class wxEAPConfigDialog : public wxEAPConfigDialogBase
{
public:
    ///
    /// Configuration provider data type
    ///
    typedef eap::config_provider<_Tmeth> _Tprov;

    ///
    /// Configuration data type
    ///
    typedef eap::config_providers<_Tprov> config_type;

    ///
    /// This data type
    ///
    typedef wxEAPConfigDialog<_Tmeth, _wxT> _T;

public:
    ///
    /// Constructs a configuration dialog
    ///
    wxEAPConfigDialog(config_type &cfg, wxWindow* parent) :
        m_cfg(cfg),
        wxEAPConfigDialogBase(parent)
    {
        // Set extra style here, as wxFormBuilder overrides all default flags.
        this->SetExtraStyle(this->GetExtraStyle() | wxWS_EX_VALIDATE_RECURSIVELY);

        for (std::list<_Tprov>::iterator provider = m_cfg.m_providers.begin(), provider_end = m_cfg.m_providers.end(); provider != provider_end; ++provider) {
            bool is_single = provider->m_methods.size() == 1;
            std::list<_Tmeth>::size_type count = 0;
            std::list<_Tmeth>::iterator method = provider->m_methods.begin(), method_end = provider->m_methods.end();
            for (; method != method_end; ++method, count++)
                m_providers->AddPage(
                    new _wxT(
                        *provider,
                        provider->m_methods.front(),
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
            _wxT *prov = wxDynamicCast(provider->GetData(), _wxT);
            if (prov)
                prov->GetEventHandler()->ProcessEvent(event);
        }
    }
    /// \endcond


protected:
    config_type &m_cfg;  ///< EAP providers configuration
};


template <class _Tprov>
class wxEAPCredentialsDialog : public wxEAPCredentialsDialogBase
{
public:
    ///
    /// Constructs a credential dialog
    ///
    wxEAPCredentialsDialog(_Tprov &prov, wxWindow* parent) : wxEAPCredentialsDialogBase(parent)
    {
        // Set extra style here, as wxFormBuilder overrides all default flags.
        this->SetExtraStyle(this->GetExtraStyle() | wxWS_EX_VALIDATE_RECURSIVELY);

        // Set banner title.
        m_banner->m_title->SetLabel(wxString::Format(_("%s Credentials"), prov.m_id.c_str()));

        m_buttonsOK->SetDefault();
    }


    ///
    /// Adds panels to the dialog
    ///
    void AddContents(wxPanel **contents, size_t content_count)
    {
        if (content_count) {
            for (size_t i = 0; i < content_count; i++)
                m_panels->Add(contents[i], 0, wxALL|wxEXPAND, 5);

            this->Layout();
            this->GetSizer()->Fit(this);
            contents[0]->SetFocusFromKbd();
        }
    }


protected:
    /// \cond internal

    virtual void OnInitDialog(wxInitDialogEvent& event)
    {
        for (wxSizerItemList::compatibility_iterator panel = m_panels->GetChildren().GetFirst(); panel; panel = panel->GetNext())
            panel->GetData()->GetWindow()->GetEventHandler()->ProcessEvent(event);
    }

    /// \endcond
};


class wxEAPBannerPanel : public wxEAPBannerPanelBase
{
public:
    ///
    /// Constructs a banner pannel and set the title text to product name
    ///
    wxEAPBannerPanel(wxWindow* parent);

protected:
    /// \cond internal
    virtual bool AcceptsFocusFromKeyboard() const { return false; }
    /// \endcond
};


template <class _Tprov>
class wxEAPProviderLocked : public wxEAPProviderLockedBase
{
public:
    ///
    /// Constructs a notice pannel and set the title text
    ///
    wxEAPProviderLocked(_Tprov &prov, wxWindow* parent) :
        m_prov(prov),
        wxEAPProviderLockedBase(parent)
    {
        // Load and set icon.
        if (m_shell32.load(_T("shell32.dll"), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE))
            wxSetIconFromResource(m_provider_locked_icon, m_icon, m_shell32, MAKEINTRESOURCE(48));

        m_provider_locked_label->SetLabel(wxString::Format(_("%s has pre-set parts of this configuration. Those parts are locked to prevent accidental modification."),
            !m_prov.m_name.empty() ? m_prov.m_name.c_str() :
            !m_prov.m_id  .empty() ? winstd::string_printf(_("Your %ls provider"), m_prov.m_id.c_str()).c_str() : _("Your provider")));
        m_provider_locked_label->Wrap(452);

        if (!m_prov.m_help_email.empty() || !m_prov.m_help_web.empty() || !m_prov.m_help_phone.empty()) {
            wxStaticText *provider_notice = new wxStaticText(this, wxID_ANY, wxString::Format(_("For additional help and instructions, please contact %s at:"),
                !m_prov.m_name.empty() ? m_prov.m_name.c_str() :
                !m_prov.m_id  .empty() ? winstd::string_printf(_("your %ls provider"), m_prov.m_id.c_str()).c_str() : _("your provider")), wxDefaultPosition, wxDefaultSize, 0);
            provider_notice->Wrap(452);
            m_provider_locked_vert->Add(provider_notice, 0, wxUP|wxLEFT|wxRIGHT|wxEXPAND, 5);

            wxFlexGridSizer* sb_contact_tbl;
            sb_contact_tbl = new wxFlexGridSizer(0, 2, 5, 5);
            sb_contact_tbl->AddGrowableCol(1);
            sb_contact_tbl->SetFlexibleDirection(wxBOTH);
            sb_contact_tbl->SetNonFlexibleGrowMode(wxFLEX_GROWMODE_SPECIFIED);

            wxFont font_wingdings(-1, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL, false, wxT("Wingdings"));

            if (!m_prov.m_help_web.empty()) {
                wxStaticText *label = new wxStaticText(this, wxID_ANY, wxT("\xb6"), wxDefaultPosition, wxDefaultSize, 0);
                label->Wrap(-1);
                label->SetFont(font_wingdings);
                sb_contact_tbl->Add(label, 0, wxEXPAND|wxALIGN_TOP, 5);

                wxHyperlinkCtrl *value = new wxHyperlinkCtrl(this, wxID_ANY, m_prov.m_help_web, m_prov.m_help_web, wxDefaultPosition, wxDefaultSize, wxHL_DEFAULT_STYLE);
                value->SetToolTip(_("Open the default web browser"));
                sb_contact_tbl->Add(value, 0, wxEXPAND|wxALIGN_TOP, 5);
            }

            if (!m_prov.m_help_email.empty()) {
                wxStaticText *label = new wxStaticText(this, wxID_ANY, wxT("\x2a"), wxDefaultPosition, wxDefaultSize, 0);
                label->Wrap(-1);
                label->SetFont(font_wingdings);
                sb_contact_tbl->Add(label, 0, wxEXPAND|wxALIGN_TOP, 5);

                wxHyperlinkCtrl *value = new wxHyperlinkCtrl(this, wxID_ANY, m_prov.m_help_email, wxString(wxT("mailto:")) + m_prov.m_help_email, wxDefaultPosition, wxDefaultSize, wxHL_DEFAULT_STYLE);
                value->SetToolTip(_("Open your e-mail program"));
                sb_contact_tbl->Add(value, 0, wxEXPAND|wxALIGN_TOP, 5);
            }

            if (!m_prov.m_help_phone.empty()) {
                wxStaticText *label = new wxStaticText(this, wxID_ANY, wxT("\x29"), wxDefaultPosition, wxDefaultSize, 0);
                label->Wrap(-1);
                label->SetFont(font_wingdings);
                sb_contact_tbl->Add(label, 0, wxEXPAND|wxALIGN_TOP, 5);

                wxHyperlinkCtrl *value = new wxHyperlinkCtrl(this, wxID_ANY, m_prov.m_help_phone, wxString(wxT("tel:")) + GetPhoneNumber(m_prov.m_help_phone.c_str()), wxDefaultPosition, wxDefaultSize, wxHL_DEFAULT_STYLE);
                value->SetToolTip(_("Dial the phone number"));
                sb_contact_tbl->Add(value, 0, wxEXPAND|wxALIGN_TOP, 5);
            }

            m_provider_locked_vert->Add(sb_contact_tbl, 0, wxLEFT|wxRIGHT|wxDOWN|wxEXPAND, 5);
        }

        this->Layout();
    }

protected:
    /// \cond internal

    virtual bool AcceptsFocusFromKeyboard() const
    {
        return !m_prov.m_help_email.empty() || !m_prov.m_help_web.empty() || !m_prov.m_help_phone.empty();
    }

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
    _Tprov &m_prov;                             ///< EAP provider
    winstd::library m_shell32;                  ///< shell32.dll resource library reference
    wxIcon m_icon;                              ///< Panel icon
};


template <class _Tprov, class _Tmeth, class _wxT>
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
    wxEAPCredentialsConfigPanel(_Tprov &prov, _Tmeth &cfg, LPCTSTR pszCredTarget, wxWindow *parent) :
        m_prov(prov),
        m_cfg(cfg),
        m_target(pszCredTarget),
        m_cred(m_cfg.m_module),
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

        if (!m_cfg.m_use_preshared) {
            m_own->SetValue(true);
            m_cred.clear();
        } else {
            m_preshared->SetValue(true);
            m_cred = m_cfg.m_preshared;
        }

        return wxEAPCredentialsConfigPanelBase::TransferDataToWindow();
    }


    virtual bool TransferDataFromWindow()
    {
        wxCHECK(wxEAPCredentialsConfigPanelBase::TransferDataFromWindow(), false);

        if (!m_prov.m_read_only) {
            // This is not a provider-locked configuration. Save the data.
            if (m_own->GetValue()) {
                m_cfg.m_use_preshared = false;
            } else {
                m_cfg.m_use_preshared = true;
                m_cfg.m_preshared = m_cred;
            }
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
            if (CredRead(m_cred.target_name(m_target.c_str()).c_str(), CRED_TYPE_GENERIC, 0, (PCREDENTIAL*)&cred)) {
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

        m_preshared_identity->SetValue(!m_cred.empty() ? m_cred.m_identity : _("<blank>"));

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

        wxEAPCredentialsDialog<_Tprov> dlg(m_prov, this);

        _wxT *panel = new _wxT(m_prov, m_cred, m_target.c_str(), &dlg, true);

        dlg.AddContents((wxPanel**)&panel, 1);
        dlg.ShowModal();
    }


    virtual void OnClearOwn(wxCommandEvent& event)
    {
        UNREFERENCED_PARAMETER(event);

        if (!CredDelete(m_cred.target_name(m_target.c_str()).c_str(), CRED_TYPE_GENERIC, 0))
            wxLogError(_("Deleting credentials failed (error %u)."), GetLastError());
    }


    virtual void OnSetPreshared(wxCommandEvent& event)
    {
        UNREFERENCED_PARAMETER(event);

        wxEAPCredentialsDialog<_Tprov> dlg(m_prov, this);

        _wxT *panel = new _wxT(m_prov, m_cred, _T(""), &dlg, true);

        dlg.AddContents((wxPanel**)&panel, 1);
        dlg.ShowModal();
    }

    /// \endcond

protected:
    _Tprov &m_prov;                             ///< EAP provider
    _Tmeth &m_cfg;                              ///< EAP configuration
    winstd::library m_shell32;                  ///< shell32.dll resource library reference
    wxIcon m_icon;                              ///< Panel icon
    winstd::tstring m_target;                   ///< Credential Manager target

private:
    typename _Tmeth::credentials_type m_cred;   ///< Temporary credential data
};


template <class _Tcred, class _Tbase>
class wxCredentialsPanel : public _Tbase
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
    wxCredentialsPanel(_Tcred &cred, LPCTSTR pszCredTarget, wxWindow* parent, bool is_config = false) :
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
    _Tcred &m_cred;             ///< Password credentials
    winstd::tstring m_target;   ///< Credential Manager target
};


template <class _Tprov>
class wxPasswordCredentialsPanel : public wxCredentialsPanel<eap::credentials_pass, wxPasswordCredentialsPanelBase>
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
    wxPasswordCredentialsPanel(_Tprov &prov, eap::credentials_pass &cred, LPCTSTR pszCredTarget, wxWindow* parent, bool is_config = false) :
        wxCredentialsPanel<eap::credentials_pass, wxPasswordCredentialsPanelBase>(cred, pszCredTarget, parent, is_config)
    {
        // Load and set icon.
        if (m_shell32.load(_T("shell32.dll"), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE))
            wxSetIconFromResource(m_credentials_icon, m_icon, m_shell32, MAKEINTRESOURCE(269));

        bool layout = false;
        if (!prov.m_lbl_alt_credential.empty()) {
            m_credentials_label->SetLabel(prov.m_lbl_alt_credential);
            m_credentials_label->Wrap( 446 );
            layout = true;
        }

        if (!prov.m_lbl_alt_identity.empty()) {
            m_identity_label->SetLabel(prov.m_lbl_alt_identity);
            layout = true;
        }

        if (!prov.m_lbl_alt_password.empty()) {
            m_password_label->SetLabel(prov.m_lbl_alt_password);
            layout = true;
        }

        if (layout)
            this->Layout();
    }

protected:
    /// \cond internal

    virtual bool TransferDataToWindow()
    {
        // Inherited TransferDataToWindow() calls m_cred.retrieve().
        // Therefore, call it now, to set m_cred.
        wxCHECK(__super::TransferDataToWindow(), false);

        m_identity->SetValue(m_cred.m_identity);
        m_identity->SetSelection(0, -1);
        m_password->SetValue(m_cred.m_password.empty() ? wxEmptyString : s_dummy_password);

        return true;
    }


    virtual bool TransferDataFromWindow()
    {
        m_cred.m_identity = m_identity->GetValue();

        wxString pass = m_password->GetValue();
        if (pass.compare(s_dummy_password) != 0) {
            m_cred.m_password = pass;
            pass.assign(pass.length(), wxT('*'));
        }

        // Inherited TransferDataFromWindow() calls m_cred.store().
        // Therefore, call it only now, that m_cred is set.
        return __super::TransferDataFromWindow();
    }

    /// \endcond

protected:
    winstd::library m_shell32;  ///< shell32.dll resource library reference
    wxIcon m_icon;              ///< Panel icon

private:
    static const wxStringCharType *s_dummy_password;
};


template <class _Tprov>
const wxStringCharType *wxPasswordCredentialsPanel<_Tprov>::s_dummy_password = wxT("dummypass");


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
