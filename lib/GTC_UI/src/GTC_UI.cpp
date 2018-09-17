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
// wxGTCConfigPanel
//////////////////////////////////////////////////////////////////////

wxGTCConfigPanel::wxGTCConfigPanel(const eap::config_provider &prov, eap::config_method_eapgtc &cfg, wxWindow* parent) :
    m_prov    (prov                     ),
    m_cfg     (cfg                      ),
    m_cfg_resp(cfg.m_module, cfg.m_level),
    m_cfg_pass(cfg.m_module, cfg.m_level),
    wxGTCConfigPanelBase(parent)
{
    // Initialize Password authentication mode properly. Challenge/Response mode does not require initialization, since it is initialized so by default.
    m_cfg_pass.m_cred.reset(new eap::credentials_pass(m_cfg.m_module));

    m_credentials_resp = new wxGTCResponseCredentialsConfigPanel(m_prov, m_cfg_resp, m_auth_mode);
    m_auth_mode->AddPage(m_credentials_resp, _("Challenge/Response"));
    m_credentials_pass = new wxGTCPasswordCredentialsConfigPanel(m_prov, m_cfg_pass, m_auth_mode);
    m_auth_mode->AddPage(m_credentials_pass, _("Password"));
}


/// \cond internal

bool wxGTCConfigPanel::TransferDataToWindow()
{
    eap::credentials_identity *cred_resp;
    eap::credentials_pass     *cred_pass;

    if ((cred_resp = dynamic_cast<eap::credentials_identity*>(m_cfg.m_cred.get())) != NULL) {
        m_cfg_resp = m_cfg;
        m_auth_mode->SetSelection(0); // 0=Challenge/Response
    } else if ((cred_pass = dynamic_cast<eap::credentials_pass*>(m_cfg.m_cred.get())) != NULL) {
        m_cfg_pass = m_cfg;
        m_auth_mode->SetSelection(1); // 1=Password
    } else
        wxFAIL_MSG(wxT("Unsupported authentication mode."));

    return wxGTCConfigPanelBase::TransferDataToWindow();
}


bool wxGTCConfigPanel::TransferDataFromWindow()
{
    wxCHECK(wxGTCConfigPanelBase::TransferDataFromWindow(), false);

    if (!m_prov.m_read_only) {
        // This is not a provider-locked configuration. Save the data.
        switch (m_auth_mode->GetSelection()) {
        case 0: // 0=Challenge/Response
            m_cfg = m_cfg_resp;
            break;

        case 1: // 1=Password
            m_cfg = m_cfg_pass;
            break;

        default:
            wxFAIL_MSG(wxT("Unsupported authentication mode."));
        }
    }

    return true;
}


void wxGTCConfigPanel::OnUpdateUI(wxUpdateUIEvent& event)
{
    UNREFERENCED_PARAMETER(event);

    if (m_prov.m_read_only) {
        // This is provider-locked configuration. Disable controls.
        m_auth_mode_label ->Enable(false);
        m_auth_mode       ->Enable(false);
        m_credentials_resp->Enable(false);
        m_credentials_pass->Enable(false);
    } else {
        // This is not a provider-locked configuration. Enable controls.
        m_auth_mode_label ->Enable(true);
        m_auth_mode       ->Enable(true);
        m_credentials_resp->Enable(true);
        m_credentials_pass ->Enable(true);
    }
}

/// \endcond


//////////////////////////////////////////////////////////////////////
// wxGTCResponseDialog
//////////////////////////////////////////////////////////////////////

wxGTCResponseDialog::wxGTCResponseDialog(const eap::config_provider &prov, wxWindow *parent, wxWindowID id, const wxString &title, const wxPoint &pos, const wxSize &size, long style) :
    wxEAPGeneralDialog(parent, id, title, pos, size, style)
{
    // Set banner title.
    m_banner->m_title->SetLabel(wxString::Format(_("%s Challenge"), wxEAPGetProviderName(prov.m_name)));
}


//////////////////////////////////////////////////////////////////////
// wxGTCResponsePanel
//////////////////////////////////////////////////////////////////////

wxGTCResponsePanel::wxGTCResponsePanel(winstd::sanitizing_wstring &response, const wchar_t *challenge, wxWindow* parent) :
    wxGTCResponsePanelBase(parent),
    m_response_value(response)
{
    // Load and set icon.
    winstd::library lib_shell32;
    if (lib_shell32.load(_T("shell32.dll"), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE))
        m_response_icon->SetIcon(wxLoadIconFromResource(lib_shell32, MAKEINTRESOURCE(24)));

    // Set challenge label.
    m_challenge->SetLabelText(challenge);
    m_challenge->Wrap(FromDIP(200));

    this->Layout();
}


/// \cond internal

bool wxGTCResponsePanel::TransferDataToWindow()
{
    m_response->SetValue(m_response_value.c_str());

    return wxGTCResponsePanelBase::TransferDataToWindow();
}


bool wxGTCResponsePanel::TransferDataFromWindow()
{
    wxCHECK(wxGTCResponsePanelBase::TransferDataFromWindow(), false);

    m_response_value = m_response->GetValue();

    return true;
}

/// \endcond
