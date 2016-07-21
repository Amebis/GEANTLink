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
// wxEAPBannerPanel
//////////////////////////////////////////////////////////////////////

wxEAPBannerPanel::wxEAPBannerPanel(wxWindow* parent) : wxEAPBannerPanelBase(parent)
{
    m_title->SetLabelText(wxT(PRODUCT_NAME_STR));
}


bool wxEAPBannerPanel::AcceptsFocusFromKeyboard() const
{
    return false;
}


//////////////////////////////////////////////////////////////////////
// wxEAPCredentialsDialog
//////////////////////////////////////////////////////////////////////

wxEAPCredentialsDialog::wxEAPCredentialsDialog(const eap::config_provider &prov, wxWindow* parent) : wxEAPCredentialsDialogBase(parent)
{
    // Set extra style here, as wxFormBuilder overrides all default flags.
    this->SetExtraStyle(this->GetExtraStyle() | wxWS_EX_VALIDATE_RECURSIVELY);

    // Set banner title.
    m_banner->m_title->SetLabel(wxString::Format(_("%s Credentials"), prov.m_id.c_str()));

    m_buttonsOK->SetDefault();
}


void wxEAPCredentialsDialog::AddContents(wxPanel **contents, size_t content_count)
{
    if (content_count) {
        for (size_t i = 0; i < content_count; i++)
            m_panels->Add(contents[i], 0, wxALL|wxEXPAND, 5);

        this->Layout();
        this->GetSizer()->Fit(this);
        contents[0]->SetFocusFromKbd();
    }
}


void wxEAPCredentialsDialog::OnInitDialog(wxInitDialogEvent& event)
{
    for (wxSizerItemList::compatibility_iterator panel = m_panels->GetChildren().GetFirst(); panel; panel = panel->GetNext())
        panel->GetData()->GetWindow()->GetEventHandler()->ProcessEvent(event);
}


//////////////////////////////////////////////////////////////////////
// wxEAPProviderLockedPanel
//////////////////////////////////////////////////////////////////////

wxEAPProviderLockedPanel::wxEAPProviderLockedPanel(const eap::config_provider &prov, wxWindow* parent) :
    m_prov(prov),
    wxEAPProviderLockedPanelBase(parent)
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


bool wxEAPProviderLockedPanel::AcceptsFocusFromKeyboard() const
{
    return !m_prov.m_help_email.empty() || !m_prov.m_help_web.empty() || !m_prov.m_help_phone.empty();
}


//////////////////////////////////////////////////////////////////////
// wxPasswordCredentialsPanel
//////////////////////////////////////////////////////////////////////

wxPasswordCredentialsPanel::wxPasswordCredentialsPanel(const eap::config_provider &prov, const eap::config_method &cfg, eap::credentials &cred, LPCTSTR pszCredTarget, wxWindow* parent, bool is_config) :
    m_cred((eap::credentials_pass&)cred),
    wxEAPCredentialsPanelBase<wxEAPCredentialsPanelPassBase>(prov, cfg, cred, pszCredTarget, parent, is_config)
{
    // Load and set icon.
    if (m_shell32.load(_T("shell32.dll"), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE))
        wxSetIconFromResource(m_credentials_icon, m_icon, m_shell32, MAKEINTRESOURCE(269));

    bool layout = false;
    if (!m_prov.m_lbl_alt_credential.empty()) {
        m_credentials_label->SetLabel(m_prov.m_lbl_alt_credential);
        m_credentials_label->Wrap( 446 );
        layout = true;
    }

    if (!m_prov.m_lbl_alt_identity.empty()) {
        m_identity_label->SetLabel(m_prov.m_lbl_alt_identity);
        layout = true;
    }

    if (!m_prov.m_lbl_alt_password.empty()) {
        m_password_label->SetLabel(m_prov.m_lbl_alt_password);
        layout = true;
    }

    if (layout)
        this->Layout();
}


bool wxPasswordCredentialsPanel::TransferDataToWindow()
{
    // Inherited TransferDataToWindow() calls m_cred.retrieve().
    // Therefore, call it now, to set m_cred.
    wxCHECK(__super::TransferDataToWindow(), false);

    m_identity->SetValue(m_cred.m_identity);
    m_identity->SetSelection(0, -1);
    m_password->SetValue(m_cred.m_password.empty() ? wxEmptyString : s_dummy_password);

    return true;
}


bool wxPasswordCredentialsPanel::TransferDataFromWindow()
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


const wxStringCharType *wxPasswordCredentialsPanel::s_dummy_password = wxT("dummypass");
