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
// wxEAPGeneralDialog
//////////////////////////////////////////////////////////////////////

wxEAPGeneralDialog::wxEAPGeneralDialog(wxWindow* parent, const wxString& title) : wxEAPGeneralDialogBase(parent, wxID_ANY, title)
{
    // Set extra style here, as wxFormBuilder overrides all default flags.
    this->SetExtraStyle(this->GetExtraStyle() | wxWS_EX_VALIDATE_RECURSIVELY);

    m_buttonsOK->SetDefault();
}


void wxEAPGeneralDialog::AddContent(wxPanel **contents, size_t content_count)
{
    if (content_count) {
        for (size_t i = 0; i < content_count; i++)
            m_panels->Add(contents[i], 0, wxALL|wxEXPAND, 5);

        this->Layout();
        this->GetSizer()->Fit(this);
        contents[0]->SetFocusFromKbd();
    }
}


void wxEAPGeneralDialog::AddContent(wxPanel *content)
{
    AddContent(&content, 1);
}


void wxEAPGeneralDialog::OnInitDialog(wxInitDialogEvent& event)
{
    for (wxSizerItemList::compatibility_iterator panel = m_panels->GetChildren().GetFirst(); panel; panel = panel->GetNext())
        panel->GetData()->GetWindow()->GetEventHandler()->ProcessEvent(event);
}


//////////////////////////////////////////////////////////////////////
// wxEAPCredentialsDialog
//////////////////////////////////////////////////////////////////////

wxEAPCredentialsDialog::wxEAPCredentialsDialog(const eap::config_provider &prov, wxWindow* parent) : wxEAPGeneralDialog(parent, _("EAP Credentials"))
{
    // Set banner title.
    m_banner->m_title->SetLabel(wxString::Format(_("%s Credentials"), wxEAPGetProviderName(prov.m_id).c_str()));
}


//////////////////////////////////////////////////////////////////////
// wxEAPNotePanel
//////////////////////////////////////////////////////////////////////

wxEAPNotePanel::wxEAPNotePanel(wxWindow* parent) :
    m_provider_notice(NULL),
    m_help_web_label(NULL),
    m_help_web_value(NULL),
    m_help_email_label(NULL),
    m_help_email_value(NULL),
    m_help_phone_label(NULL),
    m_help_phone_value(NULL),
    wxEAPNotePanelBase(parent)
{
}


bool wxEAPNotePanel::AcceptsFocusFromKeyboard() const
{
    return m_help_web_value || m_help_email_value || m_help_phone_label;
}


void wxEAPNotePanel::CreateContactFields(const eap::config_provider &prov)
{
    if (!prov.m_help_email.empty() || !prov.m_help_web.empty() || !prov.m_help_phone.empty()) {
        m_provider_notice = new wxStaticText(this, wxID_ANY, wxString::Format(_("For additional help and instructions, please contact %s at:"),
            !prov.m_name.empty() ? prov.m_name.c_str() :
            !prov.m_id  .empty() ? winstd::tstring_printf(_("your %ls provider"), prov.m_id.c_str()).c_str() : _("your provider")), wxDefaultPosition, wxDefaultSize, 0);
        m_provider_notice->Wrap(449);
        m_note_vert->Add(m_provider_notice, 0, wxUP|wxLEFT|wxRIGHT|wxEXPAND, 5);

        wxFlexGridSizer* sb_contact_tbl;
        sb_contact_tbl = new wxFlexGridSizer(0, 2, 5, 5);
        sb_contact_tbl->AddGrowableCol(1);
        sb_contact_tbl->SetFlexibleDirection(wxBOTH);
        sb_contact_tbl->SetNonFlexibleGrowMode(wxFLEX_GROWMODE_SPECIFIED);

        wxFont font_wingdings(-1, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL, false, wxT("Wingdings"));

        if (!prov.m_help_web.empty()) {
            m_help_web_label = new wxStaticText(this, wxID_ANY, wxT("\xb6"), wxDefaultPosition, wxDefaultSize, 0);
            m_help_web_label->Wrap(-1);
            m_help_web_label->SetFont(font_wingdings);
            sb_contact_tbl->Add(m_help_web_label, 0, wxEXPAND|wxALIGN_TOP, 5);

            m_help_web_value = new wxHyperlinkCtrl(this, wxID_ANY, prov.m_help_web, prov.m_help_web, wxDefaultPosition, wxDefaultSize, wxHL_DEFAULT_STYLE);
            m_help_web_value->SetToolTip(_("Open the default web browser"));
            sb_contact_tbl->Add(m_help_web_value, 0, wxEXPAND|wxALIGN_TOP, 5);
        }

        if (!prov.m_help_email.empty()) {
            m_help_email_label = new wxStaticText(this, wxID_ANY, wxT("\x2a"), wxDefaultPosition, wxDefaultSize, 0);
            m_help_email_label->Wrap(-1);
            m_help_email_label->SetFont(font_wingdings);
            sb_contact_tbl->Add(m_help_email_label, 0, wxEXPAND|wxALIGN_TOP, 5);

            m_help_email_value = new wxHyperlinkCtrl(this, wxID_ANY, prov.m_help_email, wxString(wxT("mailto:")) + prov.m_help_email, wxDefaultPosition, wxDefaultSize, wxHL_DEFAULT_STYLE);
            m_help_email_value->SetToolTip(_("Open your e-mail program"));
            sb_contact_tbl->Add(m_help_email_value, 0, wxEXPAND|wxALIGN_TOP, 5);
        }

        if (!prov.m_help_phone.empty()) {
            m_help_phone_label = new wxStaticText(this, wxID_ANY, wxT("\x29"), wxDefaultPosition, wxDefaultSize, 0);
            m_help_phone_label->Wrap(-1);
            m_help_phone_label->SetFont(font_wingdings);
            sb_contact_tbl->Add(m_help_phone_label, 0, wxEXPAND|wxALIGN_TOP, 5);

            m_help_phone_value = new wxHyperlinkCtrl(this, wxID_ANY, prov.m_help_phone, wxString(wxT("tel:")) + GetPhoneNumber(prov.m_help_phone.c_str()), wxDefaultPosition, wxDefaultSize, wxHL_DEFAULT_STYLE);
            m_help_phone_value->SetToolTip(_("Dial the phone number"));
            sb_contact_tbl->Add(m_help_phone_value, 0, wxEXPAND|wxALIGN_TOP, 5);
        }

        m_note_vert->Add(sb_contact_tbl, 0, wxLEFT|wxRIGHT|wxDOWN|wxEXPAND, 5);
    }
}


//////////////////////////////////////////////////////////////////////
// wxEAPProviderLockedPanel
//////////////////////////////////////////////////////////////////////

wxEAPProviderLockedPanel::wxEAPProviderLockedPanel(const eap::config_provider &prov, wxWindow* parent) : wxEAPNotePanel(parent)
{
    // Load and set icon.
    if (m_shell32.load(_T("shell32.dll"), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE))
        wxSetIconFromResource(m_note_icon, m_icon, m_shell32, MAKEINTRESOURCE(48));

    m_note_label->SetLabel(wxString::Format(_("%s has pre-set parts of this configuration. Those parts are locked to prevent accidental modification."),
        !prov.m_name.empty() ? prov.m_name.c_str() :
        !prov.m_id  .empty() ? winstd::tstring_printf(_("Your %ls provider"), prov.m_id.c_str()).c_str() : _("Your provider")));
    m_note_label->Wrap(449);

    CreateContactFields(prov);

    this->Layout();
}


//////////////////////////////////////////////////////////////////////
// wxEAPCredentialWarningPanel
//////////////////////////////////////////////////////////////////////

wxEAPCredentialWarningPanel::wxEAPCredentialWarningPanel(const eap::config_provider &prov, wxWindow* parent) : wxEAPNotePanel(parent)
{
    // Load and set icon.
    if (m_shell32.load(_T("shell32.dll"), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE))
        wxSetIconFromResource(m_note_icon, m_icon, m_shell32, MAKEINTRESOURCE(161));

    m_note_label->SetLabel(_("Previous attempt to connect failed. Please, make sure your credentials are correct, or try again later."));
    m_note_label->Wrap(449);

    CreateContactFields(prov);

    this->Layout();
}


//////////////////////////////////////////////////////////////////////
// wxEAPConfigWindow
//////////////////////////////////////////////////////////////////////

wxEAPConfigWindow::wxEAPConfigWindow(const eap::config_provider &prov, eap::config_method &cfg, wxWindow* parent) :
    m_prov(prov),
    m_cfg(cfg),
    wxScrolledWindow(parent, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxVSCROLL)
{
    this->SetScrollRate(5, 5);

    // Connect Events
    this->Connect(wxEVT_INIT_DIALOG, wxInitDialogEventHandler(wxEAPConfigWindow::OnInitDialog));
    this->Connect(wxEVT_UPDATE_UI, wxUpdateUIEventHandler(wxEAPConfigWindow::OnUpdateUI));
}


wxEAPConfigWindow::~wxEAPConfigWindow()
{
    // Disconnect Events
    this->Disconnect(wxEVT_UPDATE_UI, wxUpdateUIEventHandler(wxEAPConfigWindow::OnUpdateUI));
    this->Disconnect(wxEVT_INIT_DIALOG, wxInitDialogEventHandler(wxEAPConfigWindow::OnInitDialog));
}


void wxEAPConfigWindow::OnInitDialog(wxInitDialogEvent& event)
{
    UNREFERENCED_PARAMETER(event);

    // Call TransferDataToWindow() manually, as wxScrolledWindow somehow skips that.
    TransferDataToWindow();
}


void wxEAPConfigWindow::OnUpdateUI(wxUpdateUIEvent& event)
{
    UNREFERENCED_PARAMETER(event);

    if (m_parent && m_parent->IsKindOf(wxCLASSINFO(wxNotebook))) {
        // We're a notebook page. Set the ID of our provider as our page label.
        wxNotebook *notebook = (wxNotebook*)m_parent;
        int idx = notebook->FindPage(this);
        if (idx != wxNOT_FOUND)
            notebook->SetPageText(idx, wxEAPGetProviderName(m_prov.m_id));
    } else
        this->SetLabel(wxEAPGetProviderName(m_prov.m_id));
}


//////////////////////////////////////////////////////////////////////
// wxEAPProviderIdentityPanel
//////////////////////////////////////////////////////////////////////

wxEAPProviderIdentityPanel::wxEAPProviderIdentityPanel(eap::config_provider &prov, wxWindow* parent) :
    m_prov(prov),
    wxEAPProviderIdentityPanelBase(parent)
{
    // Load and set icon.
    if (m_shell32.load(_T("shell32.dll"), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE))
        wxSetIconFromResource(m_provider_id_icon, m_icon, m_shell32, MAKEINTRESOURCE(259));
}


bool wxEAPProviderIdentityPanel::TransferDataToWindow()
{
    m_provider_name ->SetValue(m_prov.m_id        );
    m_provider_web  ->SetValue(m_prov.m_help_web  );
    m_provider_email->SetValue(m_prov.m_help_email);
    m_provider_phone->SetValue(m_prov.m_help_phone);

    return wxEAPProviderIdentityPanelBase::TransferDataToWindow();
}


bool wxEAPProviderIdentityPanel::TransferDataFromWindow()
{
    wxCHECK(wxEAPProviderIdentityPanelBase::TransferDataFromWindow(), false);

    m_prov.m_id         = m_provider_name ->GetValue();
    m_prov.m_help_web   = m_provider_web  ->GetValue();
    m_prov.m_help_email = m_provider_email->GetValue();
    m_prov.m_help_phone = m_provider_phone->GetValue();

    return true;
}


//////////////////////////////////////////////////////////////////////
// wxEAPProviderLockPanel
//////////////////////////////////////////////////////////////////////

wxEAPProviderLockPanel::wxEAPProviderLockPanel(eap::config_provider &prov, wxWindow* parent) :
    m_prov(prov),
    wxEAPProviderLockPanelBase(parent)
{
    // Load and set icon.
    if (m_shell32.load(_T("shell32.dll"), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE))
        wxSetIconFromResource(m_provider_lock_icon, m_icon, m_shell32, MAKEINTRESOURCE(1003));
}


bool wxEAPProviderLockPanel::TransferDataToWindow()
{
    m_provider_lock->SetValue(m_prov.m_read_only);

    return wxEAPProviderLockPanelBase::TransferDataToWindow();
}


bool wxEAPProviderLockPanel::TransferDataFromWindow()
{
    wxCHECK(wxEAPProviderLockPanelBase::TransferDataFromWindow(), false);

    m_prov.m_read_only = m_provider_lock->GetValue();

    return true;
}


//////////////////////////////////////////////////////////////////////
// wxEAPConfigProvider
//////////////////////////////////////////////////////////////////////

wxEAPConfigProvider::wxEAPConfigProvider(eap::config_provider &prov, wxWindow* parent) :
    m_prov(prov),
    wxEAPGeneralDialog(parent, _("Provider Settings"))
{
    // Set banner title.
    m_banner->m_title->SetLabel(_("Provider Settings"));

    m_identity = new wxEAPProviderIdentityPanel(prov, this);
    AddContent(m_identity);

    m_lock = new wxEAPProviderLockPanel(prov, this);
    AddContent(m_lock);

    m_identity->m_provider_name->SetFocusFromKbd();
}
