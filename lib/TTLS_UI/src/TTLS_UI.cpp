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
// wxTTLSConfigPanel
//////////////////////////////////////////////////////////////////////

wxTTLSConfigPanel::wxTTLSConfigPanel(const eap::config_provider &prov, eap::config_method_ttls &cfg, wxWindow* parent) :
    m_prov(prov),
    m_cfg(cfg),
    wxTTLSConfigPanelBase(parent)
{
    // Load and set icon.
    if (m_shell32.load(_T("shell32.dll"), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE))
        wxSetIconFromResource(m_outer_identity_icon, m_icon, m_shell32, MAKEINTRESOURCE(265));
}


bool wxTTLSConfigPanel::TransferDataToWindow()
{
    if (m_prov.m_read_only) {
        // This is provider-locked configuration. Disable controls.
        m_outer_identity_same      ->Enable(false);
        m_outer_identity_empty     ->Enable(false);
        m_outer_identity_custom    ->Enable(false);
        m_outer_identity_custom_val->Enable(false);
    }

    // Populate identity controls.
    if (m_cfg.m_anonymous_identity.empty()) {
        m_outer_identity_same->SetValue(true);
    } else if (m_cfg.m_anonymous_identity == L"@") {
        m_outer_identity_empty->SetValue(true);
    } else {
        m_outer_identity_custom->SetValue(true);
        m_outer_identity_custom_val->SetValue(m_cfg.m_anonymous_identity);
    }

    return wxTTLSConfigPanelBase::TransferDataToWindow();
}


bool wxTTLSConfigPanel::TransferDataFromWindow()
{
    wxCHECK(wxTTLSConfigPanelBase::TransferDataFromWindow(), false);

    if (!m_prov.m_read_only) {
        // This is not a provider-locked configuration. Save the data.
        if (m_outer_identity_same->GetValue())
            m_cfg.m_anonymous_identity.clear();
        else if (m_outer_identity_empty->GetValue())
            m_cfg.m_anonymous_identity = L"@";
        else
            m_cfg.m_anonymous_identity = m_outer_identity_custom_val->GetValue();
    }

    return true;
}


void wxTTLSConfigPanel::OnUpdateUI(wxUpdateUIEvent& event)
{
    UNREFERENCED_PARAMETER(event);

    if (!m_prov.m_read_only) {
        // This is not a provider-locked configuration. Selectively enable/disable controls.
        m_outer_identity_custom_val->Enable(m_outer_identity_custom->GetValue());
    }
}


//////////////////////////////////////////////////////////////////////
// wxTTLSConfigWindow
//////////////////////////////////////////////////////////////////////

wxTTLSConfigWindow::wxTTLSConfigWindow(const eap::config_provider &prov, eap::config_method &cfg, LPCTSTR pszCredTarget, wxWindow* parent) :
    m_prov(prov),
    m_cfg((eap::config_method_ttls&)cfg),
    m_cfg_pap(cfg.m_module),
    wxScrolledWindow(parent, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxVSCROLL)
{
    wxBoxSizer* sb_content;
    sb_content = new wxBoxSizer( wxVERTICAL );

    if (m_prov.m_read_only)
        sb_content->Add(new wxEAPProviderLockedPanel(m_prov, this), 0, wxALL|wxEXPAND, 5);

    m_inner_title = new wxStaticText(this, wxID_ANY, _("Inner Authentication"), wxDefaultPosition, wxDefaultSize, 0);
    m_inner_title->SetFont(wxFont(18, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL, false, wxEmptyString));
    m_inner_title->SetForegroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_INACTIVECAPTION ) );
    sb_content->Add(m_inner_title, 0, wxALL|wxALIGN_RIGHT, 5);

    m_inner_type = new wxChoicebook(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxCHB_DEFAULT);
    m_inner_type->SetToolTip( _("Select inner authentication method from the list") );
    m_inner_type->AddPage(new wxPAPConfigPanel(m_prov, m_cfg_pap, pszCredTarget, m_inner_type), _("PAP"));
    sb_content->Add(m_inner_type, 0, wxALL|wxEXPAND, 5);

    sb_content->Add(20, 20, 1, wxALL|wxEXPAND, 5);

    m_outer_title = new wxStaticText(this, wxID_ANY, _("Outer Authentication"), wxDefaultPosition, wxDefaultSize, 0);
    m_outer_title->SetFont(wxFont(18, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL, false, wxEmptyString));
    m_outer_title->SetForegroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_INACTIVECAPTION ) );
    sb_content->Add(m_outer_title, 0, wxALL|wxALIGN_RIGHT, 5);

    m_outer_identity = new wxTTLSConfigPanel(m_prov, m_cfg, this);
    sb_content->Add(m_outer_identity, 0, wxALL|wxEXPAND, 5);

    m_tls = new wxTLSConfigPanel(m_prov, m_cfg.m_outer, pszCredTarget, this);
    sb_content->Add(m_tls, 0, wxALL|wxEXPAND, 5);

    wxSize size = sb_content->CalcMin();
    if (size.y > 500) {
        // Increase the width to allow space for vertical scroll bar (to prevent horizontal one) and truncate the height.
        size.x += wxSystemSettings::GetMetric(wxSYS_VSCROLL_X, this);
        size.y  = 500;
    }
    this->SetMinSize(size);
    this->SetScrollRate(5, 5);

    this->SetSizer(sb_content);
    this->Layout();

    m_inner_type->SetFocusFromKbd();

    // Connect Events
    this->Connect(wxEVT_INIT_DIALOG, wxInitDialogEventHandler(wxTTLSConfigWindow::OnInitDialog));
}


wxTTLSConfigWindow::~wxTTLSConfigWindow()
{
    // Disconnect Events
    this->Disconnect(wxEVT_INIT_DIALOG, wxInitDialogEventHandler(wxTTLSConfigWindow::OnInitDialog));
}


bool wxTTLSConfigWindow::TransferDataToWindow()
{
    if (m_prov.m_read_only) {
        // This is provider-locked configuration. Disable controls.
        m_inner_type->GetChoiceCtrl()->Enable(false);
    }

    eap::config_method_pap *cfg_pap = dynamic_cast<eap::config_method_pap*>(m_cfg.m_inner.get());
    if (cfg_pap) {
        m_cfg_pap = *cfg_pap;
        m_inner_type->SetSelection(0); // 0=PAP
    } else
        wxFAIL_MSG(wxT("Unsupported inner authentication method type."));

    // Do not invoke inherited TransferDataToWindow(), as it will call others TransferDataToWindow().
    // This will handle wxTTLSConfigWindow::OnInitDialog() via wxEVT_INIT_DIALOG forwarding.
    return true /*wxScrolledWindow::TransferDataToWindow()*/;
}


bool wxTTLSConfigWindow::TransferDataFromWindow()
{
    wxCHECK(wxScrolledWindow::TransferDataFromWindow(), false);

    if (!m_prov.m_read_only) {
        // This is not a provider-locked configuration. Save the data.
        switch (m_inner_type->GetSelection()) {
        case 0: // 0=PAP
            m_cfg.m_inner.reset(new eap::config_method_pap(m_cfg_pap));
            break;

        default:
            wxFAIL_MSG(wxT("Unsupported inner authentication method type."));
        }
    }

    return true;
}


void wxTTLSConfigWindow::OnInitDialog(wxInitDialogEvent& event)
{
    // Call TransferDataToWindow() manually, as wxScrolledWindow somehow skips that.
    TransferDataToWindow();

    // Forward the event to child panels.
    m_outer_identity->GetEventHandler()->ProcessEvent(event);
    m_tls->GetEventHandler()->ProcessEvent(event);
    for (wxWindowList::compatibility_iterator inner = m_inner_type->GetChildren().GetFirst(); inner; inner = inner->GetNext())
        inner->GetData()->GetEventHandler()->ProcessEvent(event);
}


//////////////////////////////////////////////////////////////////////
// wxTTLSCredentialsPanel
//////////////////////////////////////////////////////////////////////

wxTTLSCredentialsPanel::wxTTLSCredentialsPanel(const eap::config_provider &prov, const eap::config_method &cfg, eap::credentials &cred, LPCTSTR pszCredTarget, wxWindow* parent, bool is_config) :
    m_prov(prov),
    m_cfg((eap::config_method_ttls&)cfg),
    wxPanel(parent, wxID_ANY, wxDefaultPosition, wxDefaultSize)
{
    wxBoxSizer* sb_content;
    sb_content = new wxBoxSizer( wxVERTICAL );

    if (m_prov.m_read_only)
        sb_content->Add(new wxEAPProviderLockedPanel(m_prov, this), 0, wxALL|wxEXPAND, 5);

    m_inner_title = new wxStaticText(this, wxID_ANY, _("Inner Authentication"), wxDefaultPosition, wxDefaultSize, 0);
    m_inner_title->SetFont(wxFont(18, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL, false, wxEmptyString));
    m_inner_title->SetForegroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_INACTIVECAPTION ) );
    sb_content->Add(m_inner_title, 0, wxALL|wxALIGN_RIGHT, 5);

    assert(m_cfg.m_inner);
    const eap::config_method_pap *cfg_inner_pap = dynamic_cast<const eap::config_method_pap*>(m_cfg.m_inner.get());
    if (cfg_inner_pap) {
        if (!((eap::credentials_ttls&)cred).m_inner) ((eap::credentials_ttls&)cred).m_inner.reset(new eap::credentials_pap(cred.m_module));
        m_inner_cred = new wxPAPCredentialsPanel(m_prov, *cfg_inner_pap, *((eap::credentials_ttls&)cred).m_inner.get(), pszCredTarget, this, is_config);
        sb_content->Add(m_inner_cred, 0, wxALL|wxEXPAND, 5);
    } else
        assert(0); // Unsupported inner authentication method type.

    sb_content->Add(20, 20, 1, wxALL|wxEXPAND, 5);

    m_outer_title = new wxStaticText(this, wxID_ANY, _("Outer Authentication"), wxDefaultPosition, wxDefaultSize, 0);
    m_outer_title->SetFont(wxFont(18, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL, false, wxEmptyString));
    m_outer_title->SetForegroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_INACTIVECAPTION ) );
    sb_content->Add(m_outer_title, 0, wxALL|wxALIGN_RIGHT, 5);

    m_outer_cred = new wxTLSCredentialsPanel(m_prov, (const eap::config_method_tls&)m_cfg, (eap::credentials_tls&)cred, pszCredTarget, this, is_config);
    sb_content->Add(m_outer_cred, 0, wxALL|wxEXPAND, 5);

    this->SetSizer(sb_content);
    this->Layout();

    m_inner_cred->SetFocusFromKbd();

    // Connect Events
    this->Connect(wxEVT_INIT_DIALOG, wxInitDialogEventHandler(wxTTLSCredentialsPanel::OnInitDialog));
}


wxTTLSCredentialsPanel::~wxTTLSCredentialsPanel()
{
    // Disconnect Events
    this->Disconnect(wxEVT_INIT_DIALOG, wxInitDialogEventHandler(wxTTLSCredentialsPanel::OnInitDialog));
}


void wxTTLSCredentialsPanel::OnInitDialog(wxInitDialogEvent& event)
{
    // Forward the event to child panels.
    m_outer_cred->GetEventHandler()->ProcessEvent(event);
    m_inner_cred->GetEventHandler()->ProcessEvent(event);
}
