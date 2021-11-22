/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2020 Amebis
    Copyright © 2016 GÉANT
*/

#include "PCH.h"


//////////////////////////////////////////////////////////////////////
// wxMSCHAPv2ConfigPanel
//////////////////////////////////////////////////////////////////////

wxMSCHAPv2ConfigPanel::wxMSCHAPv2ConfigPanel(const eap::config_provider &prov, eap::config_method_mschapv2 &cfg, wxWindow* parent) : wxPanel(parent)
{
    wxBoxSizer* sb_content;
    sb_content = new wxBoxSizer( wxVERTICAL );

    m_credentials = new wxMSCHAPv2CredentialsConfigPanel(prov, cfg, this, _("MSCHAPv2 User ID and Password"));
    sb_content->Add(m_credentials, 0, wxEXPAND, FromDIP(5));

    this->SetSizer(sb_content);
    this->Layout();

    // Connect Events
    this->Connect(wxEVT_INIT_DIALOG, wxInitDialogEventHandler(wxMSCHAPv2ConfigPanel::OnInitDialog));
}


wxMSCHAPv2ConfigPanel::~wxMSCHAPv2ConfigPanel()
{
    // Disconnect Events
    this->Disconnect(wxEVT_INIT_DIALOG, wxInitDialogEventHandler(wxMSCHAPv2ConfigPanel::OnInitDialog));
}


/// \cond internal
void wxMSCHAPv2ConfigPanel::OnInitDialog(wxInitDialogEvent& event)
{
    // Forward the event to child panels.
    if (m_credentials)
        m_credentials->GetEventHandler()->ProcessEvent(event);
}
/// \endcond
