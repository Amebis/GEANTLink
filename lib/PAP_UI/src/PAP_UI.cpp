/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2020 Amebis
    Copyright © 2016 GÉANT
*/

#include "PCH.h"


//////////////////////////////////////////////////////////////////////
// wxPAPConfigPanel
//////////////////////////////////////////////////////////////////////

wxPAPConfigPanel::wxPAPConfigPanel(const eap::config_provider &prov, eap::config_method_pap &cfg, wxWindow* parent) : wxPanel(parent)
{
    wxBoxSizer* sb_content;
    sb_content = new wxBoxSizer( wxVERTICAL );

    m_credentials = new wxPAPCredentialsConfigPanel(prov, cfg, this, _("PAP User ID and Password"));
    sb_content->Add(m_credentials, 0, wxEXPAND, FromDIP(5));

    this->SetSizer(sb_content);
    this->Layout();

    // Connect Events
    this->Connect(wxEVT_INIT_DIALOG, wxInitDialogEventHandler(wxPAPConfigPanel::OnInitDialog));
}


wxPAPConfigPanel::~wxPAPConfigPanel()
{
    // Disconnect Events
    this->Disconnect(wxEVT_INIT_DIALOG, wxInitDialogEventHandler(wxPAPConfigPanel::OnInitDialog));
}


/// \cond internal
void wxPAPConfigPanel::OnInitDialog(wxInitDialogEvent& event)
{
    // Forward the event to child panels.
    if (m_credentials)
        m_credentials->GetEventHandler()->ProcessEvent(event);
}
/// \endcond
