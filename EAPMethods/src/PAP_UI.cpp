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

#include <StdAfx.h>


//////////////////////////////////////////////////////////////////////
// wxPAPConfigPanel
//////////////////////////////////////////////////////////////////////

wxPAPConfigPanel::wxPAPConfigPanel(eap::config_pap &cfg, LPCTSTR pszCredTarget, wxWindow* parent) : wxPanel(parent)
{
    wxBoxSizer* sb_content;
    sb_content = new wxBoxSizer( wxVERTICAL );

    if (cfg.m_allow_save) {
        m_credentials = new wxPAPCredentialsConfigPanel(cfg, pszCredTarget, this);
        sb_content->Add(m_credentials, 0, wxALL|wxEXPAND, 5);

        m_label = NULL;
    } else {
        m_credentials = NULL;

        m_label = new wxStaticText(this, wxID_ANY, _("This method requires no additional settings."), wxDefaultPosition, wxDefaultSize, 0);
        m_label->Wrap(-1);
        sb_content->Add(m_label, 0, wxALL|wxEXPAND, 5);
    }

    sb_content->Add(10, 10, 1, wxEXPAND, 5);

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


void wxPAPConfigPanel::OnInitDialog(wxInitDialogEvent& event)
{
    // Forward the event to child panels.
    if (m_credentials)
        m_credentials->GetEventHandler()->ProcessEvent(event);
}
