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
// wxEAPMsgMethodConfigPanel
//////////////////////////////////////////////////////////////////////

wxEAPMsgMethodConfigPanel::wxEAPMsgMethodConfigPanel(const eap::config_provider &prov, eap::config_method_eapmsg &cfg, wxWindow *parent) : wxEAPMsgMethodConfigPanelBase(parent)
{
    UNREFERENCED_PARAMETER(prov);
    UNREFERENCED_PARAMETER(cfg);

    // Load and set icon.
    winstd::library lib_shell32;
    if (lib_shell32.load(_T("shell32.dll"), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE))
        m_method_icon->SetIcon(wxLoadIconFromResource(lib_shell32, MAKEINTRESOURCE(175)));
}


//////////////////////////////////////////////////////////////////////
// wxEAPMsgConfigPanel
//////////////////////////////////////////////////////////////////////

wxEAPMsgConfigPanel::wxEAPMsgConfigPanel(const eap::config_provider &prov, eap::config_method_eapmsg &cfg, wxWindow* parent) : wxPanel(parent)
{
    wxBoxSizer* sb_content;
    sb_content = new wxBoxSizer( wxVERTICAL );

    m_method = new wxEAPMsgMethodConfigPanel(prov, cfg, this);
    sb_content->Add(m_method, 0, wxEXPAND, 5);

    this->SetSizer(sb_content);
    this->Layout();

    // Connect Events
    this->Connect(wxEVT_INIT_DIALOG, wxInitDialogEventHandler(wxEAPMsgConfigPanel::OnInitDialog));
}


wxEAPMsgConfigPanel::~wxEAPMsgConfigPanel()
{
    // Disconnect Events
    this->Disconnect(wxEVT_INIT_DIALOG, wxInitDialogEventHandler(wxEAPMsgConfigPanel::OnInitDialog));
}


void wxEAPMsgConfigPanel::OnInitDialog(wxInitDialogEvent& event)
{
    // Forward the event to child panels.
    if (m_method)
        m_method->GetEventHandler()->ProcessEvent(event);
}
