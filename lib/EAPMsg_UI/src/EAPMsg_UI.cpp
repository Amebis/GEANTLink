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

#pragma comment(lib, "Eappcfg.lib")


//////////////////////////////////////////////////////////////////////
// wxEAPMsgMethodConfigPanel
//////////////////////////////////////////////////////////////////////

wxEAPMethodTypeClientData::wxEAPMethodTypeClientData(const EAP_METHOD_TYPE &type, DWORD properties) :
    m_type(type),
    m_properties(properties)
{
}


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

    winstd::eap_method_info_array methods;
    std::unique_ptr<EAP_ERROR, winstd::EapHostPeerFreeErrorMemory_delete> error;
    DWORD dwResult = EapHostPeerGetMethods(&methods, &std::addressof(error)->_Myptr);
    if (dwResult == ERROR_SUCCESS) {
        for (DWORD i = 0; i < methods.dwNumberOfMethods; i++)
            m_method->Append(methods.pEapMethods[i].pwszFriendlyName, new wxEAPMethodTypeClientData(methods.pEapMethods[i].eaptype, methods.pEapMethods[i].eapProperties));
    } else if (error)
        wxLogError(_("Enumerating EAP methods failed (error %u, %s, %s)."), error->dwWinError, error->pRootCauseString, error->pRepairString);
    else
        wxLogError(_("Enumerating EAP methods failed (error %u)."), dwResult);
}


void wxEAPMsgMethodConfigPanel::OnUpdateUI(wxUpdateUIEvent& event)
{
    wxEAPMsgMethodConfigPanelBase::OnUpdateUI(event);

    int sel = m_method->GetSelection();
    const wxEAPMethodTypeClientData *data =
        sel != wxNOT_FOUND && m_method->HasClientObjectData() ?
            dynamic_cast<const wxEAPMethodTypeClientData*>(m_method->GetClientObject(sel)) :
            NULL;
    m_settings->Enable(data && (data->m_properties & eapPropSupportsConfig));
}


void wxEAPMsgMethodConfigPanel::OnSettings(wxCommandEvent& event)
{
    wxEAPMsgMethodConfigPanelBase::OnSettings(event);

    int sel = m_method->GetSelection();
    const wxEAPMethodTypeClientData *data =
        sel != wxNOT_FOUND && m_method->HasClientObjectData() ?
            dynamic_cast<const wxEAPMethodTypeClientData*>(m_method->GetClientObject(sel)) :
            NULL;
    if (data && (data->m_properties & eapPropSupportsConfig)) {
        DWORD cfg_data_size = 0;
        std::unique_ptr<BYTE[], winstd::EapHostPeerFreeMemory_delete> cfg_data;
        std::unique_ptr<EAP_ERROR, winstd::EapHostPeerFreeErrorMemory_delete> error;
        DWORD dwResult = EapHostPeerInvokeConfigUI(GetHWND(), 0, data->m_type, 0, NULL, &cfg_data_size, &std::addressof(cfg_data)->_Myptr, &std::addressof(error)->_Myptr);
    }
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
