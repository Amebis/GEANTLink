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
// eap::peer_ttls_ui
//////////////////////////////////////////////////////////////////////

eap::peer_ttls_ui::peer_ttls_ui() : peer_ui<eap::config_ttls, eap::credentials_ttls, int, int>()
{
}


DWORD eap::peer_ttls_ui::invoke_config_ui(
    _In_    HWND        hwndParent,
    _Inout_ config_type &cfg,
    _Out_   EAP_ERROR   **ppEapError)
{
    UNREFERENCED_PARAMETER(ppEapError);

    // Initialize application.
    new wxApp();
    wxEntryStart(m_instance);

    int result;
    {
        // Create wxWidget-approved parent window.
        wxWindow parent;
        parent.SetHWND((WXHWND)hwndParent);
        parent.AdoptAttributesFromHWND();
        wxTopLevelWindows.Append(&parent);

        // Create and launch configuration dialog.
        wxEAPConfigDialog<config_ttls, wxEAPTTLSConfig> dlg(cfg, &parent);
        result = dlg.ShowModal();

        wxTopLevelWindows.DeleteObject(&parent);
        parent.SetHWND((WXHWND)NULL);
    }

    // Clean-up and return.
    wxEntryCleanup();
    return result == wxID_OK ? ERROR_SUCCESS : ERROR_CANCELLED;
}


DWORD eap::peer_ttls_ui::invoke_identity_ui(
            _In_    HWND          hwndParent,
            _In_    DWORD         dwFlags,
            _Inout_ config_type   &cfg,
            _Inout_ identity_type &usr,
            _Out_   LPWSTR        *ppwszIdentity,
            _Out_   EAP_ERROR     **ppEapError)
{
    UNREFERENCED_PARAMETER(dwFlags);
    UNREFERENCED_PARAMETER(cfg);
    UNREFERENCED_PARAMETER(usr);
    UNREFERENCED_PARAMETER(ppwszIdentity);
    UNREFERENCED_PARAMETER(ppEapError);

    InitCommonControls();
    MessageBox(hwndParent, _T(PRODUCT_NAME_STR) _T(" credential prompt goes here!"), _T(PRODUCT_NAME_STR) _T(" Credentials"), MB_OK);

    return ERROR_SUCCESS;
}


DWORD eap::peer_ttls_ui::invoke_interactive_ui(
            _In_        HWND                      hwndParent,
            _In_  const interactive_request_type  &req,
            _Out_       interactive_response_type &res,
            _Out_       EAP_ERROR                 **ppEapError)
{
    UNREFERENCED_PARAMETER(req);
    UNREFERENCED_PARAMETER(res);
    UNREFERENCED_PARAMETER(ppEapError);

    InitCommonControls();
    MessageBox(hwndParent, _T(PRODUCT_NAME_STR) _T(" interactive UI goes here!"), _T(PRODUCT_NAME_STR) _T(" Prompt"), MB_OK);

    return ERROR_SUCCESS;
}


//////////////////////////////////////////////////////////////////////
// wxEAPTTLSConfigPanel
//////////////////////////////////////////////////////////////////////

wxEAPTTLSConfigPanel::wxEAPTTLSConfigPanel(eap::config_ttls &cfg, wxWindow* parent) :
    m_cfg(cfg),
    wxEAPTTLSConfigPanelBase(parent)
{
    // Load and set icon.
    if (m_shell32.load(_T("shell32.dll"), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE))
        wxSetIconFromResource(m_outer_identity_icon, m_icon, m_shell32, MAKEINTRESOURCE(265));
}


bool wxEAPTTLSConfigPanel::TransferDataToWindow()
{
    wxCHECK(wxEAPTTLSConfigPanelBase::TransferDataToWindow(), false);

    // Populate identity controls.
    if (m_cfg.m_anonymous_identity.empty()) {
        m_outer_identity_same->SetValue(true);
        m_outer_identity_custom_val->Enable(false);
    } else if (m_cfg.m_anonymous_identity == L"@") {
        m_outer_identity_empty->SetValue(true);
        m_outer_identity_custom_val->Enable(false);
    } else {
        m_outer_identity_custom->SetValue(true);
        m_outer_identity_custom_val->Enable(true);
        m_outer_identity_custom_val->SetValue(m_cfg.m_anonymous_identity);
    }

    return true;
}


bool wxEAPTTLSConfigPanel::TransferDataFromWindow()
{
    if (m_outer_identity_same->GetValue())
        m_cfg.m_anonymous_identity.clear();
    else if (m_outer_identity_empty->GetValue())
        m_cfg.m_anonymous_identity = L"@";
    else
        m_cfg.m_anonymous_identity = m_outer_identity_custom_val->GetValue();

    return wxEAPTTLSConfigPanelBase::TransferDataFromWindow();
}


void wxEAPTTLSConfigPanel::OnOuterIdentityCustom(wxCommandEvent& event)
{
    UNREFERENCED_PARAMETER(event);

    m_outer_identity_custom_val->Enable(m_outer_identity_custom->GetValue());
}


//////////////////////////////////////////////////////////////////////
// wxEAPTTLSConfig
//////////////////////////////////////////////////////////////////////

wxEAPTTLSConfig::wxEAPTTLSConfig(eap::config_ttls &cfg, LPCTSTR pszCredTarget, wxWindow* parent) :
    m_cfg(cfg),
    m_cfg_pap(cfg.m_module),
    wxScrolledWindow(parent, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxVSCROLL)
{
    wxBoxSizer* sb_content;
    sb_content = new wxBoxSizer( wxVERTICAL );

    m_outer_title = new wxStaticText(this, wxID_ANY, _("Outer Authentication"), wxDefaultPosition, wxDefaultSize, 0);
    m_outer_title->SetFont(wxFont(18, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL, false, wxEmptyString));
    m_outer_title->SetForegroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_INACTIVECAPTION ) );
    sb_content->Add(m_outer_title, 0, wxALL|wxALIGN_RIGHT, 5);

    m_outer_identity = new wxEAPTTLSConfigPanel(m_cfg, this);
    sb_content->Add(m_outer_identity, 0, wxALL|wxEXPAND, 5);

    m_tls = new wxEAPTLSConfigPanel(m_cfg, pszCredTarget, this);
    sb_content->Add(m_tls, 0, wxALL|wxEXPAND, 5);

    sb_content->Add(20, 20, 1, wxEXPAND, 5);

    m_inner_title = new wxStaticText(this, wxID_ANY, _("Inner Authentication"), wxDefaultPosition, wxDefaultSize, 0);
    m_inner_title->SetFont(wxFont(18, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL, false, wxEmptyString));
    m_inner_title->SetForegroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_INACTIVECAPTION ) );
    sb_content->Add(m_inner_title, 0, wxALL|wxALIGN_RIGHT, 5);

    m_inner_type = new wxChoicebook(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxCHB_DEFAULT);
    m_inner_type->SetToolTip( _("Select inner authentication method from the list") );
    m_inner_type->AddPage(new wxPAPConfigPanel(m_cfg_pap, pszCredTarget, m_inner_type), _("PAP"));
    sb_content->Add(m_inner_type, 0, wxALL|wxEXPAND, 5);

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

    m_outer_identity->SetFocusFromKbd();

    // Connect Events
    this->Connect(wxEVT_INIT_DIALOG, wxInitDialogEventHandler(wxEAPTTLSConfig::OnInitDialog));
}


wxEAPTTLSConfig::~wxEAPTTLSConfig()
{
    // Disconnect Events
    this->Disconnect(wxEVT_INIT_DIALOG, wxInitDialogEventHandler(wxEAPTTLSConfig::OnInitDialog));
}


bool wxEAPTTLSConfig::TransferDataToWindow()
{
    eap::config_pap *cfg_pap = dynamic_cast<eap::config_pap*>(m_cfg.m_inner);
    if (cfg_pap) {
        m_cfg_pap = *cfg_pap;
        m_inner_type->SetSelection(0); // 0=PAP
    } else
        wxFAIL_MSG(wxT("Unsupported inner authentication method type."));

    return wxScrolledWindow::TransferDataToWindow();
}


bool wxEAPTTLSConfig::TransferDataFromWindow()
{
    wxCHECK(wxScrolledWindow::TransferDataFromWindow(), false);

    switch (m_inner_type->GetSelection()) {
    case 0: // 0=PAP
        delete m_cfg.m_inner;
        m_cfg.m_inner = new eap::config_pap(m_cfg_pap);
        break;

    default:
        wxFAIL_MSG(wxT("Unsupported inner authentication method type."));
    }

    return true;
}


void wxEAPTTLSConfig::OnInitDialog(wxInitDialogEvent& event)
{
    // Forward the event to child panels.
    m_outer_identity->GetEventHandler()->ProcessEvent(event);
    m_tls->GetEventHandler()->ProcessEvent(event);
    for (wxWindowList::compatibility_iterator inner = m_inner_type->GetChildren().GetFirst(); inner; inner = inner->GetNext())
        inner->GetData()->GetEventHandler()->ProcessEvent(event);
}
