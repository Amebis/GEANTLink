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
    winstd::library lib_shell32;
    if (lib_shell32.load(_T("shell32.dll"), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE))
        m_outer_identity_icon->SetIcon(wxLoadIconFromResource(lib_shell32, MAKEINTRESOURCE(265)));
}


/// \cond internal

bool wxTTLSConfigPanel::TransferDataToWindow()
{
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
    wxTTLSConfigPanelBase::OnUpdateUI(event);

    if (m_prov.m_read_only) {
        // This is provider-locked configuration. Disable controls.
        m_outer_identity_same      ->Enable(false);
        m_outer_identity_empty     ->Enable(false);
        m_outer_identity_custom    ->Enable(false);
        m_outer_identity_custom_val->Enable(false);
    } else {
        // This is not a provider-locked configuration. Selectively enable/disable controls.
        m_outer_identity_same      ->Enable(true);
        m_outer_identity_empty     ->Enable(true);
        m_outer_identity_custom    ->Enable(true);
        m_outer_identity_custom_val->Enable(m_outer_identity_custom->GetValue());
    }
}

/// \endcond


//////////////////////////////////////////////////////////////////////
// wxTTLSConfigWindow
//////////////////////////////////////////////////////////////////////

wxTTLSConfigWindow::wxTTLSConfigWindow(eap::config_provider &prov, eap::config_method &cfg, wxWindow* parent) :
    m_cfg_pap        (cfg.m_module, cfg.m_level + 1),
    m_cfg_mschapv2   (cfg.m_module, cfg.m_level + 1),
    m_cfg_eapmschapv2(cfg.m_module, cfg.m_level + 1),
#ifdef EAP_INNER_EAPHOST
    m_cfg_eaphost    (cfg.m_module, cfg.m_level + 1),
#endif
    wxEAPConfigWindow(prov, cfg, parent)
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
    wxPAPConfigPanel *panel_pap = new wxPAPConfigPanel(m_prov, m_cfg_pap, m_inner_type);
    m_inner_type->AddPage(panel_pap, _("PAP"));
    wxMSCHAPv2ConfigPanel *panel_mschapv2 = new wxMSCHAPv2ConfigPanel(m_prov, m_cfg_mschapv2, m_inner_type);
    m_inner_type->AddPage(panel_mschapv2, _("MSCHAPv2"));
    wxMSCHAPv2ConfigPanel *panel_eapmschapv2 = new wxMSCHAPv2ConfigPanel(m_prov, m_cfg_eapmschapv2, m_inner_type);
    m_inner_type->AddPage(panel_eapmschapv2, _("EAP-MSCHAPv2"));
#ifdef EAP_INNER_EAPHOST
    wxEapHostConfigPanel *panel_eaphost = new wxEapHostConfigPanel(m_prov, m_cfg_eaphost, m_inner_type);
    m_inner_type->AddPage(panel_eaphost, _("Other EAP methods..."));
#endif
    sb_content->Add(m_inner_type, 0, wxALL|wxEXPAND, 5);

    sb_content->Add(20, 20, 1, wxALL|wxEXPAND, 5);

    m_outer_title = new wxStaticText(this, wxID_ANY, _("Outer Authentication"), wxDefaultPosition, wxDefaultSize, 0);
    m_outer_title->SetFont(wxFont(18, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL, false, wxEmptyString));
    m_outer_title->SetForegroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_INACTIVECAPTION ) );
    sb_content->Add(m_outer_title, 0, wxALL|wxALIGN_RIGHT, 5);

    m_outer_identity = new wxTTLSConfigPanel(m_prov, dynamic_cast<eap::config_method_ttls&>(m_cfg), this);
    sb_content->Add(m_outer_identity, 0, wxALL|wxEXPAND, 5);

    m_tls = new wxTLSConfigPanel(m_prov, dynamic_cast<eap::config_method_tls&>(m_cfg), this);
    sb_content->Add(m_tls, 0, wxALL|wxEXPAND, 5);

    wxSize size = sb_content->CalcMin();
    if (size.y > 500) {
        // Increase the width to allow space for vertical scroll bar (to prevent horizontal one) and truncate the height.
        size.x += wxSystemSettings::GetMetric(wxSYS_VSCROLL_X, this);
        size.y  = 500;
    }
    this->SetMinSize(size);

    this->SetSizer(sb_content);
    this->Layout();

    // m_inner_type->SetFocusFromKbd(); // This control steals mouse-wheel scrolling for itself
    panel_pap->SetFocusFromKbd();

    this->Connect(wxEVT_UPDATE_UI, wxUpdateUIEventHandler(wxTTLSConfigWindow::OnUpdateUI));
}


wxTTLSConfigWindow::~wxTTLSConfigWindow()
{
    this->Disconnect(wxEVT_UPDATE_UI, wxUpdateUIEventHandler(wxTTLSConfigWindow::OnUpdateUI));
}


/// \cond internal

bool wxTTLSConfigWindow::TransferDataToWindow()
{
    auto &cfg_ttls = dynamic_cast<eap::config_method_ttls&>(m_cfg);

#ifdef EAP_INNER_EAPHOST
    auto cfg_inner_eaphost = dynamic_cast<eap::config_method_eaphost*>(cfg_ttls.m_inner.get());
    if (!cfg_inner_eaphost)
#endif
    {
        // Native inner methods
        switch (cfg_ttls.m_inner->get_method_id()) {
        case winstd::eap_type_legacy_pap:
            m_cfg_pap = dynamic_cast<eap::config_method_pap&>(*cfg_ttls.m_inner);
            m_inner_type->SetSelection(0); // 0=PAP
            break;

        case winstd::eap_type_legacy_mschapv2:
            m_cfg_mschapv2 = dynamic_cast<eap::config_method_mschapv2&>(*cfg_ttls.m_inner);
            m_inner_type->SetSelection(1); // 1=MSCHAPv2
            break;

        case winstd::eap_type_mschapv2:
            m_cfg_eapmschapv2 = dynamic_cast<eap::config_method_eapmschapv2&>(*cfg_ttls.m_inner);
            m_inner_type->SetSelection(2); // 2=EAP-MSCHAPv2
            break;

        default:
            wxFAIL_MSG(wxT("Unsupported inner authentication method type."));
        }
    }
#ifdef EAP_INNER_EAPHOST
    else {
        // EapHost inner method
        m_cfg_eaphost = *cfg_inner_eaphost;
        m_inner_type->SetSelection(3); // 3=EapHost
    }
#endif

    // Do not invoke inherited TransferDataToWindow(), as it will call others TransferDataToWindow().
    // This will handle wxTTLSConfigWindow::OnInitDialog() via wxEVT_INIT_DIALOG forwarding.
    return true /*wxScrolledWindow::TransferDataToWindow()*/;
}


bool wxTTLSConfigWindow::TransferDataFromWindow()
{
    wxCHECK(wxScrolledWindow::TransferDataFromWindow(), false);

    auto &cfg_ttls = dynamic_cast<eap::config_method_ttls&>(m_cfg);

    if (!m_prov.m_read_only) {
        // This is not a provider-locked configuration. Save the data.
        switch (m_inner_type->GetSelection()) {
        case 0: // 0=PAP
            cfg_ttls.m_inner.reset(new eap::config_method_pap(m_cfg_pap));
            break;

        case 1: // 1=MSCHAPv2
            cfg_ttls.m_inner.reset(new eap::config_method_mschapv2(m_cfg_mschapv2));
            break;

        case 2: // 2=EAP-MSCHAPv2
            cfg_ttls.m_inner.reset(new eap::config_method_eapmschapv2(m_cfg_eapmschapv2));
            break;

#ifdef EAP_INNER_EAPHOST
        case 3: // 3=EapHost
            cfg_ttls.m_inner.reset(new eap::config_method_eaphost(m_cfg_eaphost));
            break;
#endif

        default:
            wxFAIL_MSG(wxT("Unsupported inner authentication method type."));
        }
    }

    return true;
}


void wxTTLSConfigWindow::OnInitDialog(wxInitDialogEvent& event)
{
    wxEAPConfigWindow::OnInitDialog(event);

    // Forward the event to child panels.
    m_outer_identity->GetEventHandler()->ProcessEvent(event);
    m_tls->GetEventHandler()->ProcessEvent(event);
    for (wxWindowList::compatibility_iterator inner = m_inner_type->GetChildren().GetFirst(); inner; inner = inner->GetNext())
        inner->GetData()->GetEventHandler()->ProcessEvent(event);
}


void wxTTLSConfigWindow::OnUpdateUI(wxUpdateUIEvent& event)
{
    m_inner_type->GetChoiceCtrl()->Enable(!m_prov.m_read_only);

    event.Skip();
}

/// \endcond
