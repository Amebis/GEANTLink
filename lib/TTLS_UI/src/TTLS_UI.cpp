/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2021 Amebis
    Copyright © 2016 GÉANT
*/

#include "PCH.h"


//////////////////////////////////////////////////////////////////////
// wxTLSTunnelConfigWindow
//////////////////////////////////////////////////////////////////////

wxTLSTunnelConfigWindow::wxTLSTunnelConfigWindow(eap::config_provider &prov, eap::config_method &cfg, wxWindow* parent) :
    wxEAPConfigWindow(prov, cfg, parent)
{
    wxBoxSizer* sb_content;
    sb_content = new wxBoxSizer( wxVERTICAL );

    if (m_prov.m_read_only)
        sb_content->Add(new wxEAPProviderLockedPanel(m_prov, this), 0, wxALL|wxEXPAND, FromDIP(5));

    m_outer_title = new wxStaticText(this, wxID_ANY, _("Outer Authentication"), wxDefaultPosition, wxDefaultSize, 0);
    m_outer_title->SetFont(wxFont(18, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL, false, wxEmptyString));
    m_outer_title->SetForegroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_INACTIVECAPTION ) );
    sb_content->Add(m_outer_title, 0, wxALL|wxALIGN_RIGHT, FromDIP(5));

    m_outer_identity = new wxEAPIdentityConfigPanel(m_prov, dynamic_cast<eap::config_method_with_cred&>(m_cfg), this);
    sb_content->Add(m_outer_identity, 0, wxALL|wxEXPAND, FromDIP(5));

    m_tls = new wxTLSConfigPanel(m_prov, dynamic_cast<eap::config_method_tls&>(m_cfg), this);
    sb_content->Add(m_tls, 0, wxALL|wxEXPAND, FromDIP(5));

    sb_content->Add(FromDIP(20), FromDIP(20), 1, wxALL|wxEXPAND, FromDIP(5));

    m_inner_title = new wxStaticText(this, wxID_ANY, _("Inner Authentication"), wxDefaultPosition, wxDefaultSize, 0);
    m_inner_title->SetFont(wxFont(18, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL, false, wxEmptyString));
    m_inner_title->SetForegroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_INACTIVECAPTION ) );
    sb_content->Add(m_inner_title, 0, wxALL|wxALIGN_RIGHT, FromDIP(5));

    m_inner_type = new wxChoicebook(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxCHB_DEFAULT);
    m_inner_type->SetToolTip( _("Select inner authentication method from the list") );
    sb_content->Add(m_inner_type, 0, wxALL|wxEXPAND, FromDIP(5));

    wxSize size = sb_content->CalcMin();
    if (size.y > FromDIP(500)) {
        // Increase the width to allow space for vertical scroll bar (to prevent horizontal one) and truncate the height.
        size.x += wxSystemSettings::GetMetric(wxSYS_VSCROLL_X, this);
        size.y  = FromDIP(500);
    }
    this->SetMinSize(size);

    this->SetSizer(sb_content);
    this->Layout();

    m_outer_identity->SetFocusFromKbd();

    this->Connect(wxEVT_UPDATE_UI, wxUpdateUIEventHandler(wxTLSTunnelConfigWindow::OnUpdateUI));
}


wxTLSTunnelConfigWindow::~wxTLSTunnelConfigWindow()
{
    this->Disconnect(wxEVT_UPDATE_UI, wxUpdateUIEventHandler(wxTLSTunnelConfigWindow::OnUpdateUI));
}


/// \cond internal

bool wxTLSTunnelConfigWindow::TransferDataToWindow()
{
    // Do not invoke inherited TransferDataToWindow(), as it will call others TransferDataToWindow().
    // This will handle wxTLSTunnelConfigWindow::OnInitDialog() via wxEVT_INIT_DIALOG forwarding.
    return true /*wxEAPConfigWindow::TransferDataToWindow()*/;
}


void wxTLSTunnelConfigWindow::OnInitDialog(wxInitDialogEvent& event)
{
    wxEAPConfigWindow::OnInitDialog(event);

    // Forward the event to child panels.
    m_outer_identity->GetEventHandler()->ProcessEvent(event);
    m_tls->GetEventHandler()->ProcessEvent(event);
    for (wxWindowList::compatibility_iterator inner = m_inner_type->GetChildren().GetFirst(); inner; inner = inner->GetNext())
        inner->GetData()->GetEventHandler()->ProcessEvent(event);
}


void wxTLSTunnelConfigWindow::OnUpdateUI(wxUpdateUIEvent& event)
{
    m_inner_type->GetChoiceCtrl()->Enable(!m_prov.m_read_only);

    event.Skip();
}

/// \endcond


//////////////////////////////////////////////////////////////////////
// wxPEAPConfigWindow
//////////////////////////////////////////////////////////////////////

wxPEAPConfigWindow::wxPEAPConfigWindow(eap::config_provider &prov, eap::config_method &cfg, wxWindow* parent) :
    m_cfg_eapmschapv2(cfg.m_module, cfg.m_level + 1),
    m_cfg_eapgtc     (cfg.m_module, cfg.m_level + 1),
#if EAP_INNER_EAPHOST
    m_cfg_eaphost    (cfg.m_module, cfg.m_level + 1),
#endif
    wxTLSTunnelConfigWindow(prov, cfg, parent)
{
    m_panel_eapmschapv2 = new wxMSCHAPv2ConfigPanel(m_prov, m_cfg_eapmschapv2, m_inner_type);
    m_inner_type->AddPage(m_panel_eapmschapv2, _("EAP-MSCHAPv2"));
    m_panel_eapgtc = new wxGTCConfigPanel(m_prov, m_cfg_eapgtc, m_inner_type);
    m_inner_type->AddPage(m_panel_eapgtc, _("EAP-GTC"));
#if EAP_INNER_EAPHOST
    m_panel_eaphost = new wxEapHostConfigPanel(m_prov, m_cfg_eaphost, m_inner_type);
    m_inner_type->AddPage(m_panel_eaphost, _("Other EAP methods..."));
#endif
}


/// \cond internal

bool wxPEAPConfigWindow::TransferDataToWindow()
{
    auto &cfg = dynamic_cast<eap::config_method_tls_tunnel&>(m_cfg);

    switch (cfg.m_inner->get_method_id()) {
    case winstd::eap_type_t::mschapv2:
        m_cfg_eapmschapv2 = dynamic_cast<eap::config_method_eapmschapv2&>(*cfg.m_inner);
        m_inner_type->SetSelection(m_inner_type->FindPage(m_panel_eapmschapv2));
        break;

    case winstd::eap_type_t::gtc:
        m_cfg_eapgtc = dynamic_cast<eap::config_method_eapgtc&>(*cfg.m_inner);
        m_inner_type->SetSelection(m_inner_type->FindPage(m_panel_eapgtc));
        break;

#if EAP_INNER_EAPHOST
    case winstd::eap_type_t::undefined:
        m_cfg_eaphost = dynamic_cast<eap::config_method_eaphost&>(*cfg.m_inner);
        m_inner_type->SetSelection(m_inner_type->FindPage(m_panel_eaphost));
        break;
#endif
    }

    return wxTLSTunnelConfigWindow::TransferDataToWindow();
}


bool wxPEAPConfigWindow::TransferDataFromWindow()
{
    wxCHECK(wxTLSTunnelConfigWindow::TransferDataFromWindow(), false);

    auto &cfg = dynamic_cast<eap::config_method_tls_tunnel&>(m_cfg);

    if (!m_prov.m_read_only) {
        // This is not a provider-locked configuration. Save the data.
        int idx = m_inner_type->GetSelection();
        if (idx != wxNOT_FOUND) {
            wxWindow *page = m_inner_type->GetPage(idx);
            if (page == m_panel_eapmschapv2)
                cfg.m_inner.reset(new eap::config_method_eapmschapv2(m_cfg_eapmschapv2));
            else if (page == m_panel_eapgtc)
                cfg.m_inner.reset(new eap::config_method_eapgtc(m_cfg_eapgtc));
#if EAP_INNER_EAPHOST
            else if (page == m_panel_eaphost)
                cfg.m_inner.reset(new eap::config_method_eaphost(m_cfg_eaphost));
#endif
        }
    }

    return true;
}

/// \endcond


//////////////////////////////////////////////////////////////////////
// wxTTLSConfigWindow
//////////////////////////////////////////////////////////////////////

wxTTLSConfigWindow::wxTTLSConfigWindow(eap::config_provider &prov, eap::config_method &cfg, wxWindow* parent) :
    m_cfg_pap     (cfg.m_module, cfg.m_level + 1),
    m_cfg_mschapv2(cfg.m_module, cfg.m_level + 1),
    wxPEAPConfigWindow(prov, cfg, parent)
{
    m_panel_pap = new wxPAPConfigPanel(m_prov, m_cfg_pap, m_inner_type);
    m_inner_type->InsertPage(0, m_panel_pap, _("PAP"));
    m_panel_mschapv2 = new wxMSCHAPv2ConfigPanel(m_prov, m_cfg_mschapv2, m_inner_type);
    m_inner_type->InsertPage(1, m_panel_mschapv2, _("MSCHAPv2"));

    m_panel_pap->SetFocusFromKbd();
}


/// \cond internal

bool wxTTLSConfigWindow::TransferDataToWindow()
{
    auto &cfg = dynamic_cast<eap::config_method_tls_tunnel&>(m_cfg);

    // Native inner methods
    switch (cfg.m_inner->get_method_id()) {
    case winstd::eap_type_t::legacy_pap:
        m_cfg_pap = dynamic_cast<eap::config_method_pap&>(*cfg.m_inner);
        m_inner_type->SetSelection(m_inner_type->FindPage(m_panel_pap));
        break;

    case winstd::eap_type_t::legacy_mschapv2:
        m_cfg_mschapv2 = dynamic_cast<eap::config_method_mschapv2&>(*cfg.m_inner);
        m_inner_type->SetSelection(m_inner_type->FindPage(m_panel_mschapv2));
        break;
    }

    return wxPEAPConfigWindow::TransferDataToWindow();
}


bool wxTTLSConfigWindow::TransferDataFromWindow()
{
    wxCHECK(wxPEAPConfigWindow::TransferDataFromWindow(), false);

    auto &cfg = dynamic_cast<eap::config_method_tls_tunnel&>(m_cfg);

    if (!m_prov.m_read_only) {
        // This is not a provider-locked configuration. Save the data.
        int idx = m_inner_type->GetSelection();
        if (idx != wxNOT_FOUND) {
            wxWindow *page = m_inner_type->GetPage(idx);
            if (page == m_panel_pap)
                cfg.m_inner.reset(new eap::config_method_pap(m_cfg_pap));
            else if (page == m_panel_mschapv2)
                cfg.m_inner.reset(new eap::config_method_mschapv2(m_cfg_mschapv2));
        }
    }

    return true;
}

/// \endcond
