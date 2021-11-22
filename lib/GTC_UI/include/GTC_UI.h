/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2021 Amebis
    Copyright © 2016 GÉANT
*/

#include "../../EAPBase_UI/include/EAP_UI.h"
#include "../../GTC/include/Config.h"

class wxGTCConfigPanel;
class wxGTCResponseDialog;
class wxGTCResponsePanel;

/// \addtogroup EAPBaseGUI
/// @{

///
/// GTC challenge/response credential entry panel
///
typedef wxIdentityCredentialsPanel<eap::credentials_identity, wxIdentityCredentialsPanelBase> wxGTCResponseCredentialsPanel;

///
/// GTC challenge/response credential configuration panel
///
typedef wxEAPCredentialsConfigPanel<eap::credentials_identity, wxGTCResponseCredentialsPanel> wxGTCResponseCredentialsConfigPanel;

///
/// GTC password credential entry panel
///
typedef wxPasswordCredentialsPanel<eap::credentials_pass, wxPasswordCredentialsPanelBase> wxGTCPasswordCredentialsPanel;

///
/// GTC password credential configuration panel
///
typedef wxEAPCredentialsConfigPanel<eap::credentials_pass, wxGTCPasswordCredentialsPanel> wxGTCPasswordCredentialsConfigPanel;

/// @}

#pragma once

#include "../res/wxGTC_UI.h"

#include <Windows.h>

#pragma warning(push)
#pragma warning(disable: 26444)


/// \addtogroup EAPBaseGUI
/// @{

///
/// GTC configuration panel
///
class wxGTCConfigPanel : public wxGTCConfigPanelBase
{
public:
    ///
    /// Constructs a configuration panel
    ///
    wxGTCConfigPanel(const eap::config_provider &prov, eap::config_method_eapgtc &cfg, wxWindow* parent);

protected:
    /// \cond internal
    virtual bool TransferDataToWindow();
    virtual bool TransferDataFromWindow();
    virtual void OnUpdateUI(wxUpdateUIEvent& event);
    /// \endcond

protected:
    const eap::config_provider &m_prov;                         ///< EAP provider
    eap::config_method_eapgtc &m_cfg;                           ///< EAP-GTC configuration

    wxGTCResponseCredentialsConfigPanel *m_credentials_resp;    ///< Challenge/response credentials configuration panel
    wxGTCPasswordCredentialsConfigPanel *m_credentials_pass;    ///< Password credentials configuration panel

    // Temporary configurations to hold data until applied
    eap::config_method_eapgtc m_cfg_resp;                       ///< Method configuration for challenge/response mode
    eap::config_method_eapgtc m_cfg_pass;                       ///< Method configuration for password mode
};


///
/// GTC challenge/response dialog
///
class wxGTCResponseDialog : public wxEAPGeneralDialog
{
public:
    ///
    /// Constructs a credential dialog
    ///
    /// \param[in] prov    Provider configuration data
    /// \param[in] parent  Parent window
    /// \param[in] id      An identifier for the dialog. A value of -1 is taken to mean a default.
    /// \param[in] title   The title of the dialog
    /// \param[in] pos     The dialog position. The value \c wxDefaultPosition indicates a default position, chosen by either the windowing system or wxWidgets, depending on platform.
    /// \param[in] size    The dialog size. The value \c wxDefaultSize indicates a default size, chosen by either the windowing system or wxWidgets, depending on platform.
    /// \param[in] style   The window style
    ///
    wxGTCResponseDialog(const eap::config_provider &prov, wxWindow *parent, wxWindowID id = wxID_ANY, const wxString &title = _("GTC Challenge"), const wxPoint &pos = wxDefaultPosition, const wxSize &size = wxDefaultSize, long style = wxDEFAULT_DIALOG_STYLE);
};


///
/// GTC challenge/response panel
///
class wxGTCResponsePanel : public wxGTCResponsePanelBase
{
public:
    ///
    /// Constructs a panel
    ///
    /// \param[inout] response   GTC response
    /// \param[in   ] challenge  GTC challenge
    /// \param[in   ] parent     Parent window
    ///
    wxGTCResponsePanel(winstd::sanitizing_wstring &response, const wchar_t *challenge, wxWindow* parent);

protected:
    /// \cond internal
    virtual bool TransferDataToWindow();
    virtual bool TransferDataFromWindow();
    /// \endcond

protected:
    winstd::sanitizing_wstring &m_response_value;   ///< GTC response
};

/// @}

#pragma warning(pop)
