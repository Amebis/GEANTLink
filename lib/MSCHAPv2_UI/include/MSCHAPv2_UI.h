/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2020 Amebis
    Copyright © 2016 GÉANT
*/

#include "../../EAPBase_UI/include/EAP_UI.h"
#include "../../MSCHAPv2/include/Config.h"

class wxMSCHAPv2ConfigPanel;

/// \addtogroup EAPBaseGUI
/// @{

///
/// MSCHAPv2 credential entry panel
///
typedef wxPasswordCredentialsPanel<eap::credentials_pass, wxPasswordCredentialsPanelBase> wxMSCHAPv2CredentialsPanel;

///
/// MSCHAPv2 credential configuration panel
///
typedef wxEAPCredentialsConfigPanel<eap::credentials_pass, wxMSCHAPv2CredentialsPanel> wxMSCHAPv2CredentialsConfigPanel;

/// @}

#pragma once

#include <wx/panel.h>
#include <wx/stattext.h>

#include <Windows.h>


/// \addtogroup EAPBaseGUI
/// @{

///
/// MSCHAPv2 configuration panel
///
class wxMSCHAPv2ConfigPanel : public wxPanel
{
public:
    ///
    /// Constructs a configuration panel
    ///
    wxMSCHAPv2ConfigPanel(const eap::config_provider &prov, eap::config_method_mschapv2 &cfg, wxWindow* parent);

    ///
    /// Destructs the configuration panel
    ///
    virtual ~wxMSCHAPv2ConfigPanel();

protected:
    /// \cond internal
    virtual void OnInitDialog(wxInitDialogEvent& event);
    /// \endcond

protected:
    wxMSCHAPv2CredentialsConfigPanel *m_credentials; ///< Credentials configuration panel
};

/// @}
