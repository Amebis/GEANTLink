/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2020 Amebis
    Copyright © 2016 GÉANT
*/

#include "../../EAPBase_UI/include/EAP_UI.h"
#include "../../PAP/include/Config.h"

class wxPAPConfigPanel;

/// \addtogroup EAPBaseGUI
/// @{

///
/// PAP credential entry panel
///
typedef wxPasswordCredentialsPanel<eap::credentials_pass, wxPasswordCredentialsPanelBase> wxPAPCredentialsPanel;

///
/// PAP credential configuration panel
///
typedef wxEAPCredentialsConfigPanel<eap::credentials_pass, wxPAPCredentialsPanel> wxPAPCredentialsConfigPanel;

/// @}

#pragma once

#include <wx/panel.h>
#include <wx/stattext.h>

#include <Windows.h>


/// \addtogroup EAPBaseGUI
/// @{

///
/// PAP configuration panel
///
class wxPAPConfigPanel : public wxPanel
{
public:
    ///
    /// Constructs a configuration panel
    ///
    wxPAPConfigPanel(const eap::config_provider &prov, eap::config_method_pap &cfg, wxWindow* parent);

    ///
    /// Destructs the configuration panel
    ///
    virtual ~wxPAPConfigPanel();

protected:
    /// \cond internal
    virtual void OnInitDialog(wxInitDialogEvent& event);
    /// \endcond

protected:
    wxPAPCredentialsConfigPanel *m_credentials; ///< Credentials configuration panel
};

/// @}
