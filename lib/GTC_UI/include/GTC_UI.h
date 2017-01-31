﻿/*
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

#include "../../EAPBase_UI/include/EAP_UI.h"
#include "../../GTC/include/Config.h"

class wxGTCConfigPanel;
class wxGTCResponsePanel;

/// \addtogroup EAPBaseGUI
/// @{

///
/// GTC credential entry panel
///
typedef wxIdentityCredentialsPanel<eap::credentials_identity, wxIdentityCredentialsPanelBase> wxGTCCredentialsPanel;

///
/// GTC credential configuration panel
///
typedef wxEAPCredentialsConfigPanel<eap::credentials_identity, wxGTCCredentialsPanel> wxGTCCredentialsConfigPanel;

/// @}

#pragma once

#include "../res/wxGTC_UI.h"

#include <wx/panel.h>
#include <wx/stattext.h>

#include <Windows.h>


/// \addtogroup EAPBaseGUI
/// @{

///
/// GTC configuration panel
///
class wxGTCConfigPanel : public wxPanel
{
public:
    ///
    /// Constructs a configuration panel
    ///
    wxGTCConfigPanel(const eap::config_provider &prov, eap::config_method_eapgtc &cfg, wxWindow* parent);

    ///
    /// Destructs the configuration panel
    ///
    virtual ~wxGTCConfigPanel();

protected:
    /// \cond internal
    virtual void OnInitDialog(wxInitDialogEvent& event);
    /// \endcond

protected:
    wxGTCCredentialsConfigPanel *m_credentials; ///< Credentials configuration panel
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
    wxGTCResponsePanel(const eap::config_provider &prov, eap::config_method_eapgtc &cfg, wxWindow* parent);
};

/// @}