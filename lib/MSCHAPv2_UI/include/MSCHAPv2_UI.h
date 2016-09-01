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

#include "../../EAPBase_UI/include/EAP_UI.h"
#include "../../MSCHAPv2/include/Config.h"
#include "../../MSCHAPv2/include/Credentials.h"

///
/// MSCHAPv2 credential configuration panel
///
typedef wxEAPCredentialsConfigPanel<eap::credentials_mschapv2, wxPasswordCredentialsPanel<eap::credentials_mschapv2, wxEAPCredentialsPassPanelBase> > wxMSCHAPv2CredentialsConfigPanel;

///
/// MSCHAPv2 configuration panel
///
class wxMSCHAPv2ConfigPanel;

///
/// MSCHAPv2 credential entry panel
///
typedef wxPasswordCredentialsPanel<eap::credentials_mschapv2, wxEAPCredentialsPassPanelBase> wxMSCHAPv2CredentialsPanel;

#pragma once

#include <wx/panel.h>
#include <wx/stattext.h>

#include <Windows.h>


class wxMSCHAPv2ConfigPanel : public wxPanel
{
public:
    ///
    /// Constructs a configuration panel
    ///
    wxMSCHAPv2ConfigPanel(const eap::config_provider &prov, eap::config_method_mschapv2 &cfg, LPCTSTR pszCredTarget, wxWindow* parent);

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
