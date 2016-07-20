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
#include "../../PAP/include/Config.h"
#include "../../PAP/include/Credentials.h"

///
/// PAP credential configuration panel
///
typedef wxEAPCredentialsConfigPanel<eap::config_method_pap, wxPasswordCredentialsPanel> wxPAPCredentialsConfigPanel;

///
/// PAP configuration panel
///
class wxPAPConfigPanel;

#pragma once

#include <wx/panel.h>
#include <wx/stattext.h>

#include <Windows.h>


class wxPAPConfigPanel : public wxPanel
{
public:
    ///
    /// Constructs a configuration panel
    ///
    wxPAPConfigPanel(const eap::config_provider &prov, eap::config_method_pap &cfg, LPCTSTR pszCredTarget, wxWindow* parent);

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
