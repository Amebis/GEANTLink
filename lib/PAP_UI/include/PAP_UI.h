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
/// PAP credentials configuration panel
///
template <class _Tprov> class wxPAPCredentialsConfigPanel;

///
/// PAP configuration panel
///
template <class _Tprov> class wxPAPConfigPanel;

#pragma once

#include <wx/panel.h>
#include <wx/stattext.h>

#include <Windows.h>


template <class _Tprov>
class wxPAPCredentialsConfigPanel : public wxEAPCredentialsConfigPanel<_Tprov, eap::config_pap, wxPasswordCredentialsPanel<_Tprov> >
{
public:
    ///
    /// Constructs a PAP credential configuration panel
    ///
    /// \param[inout] prov           Provider configuration data
    /// \param[inout] cfg            Configuration data
    /// \param[in]    pszCredTarget  Target name of credentials in Windows Credential Manager. Can be further decorated to create final target name.
    /// \param[in]    parent         Parent window
    ///
    wxPAPCredentialsConfigPanel(_Tprov &prov, eap::config_pap &cfg, LPCTSTR pszCredTarget, wxWindow *parent) :
        wxEAPCredentialsConfigPanel<_Tprov, eap::config_pap, wxPasswordCredentialsPanel<_Tprov> >(prov, cfg, pszCredTarget, parent)
    {
    }
};


template <class _Tprov>
class wxPAPConfigPanel : public wxPanel
{
public:
    ///
    /// Constructs a configuration panel
    ///
    wxPAPConfigPanel(_Tprov &prov, eap::config_pap &cfg, LPCTSTR pszCredTarget, wxWindow* parent) : wxPanel(parent)
    {
        wxBoxSizer* sb_content;
        sb_content = new wxBoxSizer( wxVERTICAL );

        m_credentials = new wxPAPCredentialsConfigPanel<_Tprov>(prov, cfg, pszCredTarget, this);
        sb_content->Add(m_credentials, 0, wxEXPAND, 5);

        this->SetSizer(sb_content);
        this->Layout();

        // Connect Events
        this->Connect(wxEVT_INIT_DIALOG, wxInitDialogEventHandler(wxPAPConfigPanel::OnInitDialog));
    }

    ///
    /// Destructs the configuration panel
    ///
    virtual ~wxPAPConfigPanel()
    {
        // Disconnect Events
        this->Disconnect(wxEVT_INIT_DIALOG, wxInitDialogEventHandler(wxPAPConfigPanel::OnInitDialog));
    }


protected:
    /// \cond internal

    virtual void OnInitDialog(wxInitDialogEvent& event)
    {
        // Forward the event to child panels.
        if (m_credentials)
            m_credentials->GetEventHandler()->ProcessEvent(event);
    }

    /// \endcond

protected:
    wxPAPCredentialsConfigPanel<_Tprov> *m_credentials; ///< Credentials configuration panel
};
