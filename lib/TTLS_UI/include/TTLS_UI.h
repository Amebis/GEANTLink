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

///
/// EAPTTLS configuration panel
///
class wxEAPTTLSConfigPanel;

///
/// EAPTTLS configuration
///
class wxEAPTTLSConfig;

#pragma once

#include "../res/wxTTLS_UI.h"

#include "../../TLS_UI/include/TLS_UI.h"

#include "../../TTLS/include/Config.h"

#include <WinStd/Win.h>

#include <wx/choicebk.h>
#include <wx/icon.h>
#include <wx/scrolwin.h>
#include <wx/stattext.h>

#include <Windows.h>


class wxEAPTTLSConfigPanel : public wxEAPTTLSConfigPanelBase
{
public:
    ///
    /// Constructs a configuration panel
    ///
    wxEAPTTLSConfigPanel(eap::config_ttls &cfg, wxWindow* parent);

protected:
    /// \cond internal
    virtual bool TransferDataToWindow();
    virtual bool TransferDataFromWindow();
    virtual void OnOuterIdentityCustom(wxCommandEvent& event);
    /// \endcond

protected:
    eap::config_ttls &m_cfg;    ///< TLS configuration
    winstd::library m_shell32;  ///< shell32.dll resource library reference
    wxIcon m_icon;              ///< Panel icon
};


class wxEAPTTLSConfig : public wxScrolledWindow
{
public:
    ///
    /// Constructs a configuration panel
    ///
    /// \param[inout] cfg            Configuration data
    /// \param[in]    pszCredTarget  Target name of credentials in Windows Credential Manager. Can be further decorated to create final target name.
    /// \param[in]    parent         Parent window
    ///
    wxEAPTTLSConfig(eap::config_ttls &cfg, LPCTSTR pszCredTarget, wxWindow* parent);

    ///
    /// Destructs the configuration panel
    ///
    virtual ~wxEAPTTLSConfig();

protected:
    /// \cond internal
    virtual bool TransferDataToWindow();
    virtual bool TransferDataFromWindow();
    virtual void OnInitDialog(wxInitDialogEvent& event);
    /// \endcond

protected:
    eap::config_ttls &m_cfg;                        ///< TTLS configuration
    wxStaticText *m_outer_title;                    ///< Outer authentication title
    wxEAPTTLSConfigPanel *m_outer_identity;         ///< Outer identity configuration panel
    wxEAPTLSConfigPanel *m_tls;                     ///< TLS configuration panel
    wxStaticText *m_inner_title;                    ///< Inner authentication title
    wxChoicebook *m_inner_type;                     ///< Inner authentication type

    eap::config_pap m_cfg_pap;                      ///< Temporary PAP configuration
};
