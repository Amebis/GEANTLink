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
/// TTLS configuration panel
///
class wxTTLSConfigPanel;

///
/// TTLS configuration scrollable window
///
class wxTTLSConfigWindow;

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


class wxTTLSConfigPanel : public wxTTLSConfigPanelBase
{
public:
    ///
    /// Constructs a configuration panel
    ///
    wxTTLSConfigPanel(const eap::config_provider &prov, eap::config_method_ttls &cfg, wxWindow* parent);

protected:
    /// \cond internal
    virtual bool TransferDataToWindow();
    virtual bool TransferDataFromWindow();
    virtual void OnUpdateUI(wxUpdateUIEvent& event);
    /// \endcond

protected:
    const eap::config_provider &m_prov; ///< EAP provider
    eap::config_method_ttls &m_cfg;     ///< TTLS configuration
    winstd::library m_shell32;          ///< shell32.dll resource library reference
    wxIcon m_icon;                      ///< Panel icon
};


class wxTTLSConfigWindow : public wxScrolledWindow
{
public:
    ///
    /// Constructs a configuration panel
    ///
    /// \param[inout] cfg            Configuration data
    /// \param[in]    pszCredTarget  Target name of credentials in Windows Credential Manager. Can be further decorated to create final target name.
    /// \param[in]    parent         Parent window
    ///
    wxTTLSConfigWindow(const eap::config_provider &prov, eap::config_method &cfg, LPCTSTR pszCredTarget, wxWindow* parent);

    ///
    /// Destructs the configuration panel
    ///
    virtual ~wxTTLSConfigWindow();

protected:
    /// \cond internal
    virtual bool TransferDataToWindow();
    virtual bool TransferDataFromWindow();
    virtual void OnInitDialog(wxInitDialogEvent& event);
    /// \endcond

protected:
    const eap::config_provider &m_prov;     ///< EAP provider
    eap::config_method_ttls &m_cfg;         ///< TTLS configuration
    wxStaticText *m_outer_title;            ///< Outer authentication title
    wxTTLSConfigPanel *m_outer_identity;    ///< Outer identity configuration panel
    wxTLSConfigPanel *m_tls;                ///< TLS configuration panel
    wxStaticText *m_inner_title;            ///< Inner authentication title
    wxChoicebook *m_inner_type;             ///< Inner authentication type

    // Temprary inner method configurations to hold data until applied
    eap::config_method_pap m_cfg_pap;            ///< PAP configuration
};
