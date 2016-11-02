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
#include "../../TLS/include/Config.h"
#include "../../TLS/include/Credentials.h"

#include <WinStd/Common.h>

#include <wx/arrstr.h>
#include <wx/filedlg.h>
#include <wx/msgdlg.h>

#include <Windows.h>
#include <cryptuiapi.h>
#include <WinCrypt.h> // Must include after <Windows.h>

#include <list>
#include <string>

class wxCertificateClientData;
class wxTLSCredentialsPanel;
class wxTLSServerTrustPanel;
class wxTLSConfigPanel;

/// \addtogroup EAPBaseGUI
/// @{

///
/// TLS credentials configuration panel
///
typedef wxEAPCredentialsConfigPanel<eap::credentials_tls, wxTLSCredentialsPanel> wxTLSCredentialsConfigPanel;

/// @}

#pragma once

#include "../res/wxTLS_UI.h"

#include <WinStd/Win.h>

#include <wx/clntdata.h>
#include <wx/icon.h>
#include <wx/panel.h>
#include <wx/textctrl.h>
#include <wx/validate.h>

#include <list>
#include <string>
#include <vector>


/// \addtogroup EAPBaseGUI
/// @{

///
/// Helper class for auto-destroyable certificates used in wxWidget's item containers
///
class wxCertificateClientData : public wxClientData
{
public:
    ///
    /// Constructs client data object with existing handle
    ///
    /// \param[in] cert  Certificate handle
    ///
    wxCertificateClientData(PCCERT_CONTEXT cert);

    ///
    /// Releases certificate handle and destructs the object
    ///
    virtual ~wxCertificateClientData();

public:
    PCCERT_CONTEXT m_cert;  ///< Certificate
};


///
/// TLS credential panel
///
class wxTLSCredentialsPanel : public wxEAPCredentialsPanel<eap::credentials_tls, wxTLSCredentialsPanelBase>
{
public:
    ///
    /// Constructs a TLS credentials panel
    ///
    /// \param[in]    prov       Provider configuration data
    /// \param[in]    cfg        Configuration data
    /// \param[inout] cred       Credentials data
    /// \param[in]    parent     Parent window
    /// \param[in]    is_config  Is this panel used to config credentials?
    ///
    wxTLSCredentialsPanel(const eap::config_provider &prov, const eap::config_method_with_cred &cfg, eap::credentials_tls &cred, wxWindow* parent, bool is_config = false);

protected:
    /// \cond internal
    virtual bool TransferDataToWindow();
    virtual bool TransferDataFromWindow();
    virtual void OnUpdateUI(wxUpdateUIEvent& event);
    /// \endcond
};


///
/// TLS server trust configuration panel
///
class wxTLSServerTrustPanel : public wxTLSServerTrustPanelBase
{
public:
    ///
    /// Constructs a configuration panel
    ///
    /// \param[in   ] prov    Provider configuration data
    /// \param[inout] cfg     Configuration data
    /// \param[in   ] parent  Parent window
    ///
    wxTLSServerTrustPanel(const eap::config_provider &prov, eap::config_method_tls &cfg, wxWindow* parent);

protected:
    /// \cond internal
    virtual bool TransferDataToWindow();
    virtual bool TransferDataFromWindow();
    virtual void OnUpdateUI(wxUpdateUIEvent& event);
    virtual void OnRootCADClick(wxCommandEvent& event);
    virtual void OnRootCAAddStore(wxCommandEvent& event);
    virtual void OnRootCAAddFile(wxCommandEvent& event);
    virtual void OnRootCARemove(wxCommandEvent& event);
    /// \endcond

    ///
    /// Adds a certificate to the list of trusted root CA list
    ///
    /// \param[in] cert  Certificate
    ///
    /// \returns
    /// - \c true  if certificate was added;
    /// - \c false if duplicate found or an error occured.
    ///
    bool AddRootCA(PCCERT_CONTEXT cert);

protected:
    const eap::config_provider &m_prov; ///< EAP provider
    eap::config_method_tls &m_cfg;      ///< TLS configuration
    wxArrayString m_server_names_val;   ///< Acceptable authenticating server names
};


///
/// TLS configuration panel
///
class wxTLSConfigPanel : public wxPanel
{
public:
    ///
    /// Constructs a configuration panel
    ///
    /// \param[in   ] prov    Provider configuration data
    /// \param[inout] cfg     Configuration data
    /// \param[in   ] parent  Parent window
    ///
    wxTLSConfigPanel(const eap::config_provider &prov, eap::config_method_tls &cfg, wxWindow* parent);

    ///
    /// Destructs the configuration panel
    ///
    virtual ~wxTLSConfigPanel();

protected:
    /// \cond internal
    virtual void OnInitDialog(wxInitDialogEvent& event);
    /// \endcond

protected:
    const eap::config_provider &m_prov;         ///< EAP provider
    eap::config_method_tls &m_cfg;              ///< TLS configuration
    wxTLSServerTrustPanel *m_server_trust;      ///< Server trust configuration panel
    wxTLSCredentialsConfigPanel *m_credentials; ///< Credentials configuration panel
};

/// @}
