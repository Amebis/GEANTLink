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

#include <wx/filedlg.h>
#include <wx/msgdlg.h>

#include <Windows.h>
#include <cryptuiapi.h>
#include <WinCrypt.h> // Must include after <Windows.h>

#include <list>
#include <string>


///
/// Helper class for auto-destroyable certificates used in wxWidget's item containers
///
class wxCertificateClientData;

///
/// Validator for host name
///
class wxHostNameValidator;

///
/// Validator for FQDN
///
class wxFQDNValidator;

///
/// Validator for FQDN lists
///
class wxFQDNListValidator;

///
/// TLS credential panel
///
class wxTLSCredentialsPanel;

///
/// TLS server trust configuration panel
///
class wxTLSServerTrustPanel;

///
/// TLS credentials configuration panel
///
typedef wxEAPCredentialsConfigPanel<eap::credentials_tls, wxTLSCredentialsPanel> wxTLSCredentialsConfigPanel;

///
/// TLS configuration panel
///
class wxTLSConfigPanel;

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


class wxCertificateClientData : public wxClientData
{
public:
    ///
    /// Constructs client data object with existing handle
    ///
    wxCertificateClientData(PCCERT_CONTEXT cert);

    ///
    /// Releases certificate handle and destructs the object
    ///
    virtual ~wxCertificateClientData();

public:
    PCCERT_CONTEXT m_cert;  ///< Certificate
};


class wxHostNameValidator : public wxValidator
{
    wxDECLARE_DYNAMIC_CLASS(wxHostNameValidator);
    wxDECLARE_NO_ASSIGN_CLASS(wxHostNameValidator);

public:
    ///
    /// Construct the validator with a value to store data
    ///
    wxHostNameValidator(std::string *val = NULL);

    ///
    /// Copy constructor
    ///
    wxHostNameValidator(const wxHostNameValidator &other);

    ///
    /// Copies this validator
    ///
    virtual wxObject* Clone() const;

    ///
    /// Validates the value
    ///
    virtual bool Validate(wxWindow *parent);

    ///
    /// Transfers the value to the window
    ///
    virtual bool TransferToWindow();

    ///
    /// Transfers the value from the window
    ///
    virtual bool TransferFromWindow();

    ///
    /// Parses FQDN value
    ///
    static bool Parse(const wxString &val_in, size_t i_start, size_t i_end, wxTextCtrl *ctrl, wxWindow *parent, std::string *val_out = NULL);

protected:
    std::string *m_val; ///< Pointer to variable to receive control's parsed value
};


class wxFQDNValidator : public wxValidator
{
    wxDECLARE_DYNAMIC_CLASS(wxFQDNValidator);
    wxDECLARE_NO_ASSIGN_CLASS(wxFQDNValidator);

public:
    ///
    /// Construct the validator with a value to store data
    ///
    wxFQDNValidator(std::string *val = NULL);

    ///
    /// Copy constructor
    ///
    wxFQDNValidator(const wxFQDNValidator &other);

    ///
    /// Copies this validator
    ///
    virtual wxObject* Clone() const;

    ///
    /// Validates the value
    ///
    virtual bool Validate(wxWindow *parent);

    ///
    /// Transfers the value to the window
    ///
    virtual bool TransferToWindow();

    ///
    /// Transfers the value from the window
    ///
    virtual bool TransferFromWindow();

    ///
    /// Parses FQDN value
    ///
    static bool Parse(const wxString &val_in, size_t i_start, size_t i_end, wxTextCtrl *ctrl, wxWindow *parent, std::string *val_out = NULL);

protected:
    std::string *m_val; ///< Pointer to variable to receive control's parsed value
};


class wxFQDNListValidator : public wxValidator
{
    wxDECLARE_DYNAMIC_CLASS(wxFQDNListValidator);
    wxDECLARE_NO_ASSIGN_CLASS(wxFQDNListValidator);

public:
    ///
    /// Construct the validator with a value to store data
    ///
    wxFQDNListValidator(std::list<std::string> *val = NULL);

    ///
    /// Copy constructor
    ///
    wxFQDNListValidator(const wxFQDNListValidator &other);

    ///
    /// Copies this validator
    ///
    virtual wxObject* Clone() const;

    ///
    /// Validates the value
    ///
    virtual bool Validate(wxWindow *parent);

    ///
    /// Transfers the value to the window
    ///
    virtual bool TransferToWindow();

    ///
    /// Transfers the value from the window
    ///
    virtual bool TransferFromWindow();

    ///
    /// Parses FQDN list value
    ///
    static bool Parse(const wxString &val_in, size_t i_start, size_t i_end, wxTextCtrl *ctrl, wxWindow *parent, std::list<std::string> *val_out = NULL);

protected:
    std::list<std::string> *m_val;  ///< Pointer to variable to receive control's parsed value
};


class wxTLSCredentialsPanel : public wxEAPCredentialsPanelBase<wxTLSCredentialsPanelBase>
{
public:
    ///
    /// Constructs a configuration panel
    ///
    /// \param[in]    prov           Provider configuration data
    /// \param[in]    cfg            Configuration data
    /// \param[inout] cred           Credentials data
    /// \param[in]    pszCredTarget  Target name of credentials in Windows Credential Manager. Can be further decorated to create final target name.
    /// \param[in]    parent         Parent window
    /// \param[in]    is_config      Is this panel used to pre-enter credentials? When \c true, the "Remember" checkbox is always selected and disabled.
    ///
    wxTLSCredentialsPanel(const eap::config_provider &prov, const eap::config_method &cfg, eap::credentials &cred, LPCTSTR pszCredTarget, wxWindow* parent, bool is_config = false);

protected:
    /// \cond internal
    virtual bool TransferDataToWindow();
    virtual bool TransferDataFromWindow();
    virtual void OnCertSelect(wxCommandEvent& event);
    /// \endcond

protected:
    eap::credentials_tls &m_cred;   ///< TLS credentials
    winstd::library m_shell32;      ///< shell32.dll resource library reference
    wxIcon m_icon;                  ///< Panel icon
};


class wxTLSServerTrustPanel : public wxEAPTLSServerTrustConfigPanelBase
{
public:
    ///
    /// Constructs a configuration panel
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
    const eap::config_provider &m_prov;         ///< EAP provider
    eap::config_method_tls &m_cfg;              ///< TLS configuration
    winstd::library m_certmgr;                  ///< certmgr.dll resource library reference
    wxIcon m_icon;                              ///< Panel icon
    std::list<std::string> m_server_names_val;  ///< Acceptable authenticating server names
};


class wxTLSConfigPanel : public wxPanel
{
public:
    ///
    /// Constructs a configuration panel
    ///
    wxTLSConfigPanel(const eap::config_provider &prov, eap::config_method_tls &cfg, LPCTSTR pszCredTarget, wxWindow* parent);

    ///
    /// Destructs the configuration panel
    ///
    virtual ~wxTLSConfigPanel();

protected:
    /// \cond internal
    virtual void OnInitDialog(wxInitDialogEvent& event);
    /// \endcond

protected:
    wxTLSServerTrustPanel *m_server_trust;       ///< Server trust configuration panel
    wxTLSCredentialsConfigPanel *m_credentials;  ///< Credentials configuration panel
};
