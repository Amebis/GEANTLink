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

#include <Windows.h>
#include <WinCrypt.h> // Must include after <Windows.h>


///
/// Helper class for auto-destroyable certificates used in wxWidget's item containers
///
class wxCertificateClientData;

///
/// Helper class for auto-destroyable certificates used in wxWidget's item containers
///
class wxCertificateSelectionClientData;

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
/// EAPTLS credential panel
///
class wxEAPTLSCredentialsPanel;

///
/// EAPTLS server trust configuration panel
///
class wxEAPTLSServerTrustPanel;

///
/// TLS credentials configuration panel
///
typedef wxEAPCredentialsConfigPanel<eap::config_tls, eap::credentials_tls, wxEAPTLSCredentialsPanel> wxEAPTLSCredentialsConfigPanel;

///
/// EAPTLS configuration panel
///
class wxEAPTLSConfigPanel;

namespace eap
{
    ///
    /// Helper function to compile human-readable certificate name for UI display
    ///
    void get_cert_title(PCCERT_CONTEXT cert, winstd::tstring &title);
}

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


class wxCertificateSelectionClientData : public wxClientData
{
public:
    ///
    /// Default constructor
    ///
    wxCertificateSelectionClientData();

    ///
    /// Constructs client data object
    ///
    wxCertificateSelectionClientData(const wchar_t *identity, unsigned char *hash, size_t hash_size);

    ///
    /// Constructs client data object with copy
    ///
    wxCertificateSelectionClientData(const std::wstring &identity, const std::vector<unsigned char> &hash);

    ///
    /// Constructs client data object with move
    ///
    wxCertificateSelectionClientData(std::wstring &&identity, std::vector<unsigned char> &&hash);

    ///
    /// Constructs client data object with copy
    ///
    wxCertificateSelectionClientData(const wxCertificateSelectionClientData &other);

    ///
    /// Constructs client data object with move
    ///
    wxCertificateSelectionClientData(wxCertificateSelectionClientData &&other);

public:
    std::wstring m_identity;            ///< Client identity
    std::vector<unsigned char> m_hash;  ///< Client certificate hash (certificates are kept in Personal Certificate Storage)
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


class wxEAPTLSCredentialsPanel : public wxCredentialsPanel<wxEAPTLSCredentialsPanelBase, eap::credentials_tls>
{
public:
    ///
    /// Constructs a configuration panel
    ///
    wxEAPTLSCredentialsPanel(eap::credentials_tls &cred, LPCTSTR pszCredTarget, wxWindow* parent, bool is_config = false);

protected:
    /// \cond internal
    virtual bool TransferDataToWindow();
    virtual bool TransferDataFromWindow();
    virtual void OnCertSelect(wxCommandEvent& event);
    /// \endcond

protected:
    winstd::library m_shell32;  ///< shell32.dll resource library reference
    wxIcon m_icon;              ///< Panel icon
};


class wxEAPTLSServerTrustPanel : public wxEAPTLSServerTrustConfigPanelBase
{
public:
    ///
    /// Constructs a configuration panel
    ///
    wxEAPTLSServerTrustPanel(eap::config_tls &cfg, wxWindow* parent);

protected:
    /// \cond internal
    virtual bool TransferDataToWindow();
    virtual bool TransferDataFromWindow();
    virtual void OnRootCA(wxCommandEvent& event);
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
    eap::config_tls &m_cfg;     ///< TLS configuration
    winstd::library m_certmgr;  ///< certmgr.dll resource library reference
    wxIcon m_icon;              ///< Panel icon
};


class wxEAPTLSConfigPanel : public wxPanel
{
public:
    ///
    /// Constructs a configuration panel
    ///
    wxEAPTLSConfigPanel(eap::config_tls &cfg, LPCTSTR pszCredTarget, wxWindow* parent);

    ///
    /// Destructs the configuration panel
    ///
    virtual ~wxEAPTLSConfigPanel();

protected:
    /// \cond internal
    virtual void OnInitDialog(wxInitDialogEvent& event);
    /// \endcond

protected:
    wxEAPTLSServerTrustPanel *m_server_trust; ///< Server trust configuration panel
    wxEAPTLSCredentialsConfigPanel *m_credentials;  ///< Credentials configuration panel
};
