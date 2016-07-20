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
/// EAPTLS credential panel
///
template <class _Tprov> class wxEAPTLSCredentialsPanel;

///
/// EAPTLS server trust configuration panel
///
template <class _Tprov> class wxEAPTLSServerTrustPanel;

///
/// TLS credentials configuration panel
///
template <class _Tprov> class wxEAPTLSCredentialsConfigPanel;

///
/// EAPTLS configuration panel
///
template <class _Tprov> class wxEAPTLSConfigPanel;

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


template <class _Tprov>
class wxEAPTLSCredentialsPanel : public wxCredentialsPanel<eap::credentials_tls, wxEAPTLSCredentialsPanelBase>
{
public:
    ///
    /// Constructs a configuration panel
    ///
    wxEAPTLSCredentialsPanel(_Tprov &prov, eap::credentials_tls &cred, LPCTSTR pszCredTarget, wxWindow* parent, bool is_config = false) :
        wxCredentialsPanel<eap::credentials_tls, wxEAPTLSCredentialsPanelBase>(cred, pszCredTarget, parent, is_config)
    {
        UNREFERENCED_PARAMETER(prov);

        // Load and set icon.
        if (m_shell32.load(_T("shell32.dll"), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE))
            wxSetIconFromResource(m_credentials_icon, m_icon, m_shell32, MAKEINTRESOURCE(269));
    }

protected:
    /// \cond internal

    virtual bool TransferDataToWindow()
    {
        // Populate certificate list.
        bool is_found = false;
        winstd::cert_store store;
        if (store.create(CERT_STORE_PROV_SYSTEM, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, (HCRYPTPROV)NULL, CERT_SYSTEM_STORE_CURRENT_USER, _T("My"))) {
            for (PCCERT_CONTEXT cert = NULL; (cert = CertEnumCertificatesInStore(store, cert)) != NULL;) {
                DWORD dwKeySpec = 0, dwSize = sizeof(dwKeySpec);
                if (!CertGetCertificateContextProperty(cert, CERT_KEY_SPEC_PROP_ID, &dwKeySpec, &dwSize) || !dwKeySpec) {
                    // Skip certificates without private key.
                    continue;
                }

                // Prepare certificate information.
                std::unique_ptr<wxCertificateClientData> data(new wxCertificateClientData(CertDuplicateCertificateContext(cert)));

                // Add to list.
                bool is_selected =
                    m_cred.m_cert &&
                    m_cred.m_cert->cbCertEncoded == data->m_cert->cbCertEncoded &&
                    memcmp(m_cred.m_cert->pbCertEncoded, data->m_cert->pbCertEncoded, m_cred.m_cert->cbCertEncoded) == 0;
                winstd::tstring name(std::move(eap::get_cert_title(cert)));
                int i = m_cert_select_val->Append(name, data.release());
                if (is_selected) {
                    m_cert_select_val->SetSelection(i);
                    is_found = true;
                }
            }
        }

        if (is_found) {
            m_cert_select    ->SetValue(true);
            m_cert_select_val->Enable(true);
        } else {
            m_cert_none      ->SetValue(true);
            m_cert_select_val->Enable(false);
            if (!m_cert_select_val->IsEmpty())
                m_cert_select_val->SetSelection(0);
        }

        return __super::TransferDataToWindow();
    }


    virtual bool TransferDataFromWindow()
    {
        if (m_cert_none->GetValue())
            m_cred.clear();
        else {
            const wxCertificateClientData *data = dynamic_cast<const wxCertificateClientData*>(m_cert_select_val->GetClientObject(m_cert_select_val->GetSelection()));
            if (data)
                m_cred.m_cert.attach_duplicated(data->m_cert);
            else
                m_cred.clear();
        }

        // Inherited TransferDataFromWindow() calls m_cred.store().
        // Therefore, call it only now, that m_cred is set.
        return __super::TransferDataFromWindow();
    }


    virtual void OnCertSelect(wxCommandEvent& event)
    {
        UNREFERENCED_PARAMETER(event);
        m_cert_select_val->Enable(m_cert_select->GetValue());
    }

    /// \endcond

protected:
    winstd::library m_shell32;  ///< shell32.dll resource library reference
    wxIcon m_icon;              ///< Panel icon
};


template <class _Tprov>
class wxEAPTLSServerTrustPanel : public wxEAPTLSServerTrustConfigPanelBase
{
public:
    ///
    /// Constructs a configuration panel
    ///
    wxEAPTLSServerTrustPanel(_Tprov &prov, eap::config_method_tls &cfg, wxWindow* parent) :
        m_prov(prov),
        m_cfg(cfg),
        wxEAPTLSServerTrustConfigPanelBase(parent)
    {
        // Load and set icon.
        if (m_certmgr.load(_T("certmgr.dll"), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE))
            wxSetIconFromResource(m_server_trust_icon, m_icon, m_certmgr, MAKEINTRESOURCE(218));

        // Do not use cfg.m_server_names directly, so we can decide not to store the value in case of provider-locked configuration.
        // Never rely on control disabled state alone, as they can be enabled using external tool like Spy++.
        m_server_names->SetValidator(wxFQDNListValidator(&m_server_names_val));
    }

protected:
    /// \cond internal

    virtual bool TransferDataToWindow()
    {
        if (m_prov.m_read_only) {
            // This is provider-locked configuration. Disable controls.
            m_root_ca_add_store->Enable(false);
            m_root_ca_add_file ->Enable(false);
            m_root_ca_remove   ->Enable(false);
            m_server_names     ->Enable(false);
        }

        // Populate trusted CA list.
        for (std::list<winstd::cert_context>::const_iterator cert = m_cfg.m_trusted_root_ca.cbegin(), cert_end = m_cfg.m_trusted_root_ca.cend(); cert != cert_end; ++cert)
            m_root_ca->Append(wxString(eap::get_cert_title(*cert)), new wxCertificateClientData(cert->duplicate()));

        // Set server acceptable names. The edit control will get populated by validator.
        m_server_names_val = m_cfg.m_server_names;

        return wxEAPTLSServerTrustConfigPanelBase::TransferDataToWindow();
    }


    virtual bool TransferDataFromWindow()
    {
        wxCHECK(wxEAPTLSServerTrustConfigPanelBase::TransferDataFromWindow(), false);

        if (!m_prov.m_read_only) {
            // This is not a provider-locked configuration. Save the data.

            // Parse trusted CA list.
            m_cfg.m_trusted_root_ca.clear();
            for (unsigned int i = 0, i_end = m_root_ca->GetCount(); i < i_end; i++) {
                wxCertificateClientData *cert = dynamic_cast<wxCertificateClientData*>(m_root_ca->GetClientObject(i));
                if (cert)
                    m_cfg.add_trusted_ca(cert->m_cert->dwCertEncodingType, cert->m_cert->pbCertEncoded, cert->m_cert->cbCertEncoded);
            }

            // Save acceptable server names.
            m_cfg.m_server_names = m_server_names_val;
        }

        return true;
    }


    virtual void OnUpdateUI(wxUpdateUIEvent& event)
    {
        UNREFERENCED_PARAMETER(event);

        if (!m_prov.m_read_only) {
            // This is not a provider-locked configuration. Selectively enable/disable controls.
            wxArrayInt selections;
            m_root_ca_remove->Enable(m_root_ca->GetSelections(selections) ? true : false);
        }
    }


    virtual void OnRootCADClick(wxCommandEvent& event)
    {
        wxCertificateClientData *cert = dynamic_cast<wxCertificateClientData*>(event.GetClientObject());
        if (cert)
            CryptUIDlgViewContext(CERT_STORE_CERTIFICATE_CONTEXT, cert->m_cert, this->GetHWND(), NULL, 0, NULL);
    }


    virtual void OnRootCAAddStore(wxCommandEvent& event)
    {
        UNREFERENCED_PARAMETER(event);

        winstd::cert_store store;
        if (store.create(NULL, _T("ROOT"))) {
            winstd::cert_context cert;
            cert.attach(CryptUIDlgSelectCertificateFromStore(store, this->GetHWND(), NULL, NULL, 0, 0, NULL));
            if (cert)
                AddRootCA(cert);
        }
    }


    virtual void OnRootCAAddFile(wxCommandEvent& event)
    {
        UNREFERENCED_PARAMETER(event);

        const wxString separator(wxT("|"));
        wxFileDialog open_dialog(this, _("Add Certificate"), wxEmptyString, wxEmptyString,
            _("Certificate Files (*.cer;*.crt;*.der;*.p7b;*.pem)") + separator + wxT("*.cer;*.crt;*.der;*.p7b;*.pem") + separator +
            _("X.509 Certificate Files (*.cer;*.crt;*.der;*.pem)") + separator + wxT("*.cer;*.crt;*.der;*.pem") + separator +
            _("PKCS #7 Certificate Files (*.p7b)") + separator + wxT("*.p7b") + separator +
            _("All Files (*.*)") + separator + wxT("*.*"),
            wxFD_OPEN|wxFD_FILE_MUST_EXIST|wxFD_MULTIPLE);
        if (open_dialog.ShowModal() == wxID_CANCEL) {
            event.Skip();
            return;
        }

        wxArrayString paths;
        open_dialog.GetPaths(paths);
        for (size_t i = 0, i_end = paths.GetCount(); i < i_end; i++) {
            // Load certificate(s) from file.
            winstd::cert_store cs;
            if (cs.create(CERT_STORE_PROV_FILENAME, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, NULL, CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, (LPCTSTR)(paths[i]))) {
                for (PCCERT_CONTEXT cert = NULL; (cert = CertEnumCertificatesInStore(cs, cert)) != NULL;)
                    AddRootCA(cert);
            } else
                wxMessageBox(wxString::Format(_("Invalid or unsupported certificate file %s"), paths[i]), _("Error"), wxOK | wxICON_EXCLAMATION, this);
        }
    }


    virtual void OnRootCARemove(wxCommandEvent& event)
    {
        UNREFERENCED_PARAMETER(event);

        wxArrayInt selections;
        for (int i = m_root_ca->GetSelections(selections); i--; )
            m_root_ca->Delete(selections[i]);
    }

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
    bool AddRootCA(PCCERT_CONTEXT cert)
    {
        for (unsigned int i = 0, i_end = m_root_ca->GetCount(); i < i_end; i++) {
            wxCertificateClientData *c = dynamic_cast<wxCertificateClientData*>(m_root_ca->GetClientObject(i));
            if (c && c->m_cert &&
                c->m_cert->cbCertEncoded == cert->cbCertEncoded &&
                memcmp(c->m_cert->pbCertEncoded, cert->pbCertEncoded, cert->cbCertEncoded) == 0)
            {
                // This certificate is already on the list.
                m_root_ca->SetSelection(i);
                return false;
            }
        }

        // Add certificate to the list.
        int i = m_root_ca->Append(wxString(eap::get_cert_title(cert)), new wxCertificateClientData(CertDuplicateCertificateContext(cert)));
        if (0 <= i)
            m_root_ca->SetSelection(i);

        return true;
    }

protected:
    _Tprov &m_prov;                             ///< EAP provider
    eap::config_method_tls &m_cfg;                     ///< TLS configuration
    winstd::library m_certmgr;                  ///< certmgr.dll resource library reference
    wxIcon m_icon;                              ///< Panel icon
    std::list<std::string> m_server_names_val;  ///< Acceptable authenticating server names
};


template <class _Tprov>
class wxEAPTLSCredentialsConfigPanel : public wxEAPCredentialsConfigPanel<_Tprov, eap::config_method_tls, wxEAPTLSCredentialsPanel<_Tprov> >
{
public:
    ///
    /// Constructs a credential configuration panel
    ///
    /// \param[inout] prov           Provider configuration data
    /// \param[inout] cfg            Configuration data
    /// \param[in]    pszCredTarget  Target name of credentials in Windows Credential Manager. Can be further decorated to create final target name.
    /// \param[in]    parent         Parent window
    ///
    wxEAPTLSCredentialsConfigPanel(_Tprov &prov, eap::config_method_tls &cfg, LPCTSTR pszCredTarget, wxWindow *parent) :
        wxEAPCredentialsConfigPanel<_Tprov, eap::config_method_tls, wxEAPTLSCredentialsPanel<_Tprov> >(prov, cfg, pszCredTarget, parent)
    {
    }
};


template <class _Tprov>
class wxEAPTLSConfigPanel : public wxPanel
{
public:
    ///
    /// Constructs a configuration panel
    ///
    wxEAPTLSConfigPanel(_Tprov &prov, eap::config_method_tls &cfg, LPCTSTR pszCredTarget, wxWindow* parent) : wxPanel(parent)
    {
        wxBoxSizer* sb_content;
        sb_content = new wxBoxSizer( wxVERTICAL );

        m_server_trust = new wxEAPTLSServerTrustPanel<_Tprov>(prov, cfg, this);
        sb_content->Add(m_server_trust, 0, wxDOWN|wxEXPAND, 5);

        m_credentials = new wxEAPTLSCredentialsConfigPanel<_Tprov>(prov, cfg, pszCredTarget, this);
        sb_content->Add(m_credentials, 0, wxUP|wxEXPAND, 5);

        this->SetSizer(sb_content);
        this->Layout();

        // Connect Events
        this->Connect(wxEVT_INIT_DIALOG, wxInitDialogEventHandler(wxEAPTLSConfigPanel::OnInitDialog));
    }


    ///
    /// Destructs the configuration panel
    ///
    virtual ~wxEAPTLSConfigPanel()
    {
        // Disconnect Events
        this->Disconnect(wxEVT_INIT_DIALOG, wxInitDialogEventHandler(wxEAPTLSConfigPanel::OnInitDialog));
    }

protected:
    /// \cond internal

    virtual void OnInitDialog(wxInitDialogEvent& event)
    {
        // Forward the event to child panels.
        m_server_trust->GetEventHandler()->ProcessEvent(event);
        if (m_credentials)
            m_credentials->GetEventHandler()->ProcessEvent(event);
    }

    /// \endcond

protected:
    wxEAPTLSServerTrustPanel<_Tprov> *m_server_trust;       ///< Server trust configuration panel
    wxEAPTLSCredentialsConfigPanel<_Tprov> *m_credentials;  ///< Credentials configuration panel
};
