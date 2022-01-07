/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2022 Amebis
    Copyright © 2016 GÉANT
*/

#include "PCH.h"

#pragma comment(lib, "Crypt32.lib")


//////////////////////////////////////////////////////////////////////
// wxCertificateClientData
//////////////////////////////////////////////////////////////////////

wxCertificateClientData::wxCertificateClientData(PCCERT_CONTEXT cert) : m_cert(cert)
{
}


wxCertificateClientData::~wxCertificateClientData()
{
    if (m_cert)
        CertFreeCertificateContext(m_cert);
}


//////////////////////////////////////////////////////////////////////
// wxCertificateValidator
//////////////////////////////////////////////////////////////////////

wxIMPLEMENT_DYNAMIC_CLASS(wxCertificateValidator, wxValidator);


wxCertificateValidator::wxCertificateValidator(wxCertificateHashClientData *val) :
    m_val(val),
    wxValidator()
{
}


wxObject* wxCertificateValidator::Clone() const
{
    return new wxCertificateValidator(*this);
}


bool wxCertificateValidator::Validate(wxWindow *parent)
{
    wxChoice *ctrl = (wxChoice*)GetWindow();
    if (!ctrl || !ctrl->IsEnabled()) return true;

    int sel = ctrl->GetSelection();
    const wxCertificateHashClientData *val =
        sel != wxNOT_FOUND && ctrl->HasClientObjectData() ?
            dynamic_cast<const wxCertificateHashClientData*>(ctrl->GetClientObject(sel)) :
            NULL;

    return Parse(val, ctrl, parent);
}


bool wxCertificateValidator::TransferToWindow()
{
    wxASSERT(GetWindow()->IsKindOf(CLASSINFO(wxChoice)));
    wxChoice *ctrl = (wxChoice*)GetWindow();

    if (m_val) {
        if (ctrl->HasClientObjectData()) {
            for (unsigned int i = 0, n = ctrl->GetCount(); i < n; i++) {
                const wxCertificateHashClientData *val = dynamic_cast<const wxCertificateHashClientData*>(ctrl->GetClientObject(i));
                if (val && m_val->m_cert_hash == val->m_cert_hash) {
                    ctrl->SetSelection(i);
                    return true;
                }
            }
        }
        ctrl->SetSelection(wxNOT_FOUND);
    }

    return true;
}


bool wxCertificateValidator::TransferFromWindow()
{
    wxASSERT(GetWindow()->IsKindOf(CLASSINFO(wxChoice)));
    wxChoice *ctrl = (wxChoice*)GetWindow();

    int sel = ctrl->GetSelection();
    const wxCertificateHashClientData *val =
        sel != wxNOT_FOUND && ctrl->HasClientObjectData() ?
            dynamic_cast<const wxCertificateHashClientData*>(ctrl->GetClientObject(sel)) :
            NULL;

    return Parse(val, ctrl, NULL, m_val);
}


bool wxCertificateValidator::Parse(const wxCertificateHashClientData *val_in, wxChoice *ctrl, wxWindow *parent, wxCertificateHashClientData *val_out)
{
    if (!val_in) {
        ctrl->SetFocus();
        wxMessageBox(_("No certificate selected"), _("Validation conflict"), wxOK | wxICON_EXCLAMATION, parent);
        return false;
    }

    if (val_out) val_out->m_cert_hash = val_in->m_cert_hash;
    return true;
}


//////////////////////////////////////////////////////////////////////
// wxTLSCredentialsPanel
//////////////////////////////////////////////////////////////////////

wxTLSCredentialsPanel::wxTLSCredentialsPanel(const eap::config_provider &prov, const eap::config_method_with_cred &cfg, eap::credentials_tls &cred, wxWindow* parent, bool is_config) :
    wxEAPCredentialsPanel<eap::credentials_tls, wxTLSCredentialsPanelBase>(prov, cfg, cred, parent, is_config)
{
    // Load and set icon.
    winstd::library lib_shell32;
    if (lib_shell32.load(_T("certmgr.dll"), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE))
        m_credentials_icon->SetIcon(wxLoadIconFromResource(lib_shell32, MAKEINTRESOURCE(6170)));

    // Populate certificate list.
    winstd::cert_store store;
    if (store.create(CERT_STORE_PROV_SYSTEM, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, (HCRYPTPROV)NULL, CERT_SYSTEM_STORE_CURRENT_USER, _T("My"))) {
        for (PCCERT_CONTEXT cert = NULL; (cert = CertEnumCertificatesInStore(store, cert)) != NULL;) {
            DWORD dwKeySpec = 0, dwSize = sizeof(dwKeySpec);
            if (!CertGetCertificateContextProperty(cert, CERT_KEY_SPEC_PROP_ID, &dwKeySpec, &dwSize) || !dwKeySpec) {
                // Skip certificates without private key.
                continue;
            }

            // Prepare certificate information.
            std::unique_ptr<wxCertificateHashClientData> data(new wxCertificateHashClientData);
            if (!CertGetCertificateContextProperty(cert, CERT_HASH_PROP_ID, data->m_cert_hash)) {
                // Skip certificates we cannot get thumbprint for.
                continue;
            }

            // Add to list.
            winstd::tstring name(std::move(eap::get_cert_title(cert)));
            m_certificate->Append(name, data.release());
        }
    }

    m_certificate->SetValidator(wxCertificateValidator(&m_certificate_val));
}


/// \cond internal

bool wxTLSCredentialsPanel::TransferDataToWindow()
{
    // Set client certificate hash. The wxChoice control will set selection using validator.
    m_certificate_val.m_cert_hash = m_cred.m_cert_hash;

    m_identity->SetValue(m_cred.m_identity);

    return wxEAPCredentialsPanel<eap::credentials_tls, wxTLSCredentialsPanelBase>::TransferDataToWindow();
}


bool wxTLSCredentialsPanel::TransferDataFromWindow()
{
    if (!wxEAPCredentialsPanel<eap::credentials_tls, wxTLSCredentialsPanelBase>::TransferDataFromWindow())
        return false;

    m_cred.m_cert_hash = m_certificate_val.m_cert_hash;
    m_cred.m_identity  = m_identity->GetValue();

    return true;
}


void wxTLSCredentialsPanel::OnUpdateUI(wxUpdateUIEvent& event)
{
    wxEAPCredentialsPanel<eap::credentials_tls, wxTLSCredentialsPanelBase>::OnUpdateUI(event);

    if (!m_is_config && m_cfg.m_use_cred) {
        // Credential prompt mode & Using configured credentials
        m_certificate->Enable(false);
        m_identity   ->Enable(false);
    } else {
        // Configuration mode or using stored credentials. Enable controls.
        m_certificate->Enable(true);
        m_identity   ->Enable(true);
    }
}

/// \endcond


//////////////////////////////////////////////////////////////////////
// wxTLSServerTrustPanel
//////////////////////////////////////////////////////////////////////

wxTLSServerTrustPanel::wxTLSServerTrustPanel(const eap::config_provider &prov, eap::config_method_tls &cfg, wxWindow* parent) :
    m_prov(prov),
    m_cfg(cfg),
    wxTLSServerTrustPanelBase(parent)
{
    // Load and set icon.
    winstd::library lib_certmgr;
    if (lib_certmgr.load(_T("certmgr.dll"), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE))
        m_server_trust_icon->SetIcon(wxLoadIconFromResource(lib_certmgr, MAKEINTRESOURCE(379)));

    // Do not use cfg.m_server_names directly, so we can decide not to store the value in case of provider-locked configuration.
    // Never rely on control disabled state alone, as they can be enabled using external tool like Spy++.
    m_server_names->SetValidator(wxFQDNListValidator(&m_server_names_val));
}


/// \cond internal

bool wxTLSServerTrustPanel::TransferDataToWindow()
{
    // Populate trusted CA list.
    for (auto cert = m_cfg.m_trusted_root_ca.cbegin(), cert_end = m_cfg.m_trusted_root_ca.cend(); cert != cert_end; ++cert)
        m_root_ca->Append(wxString(eap::get_cert_title(*cert)), new wxCertificateClientData(cert->duplicate()));

    // Set server acceptable names. The edit control will get populated by validator.
    m_server_names_val.clear();
    for (auto name = m_cfg.m_server_names.cbegin(), name_end = m_cfg.m_server_names.cend(); name != name_end; ++name)
        m_server_names_val.push_back(*name);

    return wxTLSServerTrustPanelBase::TransferDataToWindow();
}


bool wxTLSServerTrustPanel::TransferDataFromWindow()
{
    wxCHECK(wxTLSServerTrustPanelBase::TransferDataFromWindow(), false);

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
        m_cfg.m_server_names.clear();
        for (wxArrayString::const_iterator name = m_server_names_val.begin(), name_end = m_server_names_val.end(); name != name_end; ++name)
            m_cfg.m_server_names.push_back(std::wstring(*name));
    }

    return true;
}


void wxTLSServerTrustPanel::OnUpdateUI(wxUpdateUIEvent& event)
{
    wxTLSServerTrustPanelBase::OnUpdateUI(event);

    if (m_prov.m_read_only) {
        // This is provider-locked configuration. Disable controls.
        m_root_ca_add_store->Enable(false);
        m_root_ca_add_file ->Enable(false);
        m_root_ca_remove   ->Enable(false);
        m_server_names     ->Enable(false);
    } else {
        // This is not a provider-locked configuration. Selectively enable/disable controls.
        m_root_ca_add_store->Enable(true);
        m_root_ca_add_file ->Enable(true);
        m_root_ca_remove   ->Enable(m_root_ca->HasMultipleSelection() && ListBox_GetSelCount(m_root_ca->GetHWND()) > 0 || m_root_ca->GetSelection() != wxNOT_FOUND); // *
        m_server_names     ->Enable(true);

        // * ListBox_GetSelCount() is not cross-platform, but this is Windows EAP supplicant,
        //   and this is the fastest way to find out if there is a selection in the list box,
        //   observing wxWidgets 3.0.2 has nothing faster to offer.
    }
}


void wxTLSServerTrustPanel::OnRootCADClick(wxCommandEvent& event)
{
    wxTLSServerTrustPanelBase::OnRootCADClick(event);

    wxCertificateClientData *cert = dynamic_cast<wxCertificateClientData*>(event.GetClientObject());
    if (cert) {
        #pragma warning(suppress: 6387) // The pvReserved parameter is annotated as _In_
        CryptUIDlgViewContext(CERT_STORE_CERTIFICATE_CONTEXT, cert->m_cert, this->GetHWND(), NULL, 0, NULL);
    }
}


void wxTLSServerTrustPanel::OnRootCAAddStore(wxCommandEvent& event)
{
    wxTLSServerTrustPanelBase::OnRootCAAddStore(event);

    winstd::cert_store store;
    if (store.create(NULL, _T("ROOT"))) {
        winstd::cert_context cert;
        #pragma warning(suppress: 6387) // The pvReserved parameter is annotated as _In_
        cert.attach(CryptUIDlgSelectCertificateFromStore(store, this->GetHWND(), NULL, NULL, 0, 0, NULL));
        if (cert)
            AddRootCA(cert);
    }
}


void wxTLSServerTrustPanel::OnRootCAAddFile(wxCommandEvent& event)
{
    wxTLSServerTrustPanelBase::OnRootCAAddFile(event);

    const wxString separator(wxT("|"));
    wxFileDialog open_dialog(this, _("Add Certificate"), wxEmptyString, wxEmptyString,
        _("Certificate Files (*.cer;*.crt;*.der;*.p7b;*.pem)") + separator + wxT("*.cer;*.crt;*.der;*.p7b;*.pem") + separator +
        _("X.509 Certificate Files (*.cer;*.crt;*.der;*.pem)") + separator + wxT("*.cer;*.crt;*.der;*.pem") + separator +
        _("PKCS #7 Certificate Files (*.p7b)") + separator + wxT("*.p7b") + separator +
        _("All Files (*.*)") + separator + wxT("*.*"),
        wxFD_OPEN|wxFD_FILE_MUST_EXIST|wxFD_MULTIPLE);
    if (open_dialog.ShowModal() == wxID_CANCEL)
        return;

    wxArrayString paths;
    open_dialog.GetPaths(paths);
    for (size_t i = 0, i_end = paths.GetCount(); i < i_end; i++) {
        // Load certificate(s) from file.
        winstd::cert_store cs;
        if (cs.create(CERT_STORE_PROV_FILENAME, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, NULL, CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, static_cast<LPCTSTR>(paths[i]))) {
            for (PCCERT_CONTEXT cert = NULL; (cert = CertEnumCertificatesInStore(cs, cert)) != NULL;)
                AddRootCA(cert);
        } else
            wxMessageBox(wxString::Format(_("Invalid or unsupported certificate file %s"), paths[i]), _("Error"), wxOK | wxICON_EXCLAMATION, this);
    }
}


void wxTLSServerTrustPanel::OnRootCARemove(wxCommandEvent& event)
{
    wxTLSServerTrustPanelBase::OnRootCARemove(event);

    wxArrayInt selections;
    for (int i = m_root_ca->GetSelections(selections); i--; )
        m_root_ca->Delete(selections[i]);
}

/// \endcond


bool wxTLSServerTrustPanel::AddRootCA(PCCERT_CONTEXT cert)
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


//////////////////////////////////////////////////////////////////////
// wxTLSConfigPanel
//////////////////////////////////////////////////////////////////////

wxTLSConfigPanel::wxTLSConfigPanel(const eap::config_provider &prov, eap::config_method_tls &cfg, wxWindow* parent) :
    m_prov(prov),
    m_cfg(cfg),
    wxPanel(parent)
{
    wxBoxSizer* sb_content;
    sb_content = new wxBoxSizer( wxVERTICAL );

    m_server_trust = new wxTLSServerTrustPanel(prov, cfg, this);
    sb_content->Add(m_server_trust, 0, wxDOWN|wxEXPAND, FromDIP(5));

    m_credentials = new wxTLSCredentialsConfigPanel(prov, cfg, this, _("User Certificate"));
    sb_content->Add(m_credentials, 0, wxUP|wxEXPAND, FromDIP(5));

    this->SetSizer(sb_content);
    this->Layout();

    // Connect Events
    this->Connect(wxEVT_INIT_DIALOG, wxInitDialogEventHandler(wxTLSConfigPanel::OnInitDialog));
}


wxTLSConfigPanel::~wxTLSConfigPanel()
{
    // Disconnect Events
    this->Disconnect(wxEVT_INIT_DIALOG, wxInitDialogEventHandler(wxTLSConfigPanel::OnInitDialog));
}


/// \cond internal
void wxTLSConfigPanel::OnInitDialog(wxInitDialogEvent& event)
{
    // Forward the event to child panels.
    m_server_trust->GetEventHandler()->ProcessEvent(event);
    if (m_credentials)
        m_credentials->GetEventHandler()->ProcessEvent(event);
}
/// \endcond
