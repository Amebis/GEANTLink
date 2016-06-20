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

#include "StdAfx.h"

#pragma comment(lib, "Cryptui.lib")
#pragma comment(lib, "Crypt32.lib")


//////////////////////////////////////////////////////////////////////
// eap::get_cert_title
//////////////////////////////////////////////////////////////////////

void eap::get_cert_title(PCCERT_CONTEXT cert, winstd::tstring &title)
{
    winstd::tstring name, str, issuer;
    FILETIME ft;
    SYSTEMTIME st;

    title.clear();

    // Prepare certificate information
    CertGetNameString(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, name);
    title += name;

    FileTimeToLocalFileTime(&(cert->pCertInfo->NotBefore), &ft);
    FileTimeToSystemTime(&ft, &st);
    GetDateFormat(LOCALE_USER_DEFAULT, DATE_SHORTDATE, &st, NULL, str);
    title += _T(", ");
    title += str;

    FileTimeToLocalFileTime(&(cert->pCertInfo->NotAfter ), &ft);
    FileTimeToSystemTime(&ft, &st);
    GetDateFormat(LOCALE_USER_DEFAULT, DATE_SHORTDATE, &st, NULL, str);
    title += _T('-');
    title += str;

    CertGetNameString(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, issuer);
    if (name != issuer) {
        title += _T(", ");
        title += issuer;
    }
}


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
// wxHostNameValidator
//////////////////////////////////////////////////////////////////////

wxIMPLEMENT_DYNAMIC_CLASS(wxHostNameValidator, wxValidator);


wxHostNameValidator::wxHostNameValidator(std::string *val) :
    m_val(val),
    wxValidator()
{
}


wxHostNameValidator::wxHostNameValidator(const wxHostNameValidator &other) :
    m_val(other.m_val),
    wxValidator(other)
{
}


wxObject* wxHostNameValidator::Clone() const
{
    return new wxHostNameValidator(*this);
}


bool wxHostNameValidator::Validate(wxWindow *parent)
{
    wxASSERT(GetWindow()->IsKindOf(CLASSINFO(wxTextCtrl)));
    wxTextCtrl *ctrl = (wxTextCtrl*)GetWindow();
    if (!ctrl->IsEnabled()) return true;

    wxString val(ctrl->GetValue());
    return Parse(val, 0, val.Length(), ctrl, parent);
}


bool wxHostNameValidator::TransferToWindow()
{
    wxASSERT(GetWindow()->IsKindOf(CLASSINFO(wxTextCtrl)));

    if (m_val)
        ((wxTextCtrl*)GetWindow())->SetValue(*m_val);

    return true;
}


bool wxHostNameValidator::TransferFromWindow()
{
    wxASSERT(GetWindow()->IsKindOf(CLASSINFO(wxTextCtrl)));
    wxTextCtrl *ctrl = (wxTextCtrl*)GetWindow();

    wxString val(ctrl->GetValue());
    return Parse(val, 0, val.Length(), ctrl, NULL, m_val);
}


bool wxHostNameValidator::Parse(const wxString &val_in, size_t i_start, size_t i_end, wxTextCtrl *ctrl, wxWindow *parent, std::string *val_out)
{
    const wxStringCharType *buf = val_in;

    size_t i = i_start;
    for (;;) {
        if (i >= i_end) {
            // End of host name found.
            if (val_out) val_out->assign(val_in.c_str() + i_start, i - i_start);
            return true;
        } else if (_tcschr(wxT("abcdefghijklmnopqrstuvwxyz0123456789-*"), buf[i])) {
            // Valid character found.
            i++;
        } else {
            // Invalid character found.
            ctrl->SetFocus();
            ctrl->SetSelection(i, i + 1);
            wxMessageBox(wxString::Format(_("Invalid character in host name found: %c"), buf[i]), _("Validation conflict"), wxOK | wxICON_EXCLAMATION, parent);
            return false;
        }
    }
}


//////////////////////////////////////////////////////////////////////
// wxFQDNValidator
//////////////////////////////////////////////////////////////////////

wxIMPLEMENT_DYNAMIC_CLASS(wxFQDNValidator, wxValidator);


wxFQDNValidator::wxFQDNValidator(std::string *val) :
    m_val(val),
    wxValidator()
{
}


wxFQDNValidator::wxFQDNValidator(const wxFQDNValidator &other) :
    m_val(other.m_val),
    wxValidator(other)
{
}


wxObject* wxFQDNValidator::Clone() const
{
    return new wxFQDNValidator(*this);
}


bool wxFQDNValidator::Validate(wxWindow *parent)
{
    wxASSERT(GetWindow()->IsKindOf(CLASSINFO(wxTextCtrl)));
    wxTextCtrl *ctrl = (wxTextCtrl*)GetWindow();
    if (!ctrl->IsEnabled()) return true;

    wxString val(ctrl->GetValue());
    return Parse(val, 0, val.Length(), ctrl, parent);
}


bool wxFQDNValidator::TransferToWindow()
{
    wxASSERT(GetWindow()->IsKindOf(CLASSINFO(wxTextCtrl)));

    if (m_val)
        ((wxTextCtrl*)GetWindow())->SetValue(*m_val);

    return true;
}


bool wxFQDNValidator::TransferFromWindow()
{
    wxASSERT(GetWindow()->IsKindOf(CLASSINFO(wxTextCtrl)));
    wxTextCtrl *ctrl = (wxTextCtrl*)GetWindow();

    wxString val(ctrl->GetValue());
    return Parse(val, 0, val.Length(), ctrl, NULL, m_val);
}


bool wxFQDNValidator::Parse(const wxString &val_in, size_t i_start, size_t i_end, wxTextCtrl *ctrl, wxWindow *parent, std::string *val_out)
{
    const wxStringCharType *buf = val_in;

    size_t i = i_start;
    for (;;) {
        const wxStringCharType *buf_next;
        if ((buf_next = wmemchr(buf + i, L'.', i_end - i)) != NULL) {
            // FQDN separator found.
            if (!wxHostNameValidator::Parse(val_in, i, buf_next - buf, ctrl, parent))
                return false;
            i = buf_next - buf + 1;
        } else if (wxHostNameValidator::Parse(val_in, i, i_end, ctrl, parent)) {
            // The rest of the FQDN parsed succesfully.
            if (val_out) val_out->assign(val_in.c_str() + i_start, i_end - i_start);
            return true;
        } else
            return false;
    }
}


//////////////////////////////////////////////////////////////////////
// wxFQDNListValidator
//////////////////////////////////////////////////////////////////////

wxIMPLEMENT_DYNAMIC_CLASS(wxFQDNListValidator, wxValidator);


wxFQDNListValidator::wxFQDNListValidator(std::list<std::string> *val) :
    m_val(val),
    wxValidator()
{
}


wxFQDNListValidator::wxFQDNListValidator(const wxFQDNListValidator &other) :
    m_val(other.m_val),
    wxValidator(other)
{
}


wxObject* wxFQDNListValidator::Clone() const
{
    return new wxFQDNListValidator(*this);
}


bool wxFQDNListValidator::Validate(wxWindow *parent)
{
    wxTextCtrl *ctrl = (wxTextCtrl*)GetWindow();
    if (!ctrl->IsEnabled()) return true;

    wxString val(ctrl->GetValue());
    return Parse(val, 0, val.Length(), ctrl, parent);
}


bool wxFQDNListValidator::TransferToWindow()
{
    wxASSERT(GetWindow()->IsKindOf(CLASSINFO(wxTextCtrl)));

    if (m_val) {
        wxString str;
        for (std::list<std::string>::const_iterator name = m_val->cbegin(), name_end = m_val->cend(); name != name_end; ++name) {
            if (!str.IsEmpty()) str += wxT("; ");
            str += *name;
        }
        ((wxTextCtrl*)GetWindow())->SetValue(str);
    }

    return true;
}


bool wxFQDNListValidator::TransferFromWindow()
{
    wxASSERT(GetWindow()->IsKindOf(CLASSINFO(wxTextCtrl)));
    wxTextCtrl *ctrl = (wxTextCtrl*)GetWindow();

    wxString val(ctrl->GetValue());
    return Parse(val, 0, val.Length(), ctrl, NULL, m_val);
}


bool wxFQDNListValidator::Parse(const wxString &val_in, size_t i_start, size_t i_end, wxTextCtrl *ctrl, wxWindow *parent, std::list<std::string> *val_out)
{
    const wxStringCharType *buf = val_in;
    std::string _fqdn, *fqdn = val_out ? &_fqdn : NULL;
    std::list<std::string> _val_out;

    size_t i = i_start;
    for (;;) {
        // Skip initial white-space.
        for (; i < i_end && _istspace(buf[i]); i++);

        const wxStringCharType *buf_next;
        if ((buf_next = wmemchr(buf + i, L';', i_end - i)) != NULL) {
            // FQDN list separator found.

            // Skip trailing white-space.
            size_t i_next = buf_next - buf;
            for (; i < i_next && _istspace(buf[i_next - 1]); i_next--);

            if (!wxFQDNValidator::Parse(val_in, i, i_next, ctrl, parent, fqdn))
                return false;
            if (fqdn && !fqdn->empty()) _val_out.push_back(std::move(*fqdn));

            i = buf_next - buf + 1;
        } else {
            // Skip trailing white-space.
            for (; i < i_end && _istspace(buf[i_end - 1]); i_end--);

            if (wxFQDNValidator::Parse(val_in, i, i_end, ctrl, parent, fqdn)) {
                // The rest of the FQDN list parsed succesfully.
                if (fqdn && !fqdn->empty()) _val_out.push_back(std::move(*fqdn));
                if (val_out) *val_out = std::move(_val_out);
                return true;
            } else
                return false;
        }
    }
}
