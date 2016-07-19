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

using namespace std;
using namespace winstd;


//////////////////////////////////////////////////////////////////////
// eap::get_cert_title
//////////////////////////////////////////////////////////////////////

tstring eap::get_cert_title(PCCERT_CONTEXT cert)
{
    tstring name, str, issuer, title;
    FILETIME ft;
    SYSTEMTIME st;

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

    return title;
}


//////////////////////////////////////////////////////////////////////
// eap::config_tls
//////////////////////////////////////////////////////////////////////

eap::config_tls::config_tls(_In_ module &mod) : config_method<credentials_tls>(mod)
{
}


eap::config_tls::config_tls(_In_ const config_tls &other) :
    m_trusted_root_ca(other.m_trusted_root_ca),
    m_server_names(other.m_server_names),
    config_method<credentials_tls>(other)
{
}


eap::config_tls::config_tls(_Inout_ config_tls &&other) :
    m_trusted_root_ca(std::move(other.m_trusted_root_ca)),
    m_server_names(std::move(other.m_server_names)),
    config_method<credentials_tls>(std::move(other))
{
}


eap::config_tls& eap::config_tls::operator=(_In_ const eap::config_tls &other)
{
    if (this != &other) {
        (config_method<credentials_tls>&)*this = other;
        m_trusted_root_ca = other.m_trusted_root_ca;
        m_server_names    = other.m_server_names;
    }

    return *this;
}


eap::config_tls& eap::config_tls::operator=(_Inout_ eap::config_tls &&other)
{
    if (this != &other) {
        (config_method<credentials_tls>&&)*this = std::move(other);
        m_trusted_root_ca = std::move(other.m_trusted_root_ca);
        m_server_names    = std::move(other.m_server_names);
    }

    return *this;
}


eap::config* eap::config_tls::clone() const
{
    return new config_tls(*this);
}


bool eap::config_tls::save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError) const
{
    const bstr bstrNamespace(L"urn:ietf:params:xml:ns:yang:ietf-eap-metadata");
    DWORD dwResult;
    HRESULT hr;

    if (!config_method<credentials_tls>::save(pDoc, pConfigRoot, ppEapError))
        return false;

    // <ServerSideCredential>
    com_obj<IXMLDOMElement> pXmlElServerSideCredential;
    if ((dwResult = eapxml::create_element(pDoc, pConfigRoot, bstr(L"eap-metadata:ServerSideCredential"), bstr(L"ServerSideCredential"), bstrNamespace, &pXmlElServerSideCredential)) != ERROR_SUCCESS) {
        *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <ServerSideCredential> element."));
        return false;
    }

    for (list<cert_context>::const_iterator i = m_trusted_root_ca.begin(), i_end = m_trusted_root_ca.end(); i != i_end; ++i) {
        // <CA>
        com_obj<IXMLDOMElement> pXmlElCA;
        if ((dwResult = eapxml::create_element(pDoc, bstr(L"CA"), bstrNamespace, &pXmlElCA))) {
            *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <CA> element."));
            return false;
        }

        // <CA>/<format>
        if ((dwResult = eapxml::put_element_value(pDoc, pXmlElCA, bstr(L"format"), bstrNamespace, bstr(L"PEM"))) != ERROR_SUCCESS) {
            *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <format> element."));
            return false;
        }

        // <CA>/<cert-data>
        const cert_context &cc = *i;
        if ((dwResult = eapxml::put_element_base64(pDoc, pXmlElCA, bstr(L"cert-data"), bstrNamespace, cc->pbCertEncoded, cc->cbCertEncoded)) != ERROR_SUCCESS) {
            *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <cert-data> element."));
            return false;
        }

        if (FAILED(hr = pXmlElServerSideCredential->appendChild(pXmlElCA, NULL))) {
            *ppEapError = m_module.make_error(HRESULT_CODE(hr), _T(__FUNCTION__) _T(" Error appending <CA> element."));
            return false;
        }
    }

    // <ServerName>
    for (list<string>::const_iterator i = m_server_names.begin(), i_end = m_server_names.end(); i != i_end; ++i) {
        wstring str;
        MultiByteToWideChar(CP_UTF8, 0, i->c_str(), (int)i->length(), str);
        if ((dwResult = eapxml::put_element_value(pDoc, pXmlElServerSideCredential, bstr(L"ServerName"), bstrNamespace, bstr(str))) != ERROR_SUCCESS) {
            *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <ServerName> element."));
            return false;
        }
    }

    return true;
}


bool eap::config_tls::load(_In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError)
{
    if (!config_method<credentials_tls>::load(pConfigRoot, ppEapError))
        return false;

    m_trusted_root_ca.clear();
    m_server_names.clear();

    // <ServerSideCredential>
    com_obj<IXMLDOMElement> pXmlElServerSideCredential;
    if (eapxml::select_element(pConfigRoot, bstr(L"eap-metadata:ServerSideCredential"), &pXmlElServerSideCredential) == ERROR_SUCCESS) {
        // <CA>
        com_obj<IXMLDOMNodeList> pXmlListCAs;
        long lCACount = 0;
        if (eapxml::select_nodes(pXmlElServerSideCredential, bstr(L"eap-metadata:CA"), &pXmlListCAs) == ERROR_SUCCESS && SUCCEEDED(pXmlListCAs->get_length(&lCACount))) {
            for (long j = 0; j < lCACount; j++) {
                // Load CA certificate.
                com_obj<IXMLDOMNode> pXmlElCA;
                pXmlListCAs->get_item(j, &pXmlElCA);
                bstr bstrFormat;
                if (eapxml::get_element_value(pXmlElCA, bstr(L"eap-metadata:format"), &bstrFormat) != ERROR_SUCCESS) {
                    // <format> not specified.
                    continue;
                }

                if (CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstrFormat, bstrFormat.length(), L"PEM", -1, NULL, NULL, 0) != CSTR_EQUAL) {
                    // Certificate must be PEM encoded.
                    continue;
                }

                vector<unsigned char> aData;
                if (eapxml::get_element_base64(pXmlElCA, bstr(L"eap-metadata:cert-data"), aData) != ERROR_SUCCESS) {
                    // Error reading <cert-data> element.
                    continue;
                }

                add_trusted_ca(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, aData.data(), (DWORD)aData.size());
            }
        }

        // <ServerName>
        com_obj<IXMLDOMNodeList> pXmlListServerIDs;
        long lServerIDCount = 0;
        if (eapxml::select_nodes(pXmlElServerSideCredential, bstr(L"eap-metadata:ServerName"), &pXmlListServerIDs) == ERROR_SUCCESS && SUCCEEDED(pXmlListServerIDs->get_length(&lServerIDCount))) {
            for (long j = 0; j < lServerIDCount; j++) {
                // Load server name (<ServerName>).
                com_obj<IXMLDOMNode> pXmlElServerID;
                pXmlListServerIDs->get_item(j, &pXmlElServerID);
                bstr bstrServerID;
                pXmlElServerID->get_text(&bstrServerID);

                // Server names (FQDNs) are always ASCII. Hopefully. Convert them to UTF-8 anyway for consistent comparison. CP_ANSI varies.
                string str;
                WideCharToMultiByte(CP_UTF8, 0, bstrServerID, bstrServerID.length(), str, NULL, NULL);

                    m_server_names.push_back(str);
            }
        }
    }

    return true;
}


eap::type_t eap::config_tls::get_method_id() const
{
    return eap::type_tls;
}


bool eap::config_tls::add_trusted_ca(_In_  DWORD dwCertEncodingType, _In_  const BYTE *pbCertEncoded, _In_  DWORD cbCertEncoded)
{
    cert_context cert;
    if (!cert.create(dwCertEncodingType, pbCertEncoded, cbCertEncoded)) {
        // Invalid or unsupported certificate.
        return false;
    }

    for (list<cert_context>::const_iterator i = m_trusted_root_ca.cbegin(), i_end = m_trusted_root_ca.cend();; ++i) {
        if (i != i_end) {
            if (*i == cert) {
                // This certificate is already on the list.
                return false;
            }
        } else {
            // End of list reached. Append certificate.
            m_trusted_root_ca.push_back(std::move(cert));
            return true;
        }
    }
}
