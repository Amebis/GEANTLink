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
// eap::config_method_tls
//////////////////////////////////////////////////////////////////////

eap::config_method_tls::config_method_tls(_In_ module &mod) : config_method_with_cred(mod)
{
    m_preshared.reset(new credentials_tls(mod));
}


eap::config_method_tls::config_method_tls(_In_ const config_method_tls &other) :
    m_trusted_root_ca(other.m_trusted_root_ca),
    m_server_names(other.m_server_names),
#if EAP_TLS < EAP_TLS_SCHANNEL
    m_session_id(other.m_session_id),
    m_master_secret(other.m_master_secret),
#endif
    config_method_with_cred(other)
{
}


eap::config_method_tls::config_method_tls(_Inout_ config_method_tls &&other) :
    m_trusted_root_ca(std::move(other.m_trusted_root_ca)),
    m_server_names(std::move(other.m_server_names)),
#if EAP_TLS < EAP_TLS_SCHANNEL
    m_session_id(std::move(other.m_session_id)),
    m_master_secret(std::move(other.m_master_secret)),
#endif
    config_method_with_cred(std::move(other))
{
}


eap::config_method_tls& eap::config_method_tls::operator=(_In_ const config_method_tls &other)
{
    if (this != &other) {
        (config_method_with_cred&)*this = other;
        m_trusted_root_ca = other.m_trusted_root_ca;
        m_server_names    = other.m_server_names;
#if EAP_TLS < EAP_TLS_SCHANNEL
        m_session_id      = other.m_session_id;
        m_master_secret   = other.m_master_secret;
#endif
    }

    return *this;
}


eap::config_method_tls& eap::config_method_tls::operator=(_Inout_ config_method_tls &&other)
{
    if (this != &other) {
        (config_method_with_cred&&)*this = std::move(other);
        m_trusted_root_ca = std::move(other.m_trusted_root_ca);
        m_server_names    = std::move(other.m_server_names);
#if EAP_TLS < EAP_TLS_SCHANNEL
        m_session_id      = std::move(other.m_session_id);
        m_master_secret   = std::move(other.m_master_secret);
#endif
    }

    return *this;
}


eap::config* eap::config_method_tls::clone() const
{
    return new config_method_tls(*this);
}


void eap::config_method_tls::save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot) const
{
    assert(pDoc);
    assert(pConfigRoot);

    config_method_with_cred::save(pDoc, pConfigRoot);

    const bstr bstrNamespace(L"urn:ietf:params:xml:ns:yang:ietf-eap-metadata");
    HRESULT hr;

    // <ServerSideCredential>
    com_obj<IXMLDOMElement> pXmlElServerSideCredential;
    if (FAILED(hr = eapxml::create_element(pDoc, pConfigRoot, bstr(L"eap-metadata:ServerSideCredential"), bstr(L"ServerSideCredential"), bstrNamespace, &pXmlElServerSideCredential)))
        throw com_runtime_error(hr, __FUNCTION__ " Error creating <ServerSideCredential> element.");

    for (list<cert_context>::const_iterator i = m_trusted_root_ca.begin(), i_end = m_trusted_root_ca.end(); i != i_end; ++i) {
        // <CA>
        com_obj<IXMLDOMElement> pXmlElCA;
        if (FAILED(hr = eapxml::create_element(pDoc, bstr(L"CA"), bstrNamespace, &pXmlElCA)))
            throw com_runtime_error(hr, __FUNCTION__ " Error creating <CA> element.");

        // <CA>/<format>
        if (FAILED(hr = eapxml::put_element_value(pDoc, pXmlElCA, bstr(L"format"), bstrNamespace, bstr(L"PEM"))))
            throw com_runtime_error(hr, __FUNCTION__ " Error creating <format> element.");

        // <CA>/<cert-data>
        const cert_context &cc = *i;
        if (FAILED(hr = eapxml::put_element_base64(pDoc, pXmlElCA, bstr(L"cert-data"), bstrNamespace, cc->pbCertEncoded, cc->cbCertEncoded)))
            throw com_runtime_error(hr, __FUNCTION__ " Error creating <cert-data> element.");

        if (FAILED(hr = pXmlElServerSideCredential->appendChild(pXmlElCA, NULL)))
            throw com_runtime_error(hr, __FUNCTION__ " Error appending <CA> element.");
    }

    // <ServerName>
    for (list<wstring>::const_iterator i = m_server_names.begin(), i_end = m_server_names.end(); i != i_end; ++i) {
        if (FAILED(hr = eapxml::put_element_value(pDoc, pXmlElServerSideCredential, bstr(L"ServerName"), bstrNamespace, bstr(*i))))
            throw com_runtime_error(hr, __FUNCTION__ " Error creating <ServerName> element.");
    }
}


void eap::config_method_tls::load(_In_ IXMLDOMNode *pConfigRoot)
{
    assert(pConfigRoot);

    config_method_with_cred::load(pConfigRoot);

    std::wstring xpath(eapxml::get_xpath(pConfigRoot));

    m_trusted_root_ca.clear();
    m_server_names.clear();

    // <ServerSideCredential>
    com_obj<IXMLDOMElement> pXmlElServerSideCredential;
    if (SUCCEEDED(eapxml::select_element(pConfigRoot, bstr(L"eap-metadata:ServerSideCredential"), &pXmlElServerSideCredential))) {
        std::wstring xpathServerSideCredential(xpath + L"/ServerSideCredential");

        // <CA>
        com_obj<IXMLDOMNodeList> pXmlListCAs;
        long lCACount = 0;
        if (SUCCEEDED(eapxml::select_nodes(pXmlElServerSideCredential, bstr(L"eap-metadata:CA"), &pXmlListCAs)) && SUCCEEDED(pXmlListCAs->get_length(&lCACount))) {
            for (long j = 0; j < lCACount; j++) {
                // Load CA certificate.
                com_obj<IXMLDOMNode> pXmlElCA;
                pXmlListCAs->get_item(j, &pXmlElCA);
                bstr bstrFormat;
                if (FAILED(eapxml::get_element_value(pXmlElCA, bstr(L"eap-metadata:format"), &bstrFormat))) {
                    // <format> not specified.
                    continue;
                }

                if (CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstrFormat, bstrFormat.length(), L"PEM", -1, NULL, NULL, 0) != CSTR_EQUAL) {
                    // Certificate must be PEM encoded.
                    continue;
                }

                vector<unsigned char> aData;
                if (FAILED(eapxml::get_element_base64(pXmlElCA, bstr(L"eap-metadata:cert-data"), aData))) {
                    // Error reading <cert-data> element.
                    continue;
                }

                add_trusted_ca(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, aData.data(), (DWORD)aData.size());
            }

            // Log loaded CA certificates.
            list<tstring> cert_names;
            for (std::list<winstd::cert_context>::const_iterator cert = m_trusted_root_ca.cbegin(), cert_end = m_trusted_root_ca.cend(); cert != cert_end; ++cert)
                cert_names.push_back(std::move(get_cert_title(*cert)));
            m_module.log_config((xpathServerSideCredential + L"/CA").c_str(), cert_names);
        }

        // <ServerName>
        com_obj<IXMLDOMNodeList> pXmlListServerIDs;
        long lServerIDCount = 0;
        if (SUCCEEDED(eapxml::select_nodes(pXmlElServerSideCredential, bstr(L"eap-metadata:ServerName"), &pXmlListServerIDs)) && SUCCEEDED(pXmlListServerIDs->get_length(&lServerIDCount))) {
            for (long j = 0; j < lServerIDCount; j++) {
                // Load server name (<ServerName>).
                com_obj<IXMLDOMNode> pXmlElServerID;
                pXmlListServerIDs->get_item(j, &pXmlElServerID);
                bstr bstrServerID;
                pXmlElServerID->get_text(&bstrServerID);
                m_server_names.push_back(wstring(bstrServerID));
            }

            m_module.log_config((xpathServerSideCredential + L"/ServerName").c_str(), m_server_names);
        }
    }
}


void eap::config_method_tls::operator<<(_Inout_ cursor_out &cursor) const
{
    config_method_with_cred::operator<<(cursor);
    cursor << m_trusted_root_ca;
    cursor << m_server_names   ;
#if EAP_TLS < EAP_TLS_SCHANNEL
    cursor << m_session_id     ;
    cursor << m_master_secret  ;
#endif
}


size_t eap::config_method_tls::get_pk_size() const
{
    return
        config_method_with_cred::get_pk_size() +
        pksizeof(m_trusted_root_ca) +
        pksizeof(m_server_names   )
#if EAP_TLS < EAP_TLS_SCHANNEL
        +
        pksizeof(m_session_id     ) +
        pksizeof(m_master_secret  );
#else
        ;
#endif
}


void eap::config_method_tls::operator>>(_Inout_ cursor_in &cursor)
{
    config_method_with_cred::operator>>(cursor);
    cursor >> m_trusted_root_ca;
    cursor >> m_server_names   ;
#if EAP_TLS < EAP_TLS_SCHANNEL
    cursor >> m_session_id     ;
    cursor >> m_master_secret  ;
#endif
}


eap_type_t eap::config_method_tls::get_method_id() const
{
    return eap_type_tls;
}


bool eap::config_method_tls::add_trusted_ca(_In_  DWORD dwCertEncodingType, _In_  const BYTE *pbCertEncoded, _In_  DWORD cbCertEncoded)
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
