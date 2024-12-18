/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2022 Amebis
    Copyright © 2016 GÉANT
*/

#include "PCH.h"

using namespace std;
using namespace winstd;


//////////////////////////////////////////////////////////////////////
// eap::config_method_eaphost
//////////////////////////////////////////////////////////////////////

eap::config_method_eaphost::config_method_eaphost(_In_ module &mod, _In_ unsigned int level) :
    config_method(mod, level)
{
    memset(&m_type, 0, sizeof(EAP_METHOD_TYPE));
}


eap::config_method_eaphost::config_method_eaphost(_In_ const config_method_eaphost &other) :
    m_type       (other.m_type    ),
    m_cfg_blob   (other.m_cfg_blob),
    config_method(other           )
{
}


eap::config_method_eaphost::config_method_eaphost(_Inout_ config_method_eaphost &&other) noexcept :
    m_type       (std::move(other.m_type    )),
    m_cfg_blob   (std::move(other.m_cfg_blob)),
    config_method(std::move(other           ))
{
}


eap::config_method_eaphost& eap::config_method_eaphost::operator=(_In_ const config_method_eaphost &other)
{
    if (this != &other) {
        (config_method&)*this = other;
        m_type                = other.m_type;
        m_cfg_blob            = other.m_cfg_blob;
    }

    return *this;
}


eap::config_method_eaphost& eap::config_method_eaphost::operator=(_Inout_ config_method_eaphost &&other) noexcept
{
    if (this != &other) {
        (config_method&&)*this = std::move(other           );
        m_type                 = std::move(other.m_type    );
        m_cfg_blob             = std::move(other.m_cfg_blob);
    }

    return *this;
}


eap::config* eap::config_method_eaphost::clone() const
{
    return new config_method_eaphost(*this);
}


void eap::config_method_eaphost::save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot) const
{
    assert(pDoc);
    assert(pConfigRoot);

    config_method::save(pDoc, pConfigRoot);

    // Convert configuration BLOB to XML using EapHost (and ultimately method peer's EapPeerConfigBlob2Xml).
    com_obj<IXMLDOMDocument2> pConfigDoc;
    eap_error error;
    DWORD dwResult = EapHostPeerConfigBlob2Xml(0, m_type, (DWORD)m_cfg_blob.size(), const_cast<BYTE*>(m_cfg_blob.data()), &pConfigDoc, stdex::get_ptr(error));
    if (dwResult == ERROR_SUCCESS) {
        HRESULT hr;

        com_obj<IXMLDOMElement> pXmlElConfigDoc;
        if (FAILED(hr = pConfigDoc->get_documentElement(&pXmlElConfigDoc)))
            throw com_runtime_error(hr, __FUNCTION__ " Error getting XML document element.");

        // Insert method configuration into our XML configuration.
        if (FAILED(hr = pConfigRoot->appendChild(pXmlElConfigDoc, NULL)))
            throw com_runtime_error(hr, __FUNCTION__ " Error appending configuration document element.");
    } else if (error)
        throw eap_runtime_error(*error  , __FUNCTION__ " EapHostPeerConfigBlob2Xml failed.");
    else
        throw win_runtime_error(dwResult, __FUNCTION__ " EapHostPeerConfigBlob2Xml failed.");
}


void eap::config_method_eaphost::load(_In_ IXMLDOMNode *pConfigRoot)
{
    assert(pConfigRoot);

    config_method::load(pConfigRoot);

    // <EapHostConfig>
    winstd::com_obj<IXMLDOMElement> pXmlElEapHostConfig;
    if (SUCCEEDED(eapxml::select_element(pConfigRoot, winstd::bstr(L"eaphostconfig:EapHostConfig"), pXmlElEapHostConfig))) {
        // Convert configuration XML to BLOB using EapHost (and ultimately method peer's EapPeerConfigXml2Blob).
        DWORD cfg_data_size = 0;
        eap_blob cfg_data;
        eap_error error;
        DWORD dwResult = EapHostPeerConfigXml2Blob(0, pXmlElEapHostConfig, &cfg_data_size, stdex::get_ptr(cfg_data), &m_type, stdex::get_ptr(error));
        if (dwResult == ERROR_SUCCESS) {
            LPCBYTE _cfg_data = cfg_data.get();
            m_cfg_blob.assign(_cfg_data, _cfg_data + cfg_data_size);
        } else if (error)
            throw eap_runtime_error(*error  , __FUNCTION__ " EapHostPeerConfigXml2Blob failed.");
        else
            throw win_runtime_error(dwResult, __FUNCTION__ " EapHostPeerConfigXml2Blob failed.");
    }
}


void eap::config_method_eaphost::operator<<(_Inout_ cursor_out &cursor) const
{
    config_method::operator<<(cursor);
    cursor << m_type    ;
    cursor << m_cfg_blob;
}


size_t eap::config_method_eaphost::get_pk_size() const
{
    return
        config_method::get_pk_size() +
        pksizeof(m_type    ) +
        pksizeof(m_cfg_blob);
}


void eap::config_method_eaphost::operator>>(_Inout_ cursor_in &cursor)
{
    config_method::operator>>(cursor);
    cursor >> m_type    ;
    cursor >> m_cfg_blob;
}


eap_type_t eap::config_method_eaphost::get_method_id() const
{
    return eap_type_t::undefined;
}


const wchar_t* eap::config_method_eaphost::get_method_str() const
{
    return L"EapHost";
}


eap::credentials* eap::config_method_eaphost::make_credentials() const
{
    return new credentials_eaphost(m_module);
}
