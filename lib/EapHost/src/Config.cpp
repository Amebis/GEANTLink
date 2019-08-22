/*
    Copyright 2015-2018 Amebis
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

using namespace std;
using namespace winstd;


//////////////////////////////////////////////////////////////////////
// eap::config_method_eaphost
//////////////////////////////////////////////////////////////////////

eap::config_method_eaphost::config_method_eaphost(_In_ module &mod, _In_ unsigned int level) :
    config_method(mod, level),
    m_type_str(L"EapHost")
{
    memset(&m_type, 0, sizeof(EAP_METHOD_TYPE));
}


eap::config_method_eaphost::config_method_eaphost(_In_ const config_method_eaphost &other) :
    m_type       (other.m_type    ),
    m_type_str   (other.m_type_str),
    m_cfg_blob   (other.m_cfg_blob),
    config_method(other           )
{
}


eap::config_method_eaphost::config_method_eaphost(_Inout_ config_method_eaphost &&other) noexcept :
    m_type       (std::move(other.m_type    )),
    m_type_str   (std::move(other.m_type_str)),
    m_cfg_blob   (std::move(other.m_cfg_blob)),
    config_method(std::move(other           ))
{
}


eap::config_method_eaphost& eap::config_method_eaphost::operator=(_In_ const config_method_eaphost &other)
{
    if (this != &other) {
        (config_method&)*this = other;
        m_type                = other.m_type;
        m_type_str            = other.m_type_str;
        m_cfg_blob            = other.m_cfg_blob;
    }

    return *this;
}


eap::config_method_eaphost& eap::config_method_eaphost::operator=(_Inout_ config_method_eaphost &&other) noexcept
{
    if (this != &other) {
        (config_method&&)*this = std::move(other           );
        m_type                 = std::move(other.m_type    );
        m_type_str             = std::move(other.m_type_str);
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
    DWORD dwResult = EapHostPeerConfigBlob2Xml(0, m_type, (DWORD)m_cfg_blob.size(), const_cast<BYTE*>(m_cfg_blob.data()), &pConfigDoc, get_ptr(error));
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
        DWORD dwResult = EapHostPeerConfigXml2Blob(0, pXmlElEapHostConfig, &cfg_data_size, get_ptr(cfg_data), &m_type, get_ptr(error));
        if (dwResult == ERROR_SUCCESS) {
            update_type();
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
    cursor >> m_type    ; update_type();
    cursor >> m_cfg_blob;
}


eap_type_t eap::config_method_eaphost::get_method_id() const
{
    return (eap_type_t)m_type.eapType.type;
}


const wchar_t* eap::config_method_eaphost::get_method_str() const
{
    return m_type_str.c_str();
}


eap::credentials* eap::config_method_eaphost::make_credentials() const
{
    return new credentials_eaphost(m_module);
}


/// \cond internal
void eap::config_method_eaphost::update_type()
{
    // Query registry for EAP method name and save it to m_type_str.
    // get_method_str() can return pointer to static string only, therefore we need to have the method name ready in advance.
    reg_key key;
    if (key.open(HKEY_LOCAL_MACHINE,
            m_type.dwAuthorId   == 0   ? tstring_printf(_T("SYSTEM\\CurrentControlSet\\services\\RasMan\\PPP\\EAP\\%u"            ),                    m_type.eapType.type                                                        ).c_str() : // Legacy EAP method (RasMan)
            m_type.eapType.type == 254 ? tstring_printf(_T("SYSTEM\\CurrentControlSet\\services\\EapHost\\Methods\\%u\\%u\\%u\\%u"), m_type.dwAuthorId, m_type.eapType.type, m_type.eapType.dwVendorId, m_type.eapType.dwVendorType).c_str() : // EapHost Expanded Type Peer
                                         tstring_printf(_T("SYSTEM\\CurrentControlSet\\services\\EapHost\\Methods\\%u\\%u"        ), m_type.dwAuthorId, m_type.eapType.type                                                        ).c_str(),  // EapHost Peer
            0,
            KEY_READ) &&
        RegLoadMUIStringW(key,
            m_type.dwAuthorId == 0 ? L"FriendlyName" :
                                     L"PeerFriendlyName",
            m_type_str,
            0,
            NULL) == ERROR_SUCCESS)
        return;

    // Query failed. Provide generic name.
         if (m_type.dwAuthorId   == 0  ) sprintf(m_type_str, L"RasMan-%u"          ,                    m_type.eapType.type                                                        );
    else if (m_type.eapType.type == 254) sprintf(m_type_str, L"EapHost-%u-%u-%u-%u", m_type.dwAuthorId, m_type.eapType.type, m_type.eapType.dwVendorId, m_type.eapType.dwVendorType);
    else                                 sprintf(m_type_str, L"EapHost-%u-%u"      , m_type.dwAuthorId, m_type.eapType.type                                                        );
}
/// \endcond
