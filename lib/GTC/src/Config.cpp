/*
    Copyright 2015-2020 Amebis
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
// eap::config_method_eapgtc
//////////////////////////////////////////////////////////////////////

eap::config_method_eapgtc::config_method_eapgtc(_In_ module &mod, _In_ unsigned int level) : config_method_with_cred(mod, level)
{
    // Default to Challenge/Response authentication mode.
    m_cred.reset(new credentials_identity(mod));
}


eap::config_method_eapgtc::config_method_eapgtc(_In_ const config_method_eapgtc &other) :
    config_method_with_cred(other)
{
}


eap::config_method_eapgtc::config_method_eapgtc(_Inout_ config_method_eapgtc &&other) noexcept :
    config_method_with_cred(std::move(other))
{
}


eap::config_method_eapgtc& eap::config_method_eapgtc::operator=(_In_ const config_method_eapgtc &other)
{
    if (this != &other)
        (config_method_with_cred&)*this = other;

    return *this;
}


eap::config_method_eapgtc& eap::config_method_eapgtc::operator=(_Inout_ config_method_eapgtc &&other) noexcept
{
    if (this != &other)
        (config_method_with_cred&&)*this = std::move(other);

    return *this;
}


eap::config* eap::config_method_eapgtc::clone() const
{
    return new config_method_eapgtc(*this);
}


void eap::config_method_eapgtc::save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot) const
{
    assert(pDoc);
    assert(pConfigRoot);

    config_method_with_cred::save(pDoc, pConfigRoot);

    HRESULT hr;

    if (dynamic_cast<credentials_identity*>(m_cred.get()))
        hr = eapxml::put_element_value(pDoc, pConfigRoot, bstr(L"AuthMode"), namespace_eapmetadata, bstr(L"Challenge/Response"));
    else if (dynamic_cast<credentials_pass*>(m_cred.get()))
        hr = eapxml::put_element_value(pDoc, pConfigRoot, bstr(L"AuthMode"), namespace_eapmetadata, bstr(L"Password"));
    else
        throw invalid_argument(__FUNCTION__ " Unsupported authentication mode.");
    if (FAILED(hr))
        throw com_runtime_error(hr, __FUNCTION__ " Error creating <AuthMode> element.");
}


void eap::config_method_eapgtc::load(_In_ IXMLDOMNode *pConfigRoot)
{
    assert(pConfigRoot);
    HRESULT hr;
    wstring xpath(eapxml::get_xpath(pConfigRoot));

    // Load authentication mode first, then (re)create credentials to match the authentication mode.
    bstr auth_mode;
    if (FAILED(hr = eapxml::get_element_value(pConfigRoot, bstr(L"eap-metadata:AuthMode"), auth_mode)) ||
        CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, auth_mode, auth_mode.length(), _L("Challenge/Response"), -1, NULL, NULL, 0) == CSTR_EQUAL)
    {
        m_cred.reset(new eap::credentials_identity(m_module));
    } else if (CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, auth_mode, auth_mode.length(), _L("Password"), -1, NULL, NULL, 0) == CSTR_EQUAL) {
        m_cred.reset(new eap::credentials_pass(m_module));
    } else
        throw invalid_argument(string_printf(__FUNCTION__ " Unsupported authentication mode (%ls).", (BSTR)auth_mode));

    m_module.log_config((xpath + L"/AuthMode").c_str(), (BSTR)auth_mode);

    // Load method configuration.
    config_method_with_cred::load(pConfigRoot);
}


void eap::config_method_eapgtc::operator<<(_Inout_ cursor_out &cursor) const
{
    // Save authentication mode first, as credential loading will require this information.
    if (dynamic_cast<credentials_identity*>(m_cred.get()))
        cursor << auth_mode_response;
    else if (dynamic_cast<credentials_pass*>(m_cred.get()))
        cursor << auth_mode_password;
    else
        throw invalid_argument(__FUNCTION__ " Unsupported authentication mode.");

    config_method_with_cred::operator<<(cursor);
}


size_t eap::config_method_eapgtc::get_pk_size() const
{
    auth_mode_t auth_mode;
    if (dynamic_cast<credentials_identity*>(m_cred.get()))
        auth_mode = auth_mode_response;
    else if (dynamic_cast<credentials_pass*>(m_cred.get()))
        auth_mode = auth_mode_password;
    else
        throw invalid_argument(__FUNCTION__ " Unsupported authentication mode.");

    return
        pksizeof(auth_mode) +
        config_method_with_cred::get_pk_size();
}


void eap::config_method_eapgtc::operator>>(_Inout_ cursor_in &cursor)
{
    // (Re)create credentials to match the authentication mode.
    auth_mode_t auth_mode;
    cursor >> auth_mode;
    switch (auth_mode) {
    case auth_mode_response: m_cred.reset(new eap::credentials_identity(m_module)); break;
    case auth_mode_password: m_cred.reset(new eap::credentials_pass    (m_module)); break;
    default                : throw invalid_argument(string_printf(__FUNCTION__ " Unsupported authentication mode (%u).", auth_mode));
    }

    config_method_with_cred::operator>>(cursor);
}


eap_type_t eap::config_method_eapgtc::get_method_id() const
{
    return eap_type_gtc;
}


const wchar_t* eap::config_method_eapgtc::get_method_str() const
{
    return L"EAP-GTC";
}


eap::credentials* eap::config_method_eapgtc::make_credentials() const
{
    if (dynamic_cast<credentials_identity*>(m_cred.get()))
        return new eap::credentials_identity(m_module);
    else if (dynamic_cast<credentials_pass*>(m_cred.get()))
        return new eap::credentials_pass    (m_module);
    else
        throw invalid_argument(__FUNCTION__ " Unsupported authentication mode.");
}
