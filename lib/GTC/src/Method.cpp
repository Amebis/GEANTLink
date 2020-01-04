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
// eap::method_gtc
//////////////////////////////////////////////////////////////////////

eap::method_gtc::method_gtc(_In_ module &mod, _In_ config_method_eapgtc &cfg, _In_ credentials &cred) :
    m_cfg(cfg),
    m_cred(cred),
    method(mod)
{
}


eap::method_gtc::method_gtc(_Inout_ method_gtc &&other) noexcept :
    m_cfg      (          other.m_cfg       ),
    m_cred     (          other.m_cred      ),
    m_challenge(std::move(other.m_challenge)),
    m_response (std::move(other.m_response )),
    method     (std::move(other            ))
{
}


eap::method_gtc& eap::method_gtc::operator=(_Inout_ method_gtc &&other) noexcept
{
    if (this != std::addressof(other)) {
        assert(std::addressof(m_cfg ) == std::addressof(other.m_cfg )); // Move method within same configuration only!
        assert(std::addressof(m_cred) == std::addressof(other.m_cred)); // Move method within same credentials only!
        (method&)*this = std::move(other            );
        m_challenge    = std::move(other.m_challenge);
        m_response     = std::move(other.m_response );
    }

    return *this;
}


void eap::method_gtc::begin_session(
    _In_        DWORD         dwFlags,
    _In_  const EapAttributes *pAttributeArray,
    _In_        HANDLE        hTokenImpersonateUser,
    _In_opt_    DWORD         dwMaxSendPacketSize)
{
    method::begin_session(dwFlags, pAttributeArray, hTokenImpersonateUser, dwMaxSendPacketSize);

    // Presume authentication will fail with generic protocol failure. (Pesimist!!!)
    // We will reset once we get get_result(Success) call.
    m_cfg.m_last_status = config_method::status_t::auth_failed;
    m_cfg.m_last_msg.clear();
}


EapPeerMethodResponseAction eap::method_gtc::process_request_packet(
    _In_bytecount_(dwReceivedPacketSize) const void  *pReceivedPacket,
    _In_                                       DWORD dwReceivedPacketSize)
{
    assert(pReceivedPacket || dwReceivedPacketSize == 0);

    m_module.log_event(&EAPMETHOD_METHOD_HANDSHAKE_START2, event_data((unsigned int)eap_type_t::gtc), event_data::blank);

    credentials_pass *cred_pass;
    if (dynamic_cast<credentials_identity*>(&m_cred)) {
        // Read authenticator challenge as UTF-8 encoded string.
        MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)pReceivedPacket, dwReceivedPacketSize, m_challenge);

        m_module.log_event(&EAPMETHOD_GTC_RESPONSE_REQ, event_data((unsigned int)eap_type_t::gtc), event_data::blank);

        // User must respond to the challenge.
        return EapPeerMethodResponseActionInvokeUI;
    } else if ((cred_pass = dynamic_cast<credentials_pass*>(&m_cred)) != NULL) {
        // Ignore authenticator challenge and save password as GTC response.
        m_response = cred_pass->m_password;

        // Send the response.
        m_cfg.m_last_status = config_method::status_t::cred_invalid; // Blame "credentials" if we fail beyond this point.
        return EapPeerMethodResponseActionSend;
    } else
        throw invalid_argument(__FUNCTION__ " Unsupported authentication mode.");
}


void eap::method_gtc::get_response_packet(
    _Out_    sanitizing_blob &packet,
    _In_opt_ DWORD           size_max)
{
    // Encode GTC response as UTF-8.
    sanitizing_string response_utf8;
    WideCharToMultiByte(CP_UTF8, 0, m_response, response_utf8, NULL, NULL);

    if (sizeof(sanitizing_string::value_type)*response_utf8.length() > size_max)
        throw invalid_argument(string_printf(__FUNCTION__ " This method does not support packet fragmentation, but the data size is too big to fit in one packet (packet: %zu, maximum: %u).", sizeof(sanitizing_string::value_type)*response_utf8.length(), size_max));

    packet.assign(response_utf8.begin(), response_utf8.end());
}


void eap::method_gtc::get_result(
    _In_    EapPeerMethodResultReason reason,
    _Inout_ EapPeerMethodResult       *pResult)
{
    assert(pResult);

    method::get_result(reason, pResult);

    if (reason == EapPeerMethodResultSuccess)
        m_cfg.m_last_status = config_method::status_t::success;

    // Always ask EAP host to save the connection data. And it will save it *only* when we report "success".
    // Don't worry. EapHost is well aware of failed authentication condition.
    pResult->fSaveConnectionData = TRUE;
    pResult->fIsSuccess          = TRUE;
}


void eap::method_gtc::get_ui_context(_Out_ sanitizing_blob &context_data)
{
    // Return authenticator string.
    context_data.assign(
        reinterpret_cast<sanitizing_blob::const_pointer>(m_challenge.data()                       ),
        reinterpret_cast<sanitizing_blob::const_pointer>(m_challenge.data() + m_challenge.length()));
}


EapPeerMethodResponseAction eap::method_gtc::set_ui_context(
    _In_count_(dwUIContextDataSize) const BYTE  *pUIContextData,
    _In_                                  DWORD dwUIContextDataSize)
{
    m_module.log_event(&EAPMETHOD_GTC_RESPONSE, event_data((unsigned int)eap_type_t::gtc), event_data::blank);

    // Save GTC response.
    m_response.assign(
        reinterpret_cast<sanitizing_wstring::const_pointer>(pUIContextData                      ),
        reinterpret_cast<sanitizing_wstring::const_pointer>(pUIContextData + dwUIContextDataSize));

    // Send the response.
    m_cfg.m_last_status = config_method::status_t::cred_invalid; // Blame "credentials" if we fail beyond this point.
    return EapPeerMethodResponseActionSend;
}
