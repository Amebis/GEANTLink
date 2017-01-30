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

using namespace std;
using namespace winstd;


//////////////////////////////////////////////////////////////////////
// eap::method_gtc
//////////////////////////////////////////////////////////////////////

eap::method_gtc::method_gtc(_In_ module &mod, _In_ config_method_eapgtc &cfg) :
    m_cfg(cfg),
    method(mod)
{
}


eap::method_gtc::method_gtc(_Inout_ method_gtc &&other) :
    m_cfg       (          other.m_cfg        ),
    m_packet_res(std::move(other.m_packet_res)),
    method      (std::move(other             ))
{
}


eap::method_gtc& eap::method_gtc::operator=(_Inout_ method_gtc &&other)
{
    if (this != std::addressof(other)) {
        assert(std::addressof(m_cfg ) == std::addressof(other.m_cfg )); // Move method within same configuration only!
        (method&)*this = std::move(other             );
        m_packet_res   = std::move(other.m_packet_res);
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
    m_cfg.m_last_status = config_method::status_auth_failed;
    m_cfg.m_last_msg.clear();
}


EapPeerMethodResponseAction eap::method_gtc::process_request_packet(
    _In_bytecount_(dwReceivedPacketSize) const void  *pReceivedPacket,
    _In_                                       DWORD dwReceivedPacketSize)
{
    assert(pReceivedPacket || dwReceivedPacketSize == 0);

    //for (const unsigned char *pck = reinterpret_cast<const unsigned char*>(pReceivedPacket), *pck_end = pck + dwReceivedPacketSize; pck < pck_end; ) {
    //    if (pck + sizeof(chap_header) > pck_end)
    //        throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Incomplete CHAP header.");
    //    auto hdr = reinterpret_cast<const chap_header*>(pck);
    //    unsigned short length = ntohs(*reinterpret_cast<const unsigned short*>(hdr->length));
    //    const unsigned char
    //        *msg     = reinterpret_cast<const unsigned char*>(hdr + 1),
    //        *msg_end = pck + length;
    //    if (msg_end > pck_end)
    //        throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Incomplete CHAP data.");

    //    // Save packet ident.
    //    m_ident = hdr->ident;

    //    switch (hdr->code) {
    //    case chap_packet_code_challenge: {
    //        m_module.log_event(&EAPMETHOD_METHOD_HANDSHAKE_START2, event_data((unsigned int)eap_type_gtc), event_data::blank);

    //        if (msg + 1 > msg_end)
    //            throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Incomplete CHAP challenge packet.");

    //        // Read server challenge.
    //        if (msg + 1 + msg[0] > msg_end)
    //            throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Incomplete CHAP server challenge.");
    //        m_challenge_server.assign(msg + 1, msg + 1 + msg[0]);

    //        // Randomize Peer-Challenge.
    //        m_challenge_client.randomize(m_cp);

    //        // Calculate NT-Response.
    //        sanitizing_string identity_utf8;
    //        WideCharToMultiByte(CP_UTF8, 0, m_cred.m_identity, identity_utf8, NULL, NULL);
    //        m_nt_resp = nt_response(m_cp, m_challenge_server, m_challenge_client, identity_utf8.c_str(), m_cred.m_password.c_str());

    //        // Prepare CHAP response value.
    //        sanitizing_blob value;
    //        value.reserve(
    //            sizeof(m_challenge_client) + // Peer-Challenge
    //            8                          + // Reserved
    //            sizeof(m_nt_resp)          + // NT-Response
    //            1);                          // Flags
    //        value.insert(value.end(), reinterpret_cast<const unsigned char*>(&m_challenge_client), reinterpret_cast<const unsigned char*>(&m_challenge_client + 1)); // Peer-Challenge
    //        value.insert(value.end(), 8, 0); // Reserved (must be zero)
    //        value.insert(value.end(), reinterpret_cast<const unsigned char*>(&m_nt_resp), reinterpret_cast<const unsigned char*>(&m_nt_resp + 1)); // NT-Response
    //        value.push_back(0); // Flags

    //        chap_header hdr_resp;
    //        hdr_resp.code = chap_packet_code_response;
    //        hdr_resp.ident = m_ident;
    //        size_t size_value = value.size();
    //        *reinterpret_cast<unsigned short*>(hdr_resp.length) = htons((unsigned short)(sizeof(chap_header) + 1 + size_value + identity_utf8.length()));
    //        assert(size_value <= 0xff); // CHAP value can be 255B max

    //        // Append response.
    //        m_packet_res.assign(reinterpret_cast<const unsigned char*>(&hdr_resp), reinterpret_cast<const unsigned char*>(&hdr_resp + 1));
    //        m_packet_res.insert(m_packet_res.end(), 1, (unsigned char)size_value);
    //        m_packet_res.insert(m_packet_res.end(), value.begin(), value.end());
    //        m_packet_res.insert(m_packet_res.end(), identity_utf8.begin(), identity_utf8.end());

    //        m_cfg.m_last_status = config_method::status_cred_invalid; // Blame credentials if we fail beyond this point.
    //        return EapPeerMethodResponseActionSend;
    //    }

    //    case chap_packet_code_success:
    //        process_success(parse_response(reinterpret_cast<const char*>(msg), reinterpret_cast<const char*>(msg_end) - reinterpret_cast<const char*>(msg)));
    //        if (m_cfg.m_last_status == config_method::status_success) {
    //            // Acknowledge the authentication by sending a "3" (chap_packet_code_success).
    //            m_packet_res.assign(1, chap_packet_code_success);
    //            m_cfg.m_last_status = config_method::status_auth_failed; // Blame protocol if we fail beyond this point.
    //            return EapPeerMethodResponseActionSend;
    //        } else
    //            return EapPeerMethodResponseActionDiscard;

    //    case chap_packet_code_failure:
    //        process_error(parse_response(reinterpret_cast<const char*>(msg), reinterpret_cast<const char*>(msg_end) - reinterpret_cast<const char*>(msg)));
    //        return EapPeerMethodResponseActionDiscard;
    //    }

    //    pck = msg_end;
    //}

    return EapPeerMethodResponseActionNone;
}


void eap::method_gtc::get_response_packet(
    _Out_    sanitizing_blob &packet,
    _In_opt_ DWORD           size_max)
{
    if (m_packet_res.size() > size_max)
        throw invalid_argument(string_printf(__FUNCTION__ " This method does not support packet fragmentation, but the data size is too big to fit in one packet (packet: %u, maximum: %u).", m_packet_res.size(), size_max));

    packet.assign(m_packet_res.begin(), m_packet_res.end());
}


void eap::method_gtc::get_result(
    _In_    EapPeerMethodResultReason reason,
    _Inout_ EapPeerMethodResult       *pResult)
{
    assert(pResult);

    method::get_result(reason, pResult);

    if (reason == EapPeerMethodResultSuccess)
        m_cfg.m_last_status = config_method::status_success;

    // Always ask EAP host to save the connection data. And it will save it *only* when we report "success".
    // Don't worry. EapHost is well aware of failed authentication condition.
    pResult->fSaveConnectionData = TRUE;
    pResult->fIsSuccess          = TRUE;
}
