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
// eap::method_mschapv2_base
//////////////////////////////////////////////////////////////////////

eap::method_mschapv2_base::method_mschapv2_base(_In_ module &mod, _In_ config_method_mschapv2 &cfg, _In_ credentials_pass &cred) :
    m_cfg(cfg),
    m_cred(cred),
    m_ident(0),
    method(mod)
{
}


eap::method_mschapv2_base::method_mschapv2_base(_Inout_ method_mschapv2_base &&other) noexcept :
    m_cfg             (          other.m_cfg              ),
    m_cred            (          other.m_cred             ),
    m_cp              (std::move(other.m_cp              )),
    m_challenge_server(std::move(other.m_challenge_server)),
    m_challenge_client(std::move(other.m_challenge_client)),
    m_ident           (std::move(other.m_ident           )),
    m_nt_resp         (std::move(other.m_nt_resp         )),
    m_packet_res      (std::move(other.m_packet_res      )),
    method            (std::move(other                   ))
{
}


eap::method_mschapv2_base& eap::method_mschapv2_base::operator=(_Inout_ method_mschapv2_base &&other) noexcept
{
    if (this != std::addressof(other)) {
        assert(std::addressof(m_cfg ) == std::addressof(other.m_cfg )); // Move method within same configuration only!
        assert(std::addressof(m_cred) == std::addressof(other.m_cred)); // Move method within same credentials only!
        (method&)*this     = std::move(other                   );
        m_cp               = std::move(other.m_cp              );
        m_challenge_server = std::move(other.m_challenge_server);
        m_challenge_client = std::move(other.m_challenge_client);
        m_ident            = std::move(other.m_ident           );
        m_nt_resp          = std::move(other.m_nt_resp         );
        m_packet_res       = std::move(other.m_packet_res      );
    }

    return *this;
}


void eap::method_mschapv2_base::begin_session(
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

    // Create cryptographics provider for support needs (client challenge ...).
    if (!m_cp.create(NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        throw win_runtime_error(__FUNCTION__ " Error creating cryptographics provider.");
}


void eap::method_mschapv2_base::get_response_packet(
    _Out_    sanitizing_blob &packet,
    _In_opt_ DWORD           size_max)
{
    if (m_packet_res.size() > size_max)
        throw invalid_argument(string_printf(__FUNCTION__ " This method does not support packet fragmentation, but the data size is too big to fit in one packet (packet: %zu, maximum: %u).", m_packet_res.size(), size_max));

    packet.assign(m_packet_res.begin(), m_packet_res.end());
}


void eap::method_mschapv2_base::get_result(
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


void eap::method_mschapv2_base::process_success(_In_ const list<string> &argv)
{
    assert(m_cfg.m_last_status != config_method::status_t::success);

    for (auto arg = argv.cbegin(), arg_end = argv.cend(); arg != arg_end; ++arg) {
        const string &val = *arg;
        if ((val[0] == 'S' || val[0] == 's') && val[1] == '=') {
            // "S="
            hex_dec dec;
            sanitizing_blob resp;
            bool is_last;
            dec.decode(resp, is_last, val.data() + 2, (size_t)-1);

            // Calculate expected authenticator response.
            sanitizing_string identity_utf8;
            WideCharToMultiByte(CP_UTF8, 0, m_cred.m_identity, identity_utf8, NULL, NULL);
            authenticator_response resp_exp(m_cp, m_challenge_server, m_challenge_client, identity_utf8.c_str(), m_cred.m_password.c_str(), m_nt_resp);

            // Compare against provided authemticator response.
            if (resp.size() != sizeof(resp_exp) || memcmp(resp.data(), &resp_exp, sizeof(resp_exp)) != 0)
                throw invalid_argument(__FUNCTION__ " MS-CHAP2-Success authentication response string failed.");

            m_module.log_event(&EAPMETHOD_METHOD_SUCCESS, event_data((unsigned int)m_cfg.get_method_id()), event_data::blank);
            m_cfg.m_last_status = config_method::status_t::success;
        }
    }

    if (m_cfg.m_last_status != config_method::status_t::success)
        throw invalid_argument(__FUNCTION__ " MS-CHAP2-Success authentication response string not found.");
}


void eap::method_mschapv2_base::process_error(_In_ const list<string> &argv)
{
    for (auto arg = argv.cbegin(), arg_end = argv.cend(); arg != arg_end; ++arg) {
        const string &val = *arg;
        if ((val[0] == 'E' || val[0] == 'e') && val[1] == '=') {
            DWORD dwResult = strtoul(val.data() + 2, NULL, 10);
            m_module.log_event(&EAPMETHOD_METHOD_FAILURE_ERROR, event_data((unsigned int)m_cfg.get_method_id()), event_data(dwResult), event_data::blank);
            switch (dwResult) {
            case ERROR_ACCT_DISABLED         : m_cfg.m_last_status = config_method::status_t::account_disabled   ; break;
            case ERROR_RESTRICTED_LOGON_HOURS: m_cfg.m_last_status = config_method::status_t::account_logon_hours; break;
            case ERROR_NO_DIALIN_PERMISSION  : m_cfg.m_last_status = config_method::status_t::account_denied     ; break;
            case ERROR_PASSWD_EXPIRED        : m_cfg.m_last_status = config_method::status_t::cred_expired       ; break;
            case ERROR_CHANGING_PASSWORD     : m_cfg.m_last_status = config_method::status_t::cred_changing      ; break;
            default                          : m_cfg.m_last_status = config_method::status_t::cred_invalid       ;
            }
        } else if ((val[0] == 'C' || val[0] == 'c') && val[1] == '=') {
            hex_dec dec;
            bool is_last;
            dec.decode(m_challenge_server, is_last, val.data() + 2, (size_t)-1);
        } else if ((val[0] == 'M' || val[0] == 'm') && val[1] == '=') {
            MultiByteToWideChar(CP_UTF8, 0, val.data() + 2, (int)val.length() - 2, m_cfg.m_last_msg);
            m_module.log_event(&EAPMETHOD_METHOD_FAILURE_ERROR1, event_data((unsigned int)m_cfg.get_method_id()), event_data(m_cfg.m_last_msg), event_data::blank);
        }
    }
}


list<string> eap::method_mschapv2_base::parse_response(_In_count_(count) const char *resp, _In_ size_t count)
{
    list<string> argv;

    for (size_t i = 0; i < count && resp[i]; ) {
        if (i + 1 < count && (resp[i] == 'M' || resp[i] == 'm') && resp[i + 1] == '=') {
            // The message is always the last value. It may contain spaces and it spans to the end.
            argv.push_back(string(resp + i, strnlen(resp + i, count - i)));
            break;
        } else if (!isspace(resp[i])) {
            // Search for the next space and add value up to it.
            size_t j;
            for (j = i + 1; j < count && resp[j] && !isspace(resp[j]); j++);
            argv.push_back(string(resp + i, j - i));
            i = j + 1;
        } else {
            // Skip (multiple) spaces.
            i++;
        }
    }

    return argv;
}


//////////////////////////////////////////////////////////////////////
// eap::method_mschapv2
//////////////////////////////////////////////////////////////////////

eap::method_mschapv2::method_mschapv2(_In_ module &mod, _In_ config_method_mschapv2 &cfg, _In_ credentials_pass &cred) :
    method_mschapv2_base(mod, cfg, cred)
{
}


eap::method_mschapv2::method_mschapv2(_Inout_ method_mschapv2 &&other) noexcept :
    method_mschapv2_base(std::move(other        ))
{
}


eap::method_mschapv2& eap::method_mschapv2::operator=(_Inout_ method_mschapv2 &&other) noexcept
{
    if (this != std::addressof(other))
        (method_mschapv2_base&)*this = std::move(other);

    return *this;
}


EapPeerMethodResponseAction eap::method_mschapv2::process_request_packet(
    _In_bytecount_(dwReceivedPacketSize) const void  *pReceivedPacket,
    _In_                                       DWORD dwReceivedPacketSize)
{
    assert(pReceivedPacket || dwReceivedPacketSize == 0);

    for (const unsigned char *pck = reinterpret_cast<const unsigned char*>(pReceivedPacket), *pck_end = pck + dwReceivedPacketSize; pck < pck_end; ) {
        if (pck + sizeof(chap_header) > pck_end)
            throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Incomplete CHAP header.");
        auto hdr = reinterpret_cast<const chap_header*>(pck);
        unsigned short length = ntohs(*reinterpret_cast<const unsigned short*>(hdr->length));
        const unsigned char
            *msg     = reinterpret_cast<const unsigned char*>(hdr + 1),
            *msg_end = pck + length;
        if (msg_end > pck_end)
            throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Incomplete CHAP data.");

        // Save packet ident.
        m_ident = hdr->ident;

        switch (hdr->code) {
        case chap_packet_code_t::challenge: {
            m_module.log_event(&EAPMETHOD_METHOD_HANDSHAKE_START2, event_data((unsigned int)eap_type_t::mschapv2), event_data::blank);

            if (msg + 1 > msg_end)
                throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Incomplete CHAP challenge packet.");

            // Read server challenge.
            if (msg + 1 + msg[0] > msg_end)
                throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Incomplete CHAP server challenge.");
            m_challenge_server.assign(msg + 1, msg + 1 + msg[0]);

            // Randomize Peer-Challenge.
            m_challenge_client.randomize(m_cp);

            // Calculate NT-Response.
            sanitizing_string identity_utf8;
            WideCharToMultiByte(CP_UTF8, 0, m_cred.m_identity, identity_utf8, NULL, NULL);
            m_nt_resp = nt_response(m_cp, m_challenge_server, m_challenge_client, identity_utf8.c_str(), m_cred.m_password.c_str());

            // Prepare CHAP response value.
            sanitizing_blob value;
            value.reserve(
                sizeof(m_challenge_client) + // Peer-Challenge
                8                          + // Reserved
                sizeof(m_nt_resp)          + // NT-Response
                1);                          // Flags
            value.insert(value.end(), reinterpret_cast<const unsigned char*>(&m_challenge_client), reinterpret_cast<const unsigned char*>(&m_challenge_client + 1)); // Peer-Challenge
            value.insert(value.end(), 8, 0); // Reserved (must be zero)
            value.insert(value.end(), reinterpret_cast<const unsigned char*>(&m_nt_resp), reinterpret_cast<const unsigned char*>(&m_nt_resp + 1)); // NT-Response
            value.push_back(0); // Flags

            chap_header hdr_resp;
            hdr_resp.code = chap_packet_code_t::response;
            hdr_resp.ident = m_ident;
            size_t size_value = value.size();
            *reinterpret_cast<unsigned short*>(hdr_resp.length) = htons((unsigned short)(sizeof(chap_header) + 1 + size_value + identity_utf8.length()));
            assert(size_value <= 0xff); // CHAP value can be 255B max

            // Append response.
            m_packet_res.assign(reinterpret_cast<const unsigned char*>(&hdr_resp), reinterpret_cast<const unsigned char*>(&hdr_resp + 1));
            m_packet_res.insert(m_packet_res.end(), 1, (unsigned char)size_value);
            m_packet_res.insert(m_packet_res.end(), value.begin(), value.end());
            m_packet_res.insert(m_packet_res.end(), identity_utf8.begin(), identity_utf8.end());

            m_cfg.m_last_status = config_method::status_t::cred_invalid; // Blame credentials if we fail beyond this point.
            return EapPeerMethodResponseActionSend;
        }

        case chap_packet_code_t::success:
            process_success(parse_response(reinterpret_cast<const char*>(msg), reinterpret_cast<const char*>(msg_end) - reinterpret_cast<const char*>(msg)));
            if (m_cfg.m_last_status == config_method::status_t::success) {
                // Acknowledge the authentication by sending a "3" (chap_packet_code_t::success).
                m_packet_res.assign(1, (unsigned char)chap_packet_code_t::success);
                m_cfg.m_last_status = config_method::status_t::auth_failed; // Blame protocol if we fail beyond this point.
                return EapPeerMethodResponseActionSend;
            } else
                return EapPeerMethodResponseActionDiscard;

        case chap_packet_code_t::failure:
            process_error(parse_response(reinterpret_cast<const char*>(msg), reinterpret_cast<const char*>(msg_end) - reinterpret_cast<const char*>(msg)));
            return EapPeerMethodResponseActionDiscard;
        }

        pck = msg_end;
    }

    return EapPeerMethodResponseActionNone;
}


//////////////////////////////////////////////////////////////////////
// eap::method_mschapv2_diameter
//////////////////////////////////////////////////////////////////////

eap::method_mschapv2_diameter::method_mschapv2_diameter(_In_ module &mod, _In_ config_method_mschapv2 &cfg, _In_ credentials_pass &cred) :
    m_phase(phase_t::unknown),
    method_mschapv2_base(mod, cfg, cred)
{
}


eap::method_mschapv2_diameter::method_mschapv2_diameter(_Inout_ method_mschapv2_diameter &&other) noexcept :
    m_phase             (std::move(other.m_phase)),
    method_mschapv2_base(std::move(other        ))
{
}


eap::method_mschapv2_diameter& eap::method_mschapv2_diameter::operator=(_Inout_ method_mschapv2_diameter &&other) noexcept
{
    if (this != std::addressof(other)) {
        (method_mschapv2_base&)*this = std::move(other        );
        m_phase                      = std::move(other.m_phase);
    }

    return *this;
}


void eap::method_mschapv2_diameter::begin_session(
    _In_        DWORD         dwFlags,
    _In_  const EapAttributes *pAttributeArray,
    _In_        HANDLE        hTokenImpersonateUser,
    _In_opt_    DWORD         dwMaxSendPacketSize)
{
    method_mschapv2_base::begin_session(dwFlags, pAttributeArray, hTokenImpersonateUser, dwMaxSendPacketSize);

    m_phase = phase_t::init;
}


EapPeerMethodResponseAction eap::method_mschapv2_diameter::process_request_packet(
    _In_bytecount_(dwReceivedPacketSize) const void  *pReceivedPacket,
    _In_                                       DWORD dwReceivedPacketSize)
{
    assert(pReceivedPacket || dwReceivedPacketSize == 0);

    switch (m_phase) {
    case phase_t::init: {
        m_module.log_event(&EAPMETHOD_METHOD_HANDSHAKE_START2, event_data((unsigned int)eap_type_t::legacy_mschapv2), event_data::blank);

        // Randomize Peer-Challenge.
        m_challenge_client.randomize(m_cp);

        // Calculate NT-Response.
        sanitizing_string identity_utf8;
        WideCharToMultiByte(CP_UTF8, 0, m_cred.m_identity, identity_utf8, NULL, NULL);
        m_nt_resp = nt_response(m_cp, m_challenge_server, m_challenge_client, identity_utf8.c_str(), m_cred.m_password.c_str());

        // Prepare MS-CHAP2-Response.
        sanitizing_blob response;
        response.reserve(
            1                          + // Ident
            1                          + // Flags
            sizeof(m_challenge_client) + // Peer-Challenge
            8                          + // Reserved
            sizeof(m_nt_resp));          // NT-Response
        response.push_back(m_ident);
        response.push_back(0); // Flags
        response.insert(response.end(), reinterpret_cast<const unsigned char*>(&m_challenge_client), reinterpret_cast<const unsigned char*>(&m_challenge_client + 1)); // Peer-Challenge
        response.insert(response.end(), 8, 0); // Reserved
        response.insert(response.end(), reinterpret_cast<const unsigned char*>(&m_nt_resp), reinterpret_cast<const unsigned char*>(&m_nt_resp + 1)); // NT-Response

        // Diameter AVP (User-Name=1, MS-CHAP-Challenge=11/311, MS-CHAP2-Response=25/311)
        m_packet_res.clear();
        diameter_avp_append( 1,      diameter_avp_flag_mandatory, identity_utf8     .data(), (unsigned int)identity_utf8     .size(), m_packet_res);
        diameter_avp_append(11, 311, diameter_avp_flag_mandatory, m_challenge_server.data(), (unsigned int)m_challenge_server.size(), m_packet_res);
        diameter_avp_append(25, 311, diameter_avp_flag_mandatory, response          .data(), (unsigned int)response          .size(), m_packet_res);

        m_phase = phase_t::challenge_server;
        m_cfg.m_last_status = config_method::status_t::cred_invalid; // Blame credentials if we fail beyond this point.
        return EapPeerMethodResponseActionSend;
    }

    case phase_t::challenge_server: {
        process_packet(pReceivedPacket, dwReceivedPacketSize);
        if (m_cfg.m_last_status == config_method::status_t::success) {
            m_phase = phase_t::finished;

            // Acknowledge the authentication by sending an empty response packet.
            m_packet_res.clear();
            m_cfg.m_last_status = config_method::status_t::auth_failed; // Blame protocol if we fail beyond this point.
            return EapPeerMethodResponseActionSend;
        } else
            return EapPeerMethodResponseActionDiscard;
    }

    case phase_t::finished:
        return EapPeerMethodResponseActionNone;

    default:
        throw invalid_argument(string_printf(__FUNCTION__ " Unknown phase (phase %u).", m_phase));
    }
}


void eap::method_mschapv2_diameter::process_packet(_In_bytecount_(size_pck) const void *_pck, _In_ size_t size_pck)
{
    for (const unsigned char *pck = reinterpret_cast<const unsigned char*>(_pck), *pck_end = pck + size_pck; pck < pck_end; ) {
        if (pck + sizeof(diameter_avp_header) > pck_end)
            throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Incomplete message header.");
        const diameter_avp_header *hdr = reinterpret_cast<const diameter_avp_header*>(pck);
        unsigned int code = ntohl(*reinterpret_cast<const unsigned int*>(hdr->code));
        unsigned int vendor;
        const unsigned char *msg;
        if (hdr->flags & diameter_avp_flag_vendor) {
            if (pck + sizeof(diameter_avp_header_ven) > pck_end)
                throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Incomplete message header.");
            const diameter_avp_header_ven *hdr_ven = reinterpret_cast<const diameter_avp_header_ven*>(pck);
            vendor = ntohl(*reinterpret_cast<const unsigned int*>(hdr_ven->vendor));
            msg = reinterpret_cast<const unsigned char*>(hdr_ven + 1);
        } else {
            vendor = 0;
            msg = reinterpret_cast<const unsigned char*>(hdr + 1);
        }
        unsigned int length = ntoh24(hdr->length);
        const unsigned char
            *msg_end  = pck     + length,
            *msg_next = msg_end + (4 - length) % 4;
        if (msg_end > pck_end)
            throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Incomplete message data.");

        if (code == 26 && vendor == 311) {
            // MS-CHAP2-Success
            if (msg[0] != m_ident)
                throw invalid_argument(string_printf(__FUNCTION__ " Wrong MSCHAPv2 ident (expected: %u, received: %u).", m_ident, msg[0]));
            const char *str = reinterpret_cast<const char*>(msg + 1);
            process_success(parse_response(str, (reinterpret_cast<const char*>(msg_end) - str)));
        } else if (code == 2 && vendor == 311) {
            // MS-CHAP2-Error
            m_ident = msg[0];
            const char *str = reinterpret_cast<const char*>(msg + 1);
            process_error(parse_response(str, (reinterpret_cast<const char*>(msg_end) - str)));
        } else if (hdr->flags & diameter_avp_flag_mandatory)
            throw win_runtime_error(ERROR_NOT_SUPPORTED, string_printf(__FUNCTION__ " Server sent mandatory Diameter AVP we do not support (code: %u, vendor: %u).", code, vendor));

        pck = msg_next;
    }
}
