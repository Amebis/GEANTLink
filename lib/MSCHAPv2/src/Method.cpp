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
// eap::method_mschapv2
//////////////////////////////////////////////////////////////////////

eap::method_mschapv2::method_mschapv2(_In_ module &module, _In_ config_method_mschapv2 &cfg, _In_ credentials_pass &cred) :
    m_cred(cred),
    m_ident(0),
    m_success(false),
    m_phase(phase_unknown),
    method_noneap(module, cfg, cred)
{
}


eap::method_mschapv2::method_mschapv2(_Inout_ method_mschapv2 &&other) :
    m_cred            (          other.m_cred             ),
    m_cp              (std::move(other.m_cp              )),
    m_challenge_server(std::move(other.m_challenge_server)),
    m_challenge_client(std::move(other.m_challenge_client)),
    m_ident           (std::move(other.m_ident           )),
    m_nt_resp         (std::move(other.m_nt_resp         )),
    m_success         (std::move(other.m_success         )),
    m_phase           (std::move(other.m_phase           )),
    method_noneap     (std::move(other                   ))
{
}


eap::method_mschapv2& eap::method_mschapv2::operator=(_Inout_ method_mschapv2 &&other)
{
    if (this != std::addressof(other)) {
        assert(std::addressof(m_cred) == std::addressof(other.m_cred)); // Move method with same credentials only!
        (method_noneap&)*this = std::move(other                   );
        m_cp                  = std::move(other.m_cp              );
        m_challenge_server    = std::move(other.m_challenge_server);
        m_challenge_client    = std::move(other.m_challenge_client);
        m_ident               = std::move(other.m_ident           );
        m_nt_resp             = std::move(other.m_nt_resp         );
        m_success             = std::move(other.m_success         );
        m_phase               = std::move(other.m_phase           );
    }

    return *this;
}


void eap::method_mschapv2::begin_session(
    _In_        DWORD         dwFlags,
    _In_  const EapAttributes *pAttributeArray,
    _In_        HANDLE        hTokenImpersonateUser,
    _In_opt_    DWORD         dwMaxSendPacketSize)
{
    method_noneap::begin_session(dwFlags, pAttributeArray, hTokenImpersonateUser, dwMaxSendPacketSize);

    // Create cryptographics provider for support needs (client challenge ...).
    if (!m_cp.create(NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        throw win_runtime_error(__FUNCTION__ " Error creating cryptographics provider.");

    m_module.log_event(&EAPMETHOD_METHOD_HANDSHAKE_START2, event_data((unsigned int)eap_type_legacy_mschapv2), event_data::blank);
    m_phase = phase_init;
}


void eap::method_mschapv2::process_request_packet(
    _In_bytecount_(dwReceivedPacketSize) const void                *pReceivedPacket,
    _In_                                       DWORD               dwReceivedPacketSize,
    _Inout_                                    EapPeerMethodOutput *pEapOutput)
{
    assert(pReceivedPacket || dwReceivedPacketSize == 0);
    assert(pEapOutput);

    m_module.log_event(&EAPMETHOD_PACKET_RECV, event_data((unsigned int)eap_type_legacy_mschapv2), event_data((unsigned int)dwReceivedPacketSize), event_data::blank);

    switch (m_phase) {
    case phase_init: {
        // Convert username to UTF-8.
        sanitizing_string identity_utf8;
        WideCharToMultiByte(CP_UTF8, 0, m_cred.m_identity.c_str(), (int)m_cred.m_identity.length(), identity_utf8, NULL, NULL);

        // Randomize Peer-Challenge
        m_challenge_client.randomize(m_cp);

        // Calculate NT-Response
        m_nt_resp = nt_response(m_cp, m_challenge_server, m_challenge_client, identity_utf8.c_str(), m_cred.m_password.c_str());

        // Prepare MS-CHAP2-Response
        sanitizing_blob response;
        response.reserve(
            1                          + // Ident
            1                          + // Flags
            sizeof(challenge_mschapv2) + // Peer-Challenge
            8                          + // Reserved
            sizeof(nt_response));        // Response
        response.push_back(m_ident);
        response.push_back(0); // Flags
        response.insert(response.end(), reinterpret_cast<const unsigned char*>(&m_challenge_client), reinterpret_cast<const unsigned char*>(&m_challenge_client + 1)); // Peer-Challenge
        response.insert(response.end(), 8, 0); // Reserved
        response.insert(response.end(), reinterpret_cast<const unsigned char*>(&m_nt_resp), reinterpret_cast<const unsigned char*>(&m_nt_resp + 1)); // NT-Response

        // Diameter AVP (User-Name=1, MS-CHAP-Challenge=11/311, MS-CHAP2-Response=25/311)
        append_avp( 1,      diameter_avp_flag_mandatory,                                         identity_utf8.data(), (unsigned int)identity_utf8.size()      );
        append_avp(11, 311, diameter_avp_flag_mandatory, reinterpret_cast<const unsigned char*>(&m_challenge_server) , (unsigned int)sizeof(m_challenge_server));
        append_avp(25, 311, diameter_avp_flag_mandatory,                                         response.data()     , (unsigned int)response.size()           );

        m_phase = phase_challenge_server;
        m_cfg.m_last_status = config_method::status_cred_invalid; // Blame credentials if we fail beyond this point.
        break;
    }

    case phase_challenge_server: {
        process_packet(pReceivedPacket, dwReceivedPacketSize);
        if (m_success)
            m_phase = phase_finished;
        break;
    }

    case phase_finished:
        break;
    }

    pEapOutput->fAllowNotifications = TRUE;
    pEapOutput->action = EapPeerMethodResponseActionSend;
}


void eap::method_mschapv2::process_packet(_In_bytecount_(size_pck) const void *_pck, _In_ size_t size_pck)
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
                throw invalid_argument(string_printf(__FUNCTION__ " Wrong MSCHAPv2 ident (expected: %u, received: %u).", m_ident, msg[0]).c_str());
            const char *str = reinterpret_cast<const char*>(msg + 1);
            process_success(parse_response(str, (reinterpret_cast<const char*>(msg_end) - str)));
        } else if (code == 2 && vendor == 311) {
            // MS-CHAP2-Error
            m_ident = msg[0];
            const char *str = reinterpret_cast<const char*>(msg + 1);
            process_error(parse_response(str, (reinterpret_cast<const char*>(msg_end) - str)));
        } else if (hdr->flags & diameter_avp_flag_mandatory)
            throw win_runtime_error(ERROR_NOT_SUPPORTED, string_printf(__FUNCTION__ " Server sent mandatory Diameter AVP we do not support (code: %u, vendor: %u).", code, vendor).c_str());

        pck = msg_next;
    }
}


void eap::method_mschapv2::process_success(_In_ const list<string> &argv)
{
    m_success = false;

    for (list<string>::const_iterator arg = argv.cbegin(), arg_end = argv.cend(); arg != arg_end; ++arg) {
        const string &val = *arg;
        if ((val[0] == 'S' || val[0] == 's') && val[1] == '=') {
            // "S="
            hex_dec dec;
            sanitizing_blob resp;
            bool is_last;
            dec.decode(resp, is_last, val.data() + 2, (size_t)-1);

            // Calculate expected authenticator response.
            sanitizing_string identity_utf8;
            WideCharToMultiByte(CP_UTF8, 0, m_cred.m_identity.c_str(), (int)m_cred.m_identity.length(), identity_utf8, NULL, NULL);
            authenticator_response resp_exp(m_cp, m_challenge_server, m_challenge_client, identity_utf8.c_str(), m_cred.m_password.c_str(), m_nt_resp);

            // Compare against provided authemticator response.
            if (resp.size() != sizeof(resp_exp) || memcmp(resp.data(), &resp_exp, sizeof(resp_exp)) != 0)
                throw invalid_argument(__FUNCTION__ " MS-CHAP2-Success authentication response string failed.");

            m_success = true;
        }
    }

    if (!m_success)
        throw invalid_argument(__FUNCTION__ " MS-CHAP2-Success authentication response string not found.");
}


void eap::method_mschapv2::process_error(_In_ const list<string> &argv)
{
    for (list<string>::const_iterator arg = argv.cbegin(), arg_end = argv.cend(); arg != arg_end; ++arg) {
        const string &val = *arg;
        if ((val[0] == 'E' || val[0] == 'e') && val[1] == '=') {
            DWORD dwResult = strtoul(val.data() + 2, NULL, 10);
            m_module.log_event(&EAPMETHOD_METHOD_FAILURE_ERROR, event_data((unsigned int)eap_type_legacy_mschapv2), event_data(dwResult), event_data::blank);
            switch (dwResult) {
            case ERROR_ACCT_DISABLED         : m_cfg.m_last_status = config_method::status_account_disabled   ; break;
            case ERROR_RESTRICTED_LOGON_HOURS: m_cfg.m_last_status = config_method::status_account_logon_hours; break;
            case ERROR_NO_DIALIN_PERMISSION  : m_cfg.m_last_status = config_method::status_account_denied     ; break;
            case ERROR_PASSWD_EXPIRED        : m_cfg.m_last_status = config_method::status_cred_expired       ; break;
            case ERROR_CHANGING_PASSWORD     : m_cfg.m_last_status = config_method::status_cred_changing      ; break;
            default                          : m_cfg.m_last_status = config_method::status_cred_invalid       ;
            }
        } else if ((val[0] == 'C' || val[0] == 'c') && val[1] == '=') {
            hex_dec dec;
            sanitizing_blob resp;
            bool is_last;
            dec.decode(resp, is_last, val.data() + 2, (size_t)-1);
            if (resp.size() != sizeof(m_challenge_server))
                throw invalid_argument(string_printf(__FUNCTION__ " Incorrect MSCHAPv2 challenge length (expected: %uB, received: %uB).", sizeof(m_challenge_server), resp.size()).c_str());
            memcpy(&m_challenge_server, resp.data(), sizeof(m_challenge_server));
        } else if ((val[0] == 'M' || val[0] == 'm') && val[1] == '=') {
            MultiByteToWideChar(CP_UTF8, 0, val.data() + 2, -1, m_cfg.m_last_msg);
            m_module.log_event(&EAPMETHOD_METHOD_FAILURE_ERROR1, event_data((unsigned int)eap_type_legacy_mschapv2), event_data(m_cfg.m_last_msg), event_data::blank);
        }
    }
}


list<string> eap::method_mschapv2::parse_response(_In_count_(count) const char *resp, _In_ size_t count)
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
