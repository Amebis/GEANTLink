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

eap::method_mschapv2::method_mschapv2(_In_ module &module, _In_ config_method_mschapv2 &cfg, _In_ credentials_mschapv2 &cred) :
    m_cred(cred),
    m_ident(0),
    m_success(false),
    m_phase(phase_unknown),
    m_phase_prev(phase_unknown),
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
    m_phase_prev      (std::move(other.m_phase_prev      )),
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
        m_phase_prev          = std::move(other.m_phase_prev      );
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

    m_phase_prev = m_phase;
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
        response.insert(response.end(), (unsigned char*)&m_challenge_client, (unsigned char*)(&m_challenge_client + 1)); // Peer-Challenge
        response.insert(response.end(), 8, 0); // Reserved
        response.insert(response.end(), (unsigned char*)&m_nt_resp, (unsigned char*)(&m_nt_resp + 1)); // NT-Response

        // Diameter AVP (User-Name=1, MS-CHAP-Challenge=11/311, MS-CHAP2-Response=25/311)
        append_avp( 1,      diameter_avp_flag_mandatory,                 identity_utf8.data(), (unsigned int)identity_utf8.size()      );
        append_avp(11, 311, diameter_avp_flag_mandatory, (unsigned char*)&m_challenge_server , (unsigned int)sizeof(m_challenge_server));
        append_avp(25, 311, diameter_avp_flag_mandatory,                 response.data()     , (unsigned int)response.size()           );

        m_phase = phase_challenge_server;
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


void eap::method_mschapv2::get_result(
    _In_    EapPeerMethodResultReason reason,
    _Inout_ EapPeerMethodResult       *ppResult)
{
    assert(ppResult);

    switch (reason) {
    case EapPeerMethodResultSuccess: {
        m_module.log_event(&EAPMETHOD_METHOD_SUCCESS, event_data((unsigned int)eap_type_legacy_mschapv2), event_data::blank);
        m_cfg.m_auth_failed = false;

        break;
    }

    case EapPeerMethodResultFailure:
        m_module.log_event(
            m_phase_prev < phase_finished ? &EAPMETHOD_METHOD_FAILURE_INIT : &EAPMETHOD_METHOD_FAILURE,
            event_data((unsigned int)eap_type_legacy_mschapv2), event_data::blank);

        // Mark credentials as failed, so GUI can re-prompt user.
        // But be careful: do so only after credentials were actually tried.
        m_cfg.m_auth_failed = m_phase_prev < phase_finished && m_phase >= phase_finished;

        break;

    default:
        throw win_runtime_error(ERROR_NOT_SUPPORTED, __FUNCTION__ " Not supported.");
    }

    // Always ask EAP host to save the connection data.
    ppResult->fSaveConnectionData = TRUE;
}


void eap::method_mschapv2::process_packet(_In_bytecount_(size_pck) const void *_pck, _In_ size_t size_pck)
{
    sanitizing_blob data;
    wstring msg_w;

    for (const unsigned char *pck = (const unsigned char*)_pck, *pck_end = pck + size_pck; pck < pck_end; ) {
        if (pck + sizeof(diameter_avp_header) > pck_end)
            throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Incomplete message header.");
        const diameter_avp_header *hdr = (const diameter_avp_header*)pck;
        unsigned int code = ntohl(*(unsigned int*)hdr->code);
        unsigned int vendor;
        const unsigned char *msg;
        if (hdr->flags & diameter_avp_flag_vendor) {
            if (pck + sizeof(diameter_avp_header_ven) > pck_end)
                throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Incomplete message header.");
            const diameter_avp_header_ven *hdr_ven = (const diameter_avp_header_ven*)pck;
            vendor = ntohl(*(unsigned int*)hdr_ven->vendor);
            msg = (const unsigned char*)(hdr_ven + 1);
        } else {
            vendor = 0;
            msg = (const unsigned char*)(hdr + 1);
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
            const char *str = (const char*)(msg + 1);
            MultiByteToWideChar(CP_UTF8, 0, str, (int)((const char*)msg_end - str), msg_w);
            int argc;
            unique_ptr<LPWSTR[], LocalFree_delete<LPWSTR[]> > argv(CommandLineToArgvW(msg_w.c_str(), &argc));
            if (!argv) argc = 0;
            process_success(argc, (const wchar_t**)argv.get());
        } else if (code == 2 && vendor == 311) {
            // MS-CHAP2-Error
            if (msg[0] != m_ident)
                throw invalid_argument(string_printf(__FUNCTION__ " Wrong MSCHAPv2 ident (expected: %u, received: %u).", m_ident, msg[0]).c_str());
            const char *str = (const char*)(msg + 1);
            MultiByteToWideChar(CP_UTF8, 0, str, (int)((const char*)msg_end - str), msg_w);
            int argc;
            unique_ptr<LPWSTR[], LocalFree_delete<LPWSTR[]> > argv(CommandLineToArgvW(msg_w.c_str(), &argc));
            if (!argv) argc = 0;
            process_error(argc, (const wchar_t**)argv.get());
        } else if (hdr->flags & diameter_avp_flag_mandatory)
            throw win_runtime_error(ERROR_NOT_SUPPORTED, string_printf(__FUNCTION__ " Server sent mandatory Diameter AVP we do not support (code: %u, vendor: %u).", code, vendor).c_str());

        pck = msg_next;
    }
}


void eap::method_mschapv2::process_success(_In_ int argc, _In_count_(argc) const wchar_t *argv[])
{
    m_success = false;

    for (int i = 0; i < argc; i++) {
        if ((argv[i][0] == L'S' || argv[i][0] == L's') && argv[i][1] == L'=') {
            // "S="
            hex_dec dec;
            sanitizing_blob resp;
            bool is_last;
            dec.decode(resp, is_last, argv[i] + 2, (size_t)-1);

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

    //m_module.log_event(&EAPMETHOD_TLS_ALERT, event_data((unsigned int)eap_type_tls), event_data((unsigned char)msg[0]), event_data((unsigned char)msg[1]), event_data::blank);
}


void eap::method_mschapv2::process_error(_In_ int argc, _In_count_(argc) const wchar_t *argv[])
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);
}
