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
// eap::method_ttls
//////////////////////////////////////////////////////////////////////

eap::method_ttls::method_ttls(_In_ module &module, _In_ config_method_ttls &cfg, _In_ credentials_ttls &cred) :
    m_cfg(cfg),
    m_cred(cred),
    m_version(version_0),
    method_tls(module, cfg, cred)
{
}


eap::method_ttls::method_ttls(_Inout_ method_ttls &&other) :
    m_cfg     (          other.m_cfg     ),
    m_cred    (          other.m_cred    ),
    m_version (std::move(other.m_version)),
    m_inner   (std::move(other.m_inner  )),
    method_tls(std::move(other          ))
{
}


eap::method_ttls& eap::method_ttls::operator=(_Inout_ method_ttls &&other)
{
    if (this != std::addressof(other)) {
        (method_tls&)*this = std::move(other          );
        m_version          = std::move(other.m_version);
        m_inner            = std::move(other.m_inner  );
    }

    return *this;
}


void eap::method_ttls::begin_session(
    _In_        DWORD         dwFlags,
    _In_  const EapAttributes *pAttributeArray,
    _In_        HANDLE        hTokenImpersonateUser,
    _In_opt_    DWORD         dwMaxSendPacketSize)
{
    method_tls::begin_session(dwFlags, pAttributeArray, hTokenImpersonateUser, dwMaxSendPacketSize);

    // Initialize inner method.
    switch (m_cfg.m_inner->get_method_id()) {
    case eap_type_legacy_pap     : m_inner.reset(new method_pap     (m_module, (config_method_pap     &)*m_cfg.m_inner, (credentials_pass     &)*m_cred.m_inner.get())); break;
    case eap_type_legacy_mschapv2: m_inner.reset(new method_mschapv2(m_module, (config_method_mschapv2&)*m_cfg.m_inner, (credentials_pass&)*m_cred.m_inner.get())); break;
    default: throw invalid_argument(__FUNCTION__ " Unsupported inner authentication method.");
    }
    m_inner->begin_session(dwFlags, pAttributeArray, hTokenImpersonateUser, MAXDWORD);
}


void eap::method_ttls::end_session()
{
    m_inner->end_session();
    method_tls::end_session();
}


void eap::method_ttls::process_request_packet(
    _In_bytecount_(dwReceivedPacketSize) const void                *pReceivedPacket,
    _In_                                       DWORD               dwReceivedPacketSize,
    _Inout_                                    EapPeerMethodOutput *pEapOutput)
{
    if (((const EapPacket*)pReceivedPacket)->Code == EapCodeRequest && (((const EapPacket*)pReceivedPacket)->Data[1] & packet_ttls::flags_start)) {
        // This is a start EAP-TTLS packet.

        // Determine minimum EAP-TTLS version supported by server and us.
        version_t ver_remote = (version_t)(((const EapPacket*)pReceivedPacket)->Data[1] & packet_ttls::flags_ver_mask);
        m_version = std::min<version_t>(ver_remote, version_0);
        m_module.log_event(&EAPMETHOD_TTLS_HANDSHAKE_START, event_data((unsigned int)eap_type_ttls), event_data((unsigned char)m_version), event_data((unsigned char)ver_remote), event_data::blank);
    }

    // Do the TLS.
    method_tls::process_request_packet(pReceivedPacket, dwReceivedPacketSize, pEapOutput);
}


void eap::method_ttls::get_response_packet(
    _Inout_bytecap_(*dwSendPacketSize) void  *pSendPacket,
    _Inout_                            DWORD *pdwSendPacketSize)
{
    method_tls::get_response_packet(pSendPacket, pdwSendPacketSize);

    // Change packet type to EAP-TTLS, and add EAP-TTLS version.
    ((EapPacket*)pSendPacket)->Data[0]  = (BYTE)eap_type_ttls;
    ((EapPacket*)pSendPacket)->Data[1] &= ~packet_ttls::flags_ver_mask;
    ((EapPacket*)pSendPacket)->Data[1] |= m_version;
}


void eap::method_ttls::get_result(
    _In_    EapPeerMethodResultReason reason,
    _Inout_ EapPeerMethodResult       *ppResult)
{
    // Do the TLS.
    method_tls::get_result(reason, ppResult);

    if (m_phase == phase_application_data) {
        // Get inner method result.
        EapPeerMethodResult result = {};
        m_inner->get_result(reason, &result);
        if (result.fSaveConnectionData)
            ppResult->fSaveConnectionData = TRUE;

        if (m_inner->m_cfg.m_last_status != config_method::status_success) {
            // Inner method admitted problems, so autentication must have proceeded to inner authentication already.
            // Therefore, outer authentication must have been OK.
            m_cfg.m_last_status = config_method::status_success;
        }
    }
}


void eap::method_ttls::derive_msk()
{
    const unsigned char *_key_block;

#if EAP_TLS < EAP_TLS_SCHANNEL
    //
    //   TLS versions 1.0 [RFC2246] and 1.1 [RFC4346] define the same PRF
    //   function, and any EAP-TTLSv0 implementation based on these versions
    //   of TLS must use the PRF defined therein.  It is expected that future
    //   versions of or extensions to the TLS protocol will permit alternative
    //   PRF functions to be negotiated.  If an alternative PRF function is
    //   specified for the underlying TLS version or has been negotiated
    //   during the TLS handshake negotiation, then that alternative PRF
    //   function must be used in EAP-TTLSv0 computations instead of the TLS
    //   1.0/1.1 PRF.
    //
    // [Extensible Authentication Protocol Tunneled Transport Layer Security Authenticated Protocol Version 0 (EAP-TTLSv0) (Chapter 7.8. Use of TLS PRF)](https://tools.ietf.org/html/rfc5281#section-7.8)
    //
    // If we use PRF_SHA256() the key exchange fails. Therefore we use PRF of TLS 1.0/1.1.
    //
    static const unsigned char s_label[] = "ttls keying material";
    sanitizing_blob seed(s_label, s_label + _countof(s_label) - 1);
    seed.insert(seed.end(), (const unsigned char*)&m_random_client, (const unsigned char*)(&m_random_client + 1));
    seed.insert(seed.end(), (const unsigned char*)&m_random_server, (const unsigned char*)(&m_random_server + 1));
    sanitizing_blob key_block(prf(m_cp, CALG_TLS1PRF, m_master_secret, seed, 2*sizeof(tls_random)));
    _key_block = key_block.data();
#else
    // EAP-TTLS uses different label in PRF for MSK derivation than EAP-TLS.
    static const DWORD s_key_id = 0x01; // EAP-TTLSv0 Keying Material
    static const SecPkgContext_EapPrfInfo s_prf_info = { 0, sizeof(s_key_id), (PBYTE)&s_key_id };
    SECURITY_STATUS status = SetContextAttributes(m_sc_ctx, SECPKG_ATTR_EAP_PRF_INFO, (void*)&s_prf_info, sizeof(s_prf_info));
    if (FAILED(status))
        throw sec_runtime_error(status, __FUNCTION__ " Error setting EAP-TTLS PRF in Schannel.");

    SecPkgContext_EapKeyBlock key_block;
    status = QueryContextAttributes(m_sc_ctx, SECPKG_ATTR_EAP_KEY_BLOCK, &key_block);
    if (FAILED(status))
        throw sec_runtime_error(status, __FUNCTION__ " Error generating MSK in Schannel.");
    _key_block = key_block.rgbKeys;
#endif

    // MSK: MPPE-Recv-Key
    memcpy(&m_key_mppe_client, _key_block, sizeof(tls_random));
    _key_block += sizeof(tls_random);

    // MSK: MPPE-Send-Key
    memcpy(&m_key_mppe_server, _key_block, sizeof(tls_random));
    _key_block += sizeof(tls_random);

#if EAP_TLS >= EAP_TLS_SCHANNEL
    SecureZeroMemory(&key_block, sizeof(key_block));
#endif
}


void eap::method_ttls::derive_challenge()
{
    method_mschapv2 *inner_mschapv2 = dynamic_cast<method_mschapv2*>(m_inner.get());
    if (inner_mschapv2) {
#if EAP_TLS < EAP_TLS_SCHANNEL
        static const unsigned char s_label[] = "ttls challenge";
        sanitizing_blob seed(s_label, s_label + _countof(s_label) - 1);
        seed.insert(seed.end(), (const unsigned char*)&m_random_client, (const unsigned char*)(&m_random_client + 1));
        seed.insert(seed.end(), (const unsigned char*)&m_random_server, (const unsigned char*)(&m_random_server + 1));
        sanitizing_blob keying(prf(m_cp, CALG_TLS1PRF, m_master_secret, seed, sizeof(challenge_mschapv2) + 1));
        memcpy(&inner_mschapv2->m_challenge_server, keying.data(), sizeof(challenge_mschapv2));
        inner_mschapv2->m_ident = keying[sizeof(challenge_mschapv2) + 0];
#else
        static const DWORD s_key_id = 0x02; // EAP-TTLSv0 Challenge Data
        static const SecPkgContext_EapPrfInfo s_prf_info = { 0, sizeof(s_key_id), (PBYTE)&s_key_id };
        SECURITY_STATUS status = SetContextAttributes(m_sc_ctx, SECPKG_ATTR_EAP_PRF_INFO, (void*)&s_prf_info, sizeof(s_prf_info));
        if (FAILED(status))
            throw sec_runtime_error(status, __FUNCTION__ " Error setting EAP-TTLS PRF in Schannel.");

        SecPkgContext_EapKeyBlock key_block;
        status = QueryContextAttributes(m_sc_ctx, SECPKG_ATTR_EAP_KEY_BLOCK, &key_block);
        if (FAILED(status))
            throw sec_runtime_error(status, __FUNCTION__ " Error generating PRF in Schannel.");

        memcpy(&inner_mschapv2->m_challenge_server, key_block.rgbKeys, sizeof(challenge_mschapv2));
        inner_mschapv2->m_ident = key_block.rgbKeys[sizeof(challenge_mschapv2) + 0];
#endif
    }
}


void eap::method_ttls::process_application_data(_In_bytecount_(size_msg) const void *msg, _In_ size_t size_msg)
{
    // Prepare inner authentication.
#if EAP_TLS < EAP_TLS_SCHANNEL
    if (!m_state_client.m_alg_encrypt)
        throw runtime_error(__FUNCTION__ " Refusing to continue with inner authentication unencrypted.");

    if (m_session_resumed) {
        // On reconnect we do not need to do inner re-authentication.
        return;
    }
#else
    if (!(m_sc_ctx.m_attrib & ISC_RET_CONFIDENTIALITY))
        throw runtime_error(__FUNCTION__ " Refusing to continue with inner authentication unencrypted.");

    SecPkgContext_SessionInfo session_info;
    if (SUCCEEDED(QueryContextAttributes(m_sc_ctx, SECPKG_ATTR_SESSION_INFO, &session_info)) && (session_info.dwFlags & SSL_SESSION_RECONNECT)) {
        // On reconnect we do not need to do inner re-authentication.
        // According to MSDN QueryContextAttributes(SECPKG_ATTR_SESSION_INFO) works from Windows 7 on. Therefore behaviour might vary.
        return;
    }
#endif

    EapPeerMethodOutput eap_output = {};
    m_inner->process_request_packet(msg, (DWORD)size_msg, &eap_output);
    switch (eap_output.action) {
    case EapPeerMethodResponseActionSend: {
        // Retrieve inner packet and send it.

        // Get maximum message size and allocate memory for response packet.
#if EAP_TLS < EAP_TLS_SCHANNEL
        m_packet_res.m_code  = EapCodeResponse;
        m_packet_res.m_id    = m_packet_req.m_id;
        m_packet_res.m_flags = 0;

        DWORD size_data = (DWORD)get_max_message(16384 - sizeof(message_header));
        sanitizing_blob data(size_data, 0);
        unsigned char *ptr_data = data.data();
#else
        SecPkgContext_StreamSizes sizes;
        SECURITY_STATUS status = QueryContextAttributes(m_sc_ctx, SECPKG_ATTR_STREAM_SIZES, &sizes);
        if (FAILED(status))
            throw sec_runtime_error(status, __FUNCTION__ " Error getting Schannel required encryption sizes.");

        sanitizing_blob data(sizes.cbHeader + sizes.cbMaximumMessage + sizes.cbTrailer, 0);
        DWORD size_data = sizes.cbMaximumMessage;
        unsigned char *ptr_data = data.data() + sizes.cbHeader;
#endif
        m_inner->get_response_packet(ptr_data, &size_data);

        if (size_data) {
#if EAP_TLS < EAP_TLS_SCHANNEL
            data.resize(size_data);
            sanitizing_blob msg_application(make_message(tls_message_type_application_data, std::move(data)));
            m_packet_res.m_data.insert(m_packet_res.m_data.end(), msg_application.begin(), msg_application.end());
#else
            // Prepare input/output buffer(s).
            SecBuffer buf[] = {
                {  sizes.cbHeader, SECBUFFER_STREAM_HEADER , data.data()          },
                {       size_data, SECBUFFER_DATA          , ptr_data             },
                { sizes.cbTrailer, SECBUFFER_STREAM_TRAILER, ptr_data + size_data },
                {               0, SECBUFFER_EMPTY         , NULL                 },
            };
            SecBufferDesc buf_desc = {
                SECBUFFER_VERSION,
                _countof(buf),
                buf
            };

            // Encrypt the message.
            status = EncryptMessage(m_sc_ctx, 0, &buf_desc, 0);
            if (FAILED(status))
                throw sec_runtime_error(status, __FUNCTION__ " Error encrypting message.");
            m_packet_res.m_data.insert(m_packet_res.m_data.end(), (const unsigned char*)buf[0].pvBuffer, (const unsigned char*)buf[0].pvBuffer + buf[0].cbBuffer + buf[1].cbBuffer + buf[2].cbBuffer);
#endif
        } else {
            // Empty packets represent ACK message, and are not encrypted.
        }

        break;
    }

    default:
        throw invalid_argument(string_printf(__FUNCTION__ " Inner method returned an unsupported action (action %u).", eap_output.action).c_str());
    }
}
