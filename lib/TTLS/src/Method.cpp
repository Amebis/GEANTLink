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

eap::method_ttls::method_ttls(_In_ module &module, _In_ config_provider_list &cfg, _In_ credentials_ttls &cred) :
    m_cred(cred),
    m_version(version_0),
    method_tls(module, cfg, cred)
{
}


eap::method_ttls::method_ttls(_Inout_ method_ttls &&other) :
    m_cred(other.m_cred),
    m_version(std::move(other.m_version)),
    method_tls(std::move(other))
{
}


eap::method_ttls& eap::method_ttls::operator=(_Inout_ method_ttls &&other)
{
    if (this != std::addressof(other)) {
        (method_tls&)*this = std::move(other);
        m_version          = std::move(other.m_version);
    }

    return *this;
}


void eap::method_ttls::process_request_packet(
    _In_bytecount_(dwReceivedPacketSize) const EapPacket           *pReceivedPacket,
    _In_                                       DWORD               dwReceivedPacketSize,
    _Inout_                                    EapPeerMethodOutput *pEapOutput)
{
    if (pReceivedPacket->Code == EapCodeRequest && (pReceivedPacket->Data[1] & flags_start)) {
        // This is a start EAP-TTLS packet.

        // Determine minimum EAP-TTLS version supported by server and us.
        version_t ver_remote = (version_t)(pReceivedPacket->Data[1] & flags_ver_mask);
        m_version = std::min<version_t>(ver_remote, version_0);
        m_module.log_event(&EAPMETHOD_TTLS_HANDSHAKE_START, event_data((unsigned int)eap_type_ttls), event_data((unsigned char)m_version), event_data((unsigned char)ver_remote), event_data::blank);
    }

    if (!m_server_finished) {
        // Do the TLS.
        method_tls::process_request_packet(pReceivedPacket, dwReceivedPacketSize, pEapOutput);

        if (m_server_finished) {
            // Piggyback inner authentication.
            if (!m_state_client.m_alg_encrypt)
                throw runtime_error(__FUNCTION__ " Refusing to send credentials unencrypted.");

            m_packet_res.m_code  = EapCodeResponse;
            m_packet_res.m_id    = m_packet_req.m_id;
            m_packet_res.m_flags = 0;
            sanitizing_blob msg_application(make_message(tls_message_type_application_data, make_pap_client()));
            m_packet_res.m_data.assign(msg_application.begin(), msg_application.end());

            pEapOutput->fAllowNotifications = FALSE;
            pEapOutput->action = EapPeerMethodResponseActionSend;
        }
    } else {
        // Do the TLS. Again.
        method_tls::process_request_packet(pReceivedPacket, dwReceivedPacketSize, pEapOutput);
    }
}


void eap::method_ttls::get_response_packet(
    _Inout_bytecap_(*dwSendPacketSize) EapPacket *pSendPacket,
    _Inout_                            DWORD     *pdwSendPacketSize)
{
    method_tls::get_response_packet(pSendPacket, pdwSendPacketSize);

    // Change packet type to EAP-TTLS, and add EAP-TTLS version.
    pSendPacket->Data[0]  = (BYTE)eap_type_ttls;
    pSendPacket->Data[1] &= ~flags_ver_mask;
    pSendPacket->Data[1] |= m_version;
}


void eap::method_ttls::get_result(
    _In_    EapPeerMethodResultReason reason,
    _Inout_ EapPeerMethodResult       *ppResult)
{
    if (!m_server_finished) {
        // Do the TLS.
        method_tls::get_result(reason, ppResult);
    } else {
        config_provider &cfg_prov(m_cfg.m_providers.front());
        config_method_ttls *cfg_method = dynamic_cast<config_method_ttls*>(cfg_prov.m_methods.front().get());
        assert(cfg_method);

        // Mark credentials appropriately, so GUI can re-prompt user.
        cfg_method->m_inner->m_cred_failed = reason == EapPeerMethodResultFailure;

        // The TLS was OK.
        method_tls::get_result(EapPeerMethodResultSuccess, ppResult);

        //if (reason == EapPeerMethodResultFailure) {
        //    ppResult->fIsSuccess = FALSE;
        //    ppResult->dwFailureReasonCode = EAP_E_AUTHENTICATION_FAILED;
        //}
    }
}


void eap::method_ttls::derive_msk()
{
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
    const unsigned char *_key_block = key_block.data();

    // MSK: MPPE-Recv-Key
    memcpy(&m_key_mppe_client, _key_block, sizeof(tls_random));
    _key_block += sizeof(tls_random);

    // MSK: MPPE-Send-Key
    memcpy(&m_key_mppe_server, _key_block, sizeof(tls_random));
    _key_block += sizeof(tls_random);
}


eap::sanitizing_blob eap::method_ttls::make_pap_client() const
{
    const credentials_pap *cred = dynamic_cast<credentials_pap*>(m_cred.m_inner.get());
    if (!cred)
        throw invalid_argument(__FUNCTION__ " Inner credentials missing or not PAP.");

    // Convert username and password to UTF-8.
    sanitizing_string identity_utf8, password_utf8;
    WideCharToMultiByte(CP_UTF8, 0, cred->m_identity.c_str(), (int)cred->m_identity.length(), identity_utf8, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, cred->m_password.c_str(), (int)cred->m_password.length(), password_utf8, NULL, NULL);

    // PAP passwords must be padded to 16B boundary according to RFC 5281. Will not add random extra padding here, as length obfuscation should be done by TLS encryption layer.
    size_t padding_password_ex = (16 - password_utf8.length()) % 16;
    password_utf8.append(padding_password_ex, 0);

    size_t
        size_identity    = identity_utf8.length(),
        size_password    = password_utf8.length(),
        padding_identity = (4 - size_identity         ) % 4,
        padding_password = (4 - password_utf8.length()) % 4,
        size_identity_outer,
        size_password_outer;

    sanitizing_blob msg;
    msg.reserve(
        (size_identity_outer = 
        4                + // Diameter AVP Code
        4                + // Diameter AVP Flags & Length
        size_identity)   + // Identity
        padding_identity + // Identity padding
        (size_password_outer = 
        4                + // Diameter AVP Code
        4                + // Diameter AVP Flags & Length
        size_password)   + // Password
        padding_password); // Password padding

    // Diameter AVP Code User-Name (0x00000001)
    msg.push_back(0x00);
    msg.push_back(0x00);
    msg.push_back(0x00);
    msg.push_back(0x01);

    // Diameter AVP Flags & Length
    unsigned int identity_hdr = htonl((diameter_avp_flag_mandatory << 24) | (unsigned int)size_identity_outer);
    msg.insert(msg.end(), (unsigned char*)&identity_hdr, (unsigned char*)(&identity_hdr + 1));

    // Identity
    msg.insert(msg.end(), identity_utf8.begin(), identity_utf8.end());
    msg.insert(msg.end(), padding_identity, 0);

    // Diameter AVP Code User-Password (0x00000002)
    msg.push_back(0x00);
    msg.push_back(0x00);
    msg.push_back(0x00);
    msg.push_back(0x02);

    // Diameter AVP Flags & Length
    unsigned int password_hdr = htonl((diameter_avp_flag_mandatory << 24) | (unsigned int)size_password_outer);
    msg.insert(msg.end(), (unsigned char*)&password_hdr, (unsigned char*)(&password_hdr + 1));

    // Password
    msg.insert(msg.end(), password_utf8.begin(), password_utf8.end());
    msg.insert(msg.end(), padding_password, 0);

    return msg;
}
