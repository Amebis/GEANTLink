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

#pragma comment(lib, "Secur32.lib")

using namespace std;
using namespace winstd;


//////////////////////////////////////////////////////////////////////
// eap::method_tls::packet
//////////////////////////////////////////////////////////////////////

eap::method_tls::packet::packet() :
    m_code((EapCode)0),
    m_id(0),
    m_flags(0)
{
}


eap::method_tls::packet::packet(_In_ const packet &other) :
    m_code (other.m_code ),
    m_id   (other.m_id   ),
    m_flags(other.m_flags),
    m_data (other.m_data )
{
}


eap::method_tls::packet::packet(_Inout_ packet &&other) :
    m_code (std::move(other.m_code )),
    m_id   (std::move(other.m_id   )),
    m_flags(std::move(other.m_flags)),
    m_data (std::move(other.m_data ))
{
}


eap::method_tls::packet& eap::method_tls::packet::operator=(_In_ const packet &other)
{
    if (this != std::addressof(other)) {
        m_code  = other.m_code ;
        m_id    = other.m_id   ;
        m_flags = other.m_flags;
        m_data  = other.m_data ;
    }

    return *this;
}


eap::method_tls::packet& eap::method_tls::packet::operator=(_Inout_ packet &&other)
{
    if (this != std::addressof(other)) {
        m_code  = std::move(other.m_code );
        m_id    = std::move(other.m_id   );
        m_flags = std::move(other.m_flags);
        m_data  = std::move(other.m_data );
    }

    return *this;
}


void eap::method_tls::packet::clear()
{
    m_code  = (EapCode)0;
    m_id    = 0;
    m_flags = 0;
    m_data.clear();
}


//////////////////////////////////////////////////////////////////////
// eap::method_tls
//////////////////////////////////////////////////////////////////////

eap::method_tls::method_tls(_In_ module &module, _In_ config_provider_list &cfg, _In_ credentials_tls &cred) :
    m_cred(cred),
    m_user_ctx(NULL),
    m_phase(phase_unknown),
    m_blob_cfg(NULL),
#ifdef EAP_USE_NATIVE_CREDENTIAL_CACHE
    m_blob_cred(NULL),
#endif
    method(module, cfg, cred)
{
}


eap::method_tls::method_tls(_Inout_ method_tls &&other) :
    m_cred          (          other.m_cred           ),
    m_packet_req    (std::move(other.m_packet_req    )),
    m_packet_res    (std::move(other.m_packet_res    )),
    m_user_ctx      (std::move(other.m_user_ctx      )),
    m_sc_target_name(std::move(other.m_sc_target_name)),
    m_sc_cred       (std::move(other.m_sc_cred       )),
    m_sc_queue      (std::move(other.m_sc_queue      )),
    m_sc_ctx        (std::move(other.m_sc_ctx        )),
    m_phase         (std::move(other.m_phase         )),
    method          (std::move(other                 ))
{
}


eap::method_tls::~method_tls()
{
    if (m_blob_cfg)
        m_module.free_memory(m_blob_cfg);

#ifdef EAP_USE_NATIVE_CREDENTIAL_CACHE
    if (m_blob_cred)
        m_module.free_memory(m_blob_cred);
#endif
}


eap::method_tls& eap::method_tls::operator=(_Inout_ method_tls &&other)
{
    if (this != std::addressof(other)) {
        assert(std::addressof(m_cred) == std::addressof(other.m_cred)); // Move method with same credentials only!
        (method&)*this   = std::move(other                 );
        m_packet_req     = std::move(other.m_packet_req    );
        m_packet_res     = std::move(other.m_packet_res    );
        m_user_ctx       = std::move(other.m_user_ctx      );
        m_sc_target_name = std::move(other.m_sc_target_name);
        m_sc_cred        = std::move(other.m_sc_cred       );
        m_sc_queue       = std::move(other.m_sc_queue      );
        m_sc_ctx         = std::move(other.m_sc_ctx        );
        m_phase          = std::move(other.m_phase         );
    }

    return *this;
}


void eap::method_tls::begin_session(
    _In_        DWORD         dwFlags,
    _In_  const EapAttributes *pAttributeArray,
    _In_        HANDLE        hTokenImpersonateUser,
    _In_        DWORD         dwMaxSendPacketSize)
{
    method::begin_session(dwFlags, pAttributeArray, hTokenImpersonateUser, dwMaxSendPacketSize);

    m_user_ctx = hTokenImpersonateUser;
    user_impersonator impersonating(m_user_ctx);

    // Get method configuration.
    if (m_cfg.m_providers.empty() || m_cfg.m_providers.front().m_methods.empty())
        throw invalid_argument(__FUNCTION__ " Configuration has no providers and/or methods.");
    const config_provider &cfg_prov(m_cfg.m_providers.front());
    const config_method_tls *cfg_method = dynamic_cast<const config_method_tls*>(cfg_prov.m_methods.front().get());
    assert(cfg_method);

    // Build (expected) server name(s) for Schannel.
    m_sc_target_name.clear();
    for (list<wstring>::const_iterator name = cfg_method->m_server_names.cbegin(), name_end = cfg_method->m_server_names.cend(); name != name_end; ++name) {
        if (name != cfg_method->m_server_names.cbegin())
            m_sc_target_name += _T(';');
#ifdef _UNICODE
        m_sc_target_name.insert(m_sc_target_name.end(), name->begin(), name->end());
#else
        string buf;
        WideCharToMultiByte(CP_ACP, 0, name->c_str(), -1, buf, NULL, NULL);
        m_sc_target_name.insert(m_sc_target_name.end(), buf.begin(), buf.end());
#endif
    }

    // Prepare client credentials for Schannel.
    PCCERT_CONTEXT certs[] = { m_cred.m_cert ? m_cred.m_cert : NULL };
    SCHANNEL_CRED cred = {
        SCHANNEL_CRED_VERSION,                                                      // dwVersion
        m_cred.m_cert ? 1 : 0,                                                      // cCreds
        certs,                                                                      // paCred
        NULL,                                                                       // hRootStore: Not valid for client credentials
        0,                                                                          // cMappers
        NULL,                                                                       // aphMappers
        0,                                                                          // cSupportedAlgs: Use system configured default
        NULL,                                                                       // palgSupportedAlgs: Use system configured default
        0,                                                                          // grbitEnabledProtocols: Use default
        0,                                                                          // dwMinimumCipherStrength: Use system configured default
        0,                                                                          // dwMaximumCipherStrength: Use system configured default
        0,                                                                          // dwSessionLifespan: Use system configured default = 10hr
#ifdef SCHANNEL_SRV_CERT_CHECK
        SCH_CRED_AUTO_CRED_VALIDATION                                           |   // dwFlags: Let Schannel verify server certificate
#else
        SCH_CRED_MANUAL_CRED_VALIDATION                                         |   // dwFlags: Prevent Schannel verify server certificate (we want to use custom root CA store and multiple name checking)
#endif
        SCH_CRED_CACHE_ONLY_URL_RETRIEVAL_ON_CREATE                             |   // dwFlags: Do not attempt online revocation check - we do not expect to have network connection yet
        SCH_CRED_IGNORE_NO_REVOCATION_CHECK                                     |   // dwFlags: Ignore no-revocation-check errors (TODO: Test if this flag is required.)
        SCH_CRED_IGNORE_REVOCATION_OFFLINE                                      |   // dwFlags: Ignore offline-revocation errors - we do not expect to have network connection yet
        SCH_CRED_NO_DEFAULT_CREDS                                               |   // dwFlags: If client certificate we provided is not acceptable, do not try to select one on your own
        (cfg_method->m_server_names.empty() ? SCH_CRED_NO_SERVERNAME_CHECK : 0) |   // dwFlags: When no expected server name is given, do not do the server name check.
        0x00400000 /*SCH_USE_STRONG_CRYPTO*/,                                       // dwFlags: Do not use broken ciphers
        0                                                                           // dwCredFormat
    };
    SECURITY_STATUS stat = m_sc_cred.acquire(NULL, UNISP_NAME, SECPKG_CRED_OUTBOUND, NULL, &cred);
    if (FAILED(stat))
        throw sec_runtime_error(stat, __FUNCTION__ " Error acquiring Schannel credentials handle.");
}


void eap::method_tls::process_request_packet(
    _In_bytecount_(dwReceivedPacketSize) const EapPacket           *pReceivedPacket,
    _In_                                       DWORD               dwReceivedPacketSize,
    _Inout_                                    EapPeerMethodOutput *pEapOutput)
{
    assert(pReceivedPacket && dwReceivedPacketSize >= 4);
    assert(pEapOutput);

    // Is this a valid EAP-TLS packet?
    if (dwReceivedPacketSize < 6)
        throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Packet is too small. EAP-%s packets should be at least 6B.");
    //else if (pReceivedPacket->Data[0] != eap_type_tls) // Skip method check, to allow TTLS extension.
    //    throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, string_printf(__FUNCTION__ " Packet is not EAP-TLS (expected: %u, received: %u).", eap_type_tls, pReceivedPacket->Data[0]));

    // Get packet data pointer and size for more readable code later on.
    const unsigned char *packet_data_ptr;
    size_t packet_data_size;
    if (pReceivedPacket->Data[1] & flags_req_length_incl) {
        // Length field is included.
        packet_data_ptr  = pReceivedPacket->Data + 6;
        packet_data_size = dwReceivedPacketSize - 10;
    } else {
        // Length field not included.
        packet_data_ptr  = pReceivedPacket->Data + 2;
        packet_data_size = dwReceivedPacketSize - 6;
    }

    // Do the EAP-TLS defragmentation.
    if (pReceivedPacket->Data[1] & flags_req_more_frag) {
        if (m_packet_req.m_data.empty()) {
            // Start a new packet.
            if (pReceivedPacket->Data[1] & flags_req_length_incl) {
                // Preallocate data according to the Length field.
                size_t size_tot  = ntohl(*(unsigned int*)(pReceivedPacket->Data + 2));
                m_packet_req.m_data.reserve(size_tot);
                m_module.log_event(&EAPMETHOD_TLS_PACKET_RECV_FRAG_FIRST, event_data((unsigned int)eap_type_tls), event_data((unsigned int)packet_data_size), event_data((unsigned int)size_tot), event_data::blank);
            } else {
                // The Length field was not included. Odd. Nevermind, no pre-allocation then.
                m_module.log_event(&EAPMETHOD_TLS_PACKET_RECV_FRAG_FIRST1, event_data((unsigned int)eap_type_tls), event_data((unsigned int)packet_data_size), event_data::blank);
            }
        } else {
            // Mid fragment received.
            m_module.log_event(&EAPMETHOD_TLS_PACKET_RECV_FRAG_MID, event_data((unsigned int)eap_type_tls), event_data((unsigned int)packet_data_size), event_data((unsigned int)m_packet_req.m_data.size()), event_data::blank);
        }
        m_packet_req.m_data.insert(m_packet_req.m_data.end(), packet_data_ptr, packet_data_ptr + packet_data_size);

        // Reply with ACK packet.
        m_packet_res.m_code  = EapCodeResponse;
        m_packet_res.m_id    = pReceivedPacket->Id;
        m_packet_res.m_flags = 0;
        m_packet_res.m_data.clear();
        pEapOutput->fAllowNotifications = FALSE;
        pEapOutput->action = EapPeerMethodResponseActionSend;
        return;
    } else if (!m_packet_req.m_data.empty()) {
        // Last fragment received. Append data.
        m_packet_req.m_data.insert(m_packet_req.m_data.end(), packet_data_ptr, packet_data_ptr + packet_data_size);
        m_module.log_event(&EAPMETHOD_TLS_PACKET_RECV_FRAG_LAST, event_data((unsigned int)eap_type_tls), event_data((unsigned int)packet_data_size), event_data((unsigned int)m_packet_req.m_data.size()), event_data::blank);
    } else {
        // This is a complete non-fragmented packet.
        m_packet_req.m_data.assign(packet_data_ptr, packet_data_ptr + packet_data_size);
        m_module.log_event(&EAPMETHOD_TLS_PACKET_RECV, event_data((unsigned int)eap_type_tls), event_data((unsigned int)packet_data_size), event_data::blank);
    }

    m_packet_req.m_code  = (EapCode)pReceivedPacket->Code;
    m_packet_req.m_id    = pReceivedPacket->Id;
    m_packet_req.m_flags = pReceivedPacket->Data[1];

    if (m_packet_res.m_flags & flags_res_more_frag) {
        // We are sending a fragmented message.
        if (  m_packet_req.m_code == EapCodeRequest    &&
              m_packet_req.m_id   == m_packet_res.m_id &&
              m_packet_req.m_data.empty()              &&
            !(m_packet_req.m_flags & (flags_req_length_incl | flags_req_more_frag | flags_req_start)))
        {
            // This is the ACK of our fragmented message packet. Send the next fragment.
            m_packet_res.m_id++;
            pEapOutput->fAllowNotifications = FALSE;
            pEapOutput->action = EapPeerMethodResponseActionSend;
            return;
        } else
            throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, string_printf(__FUNCTION__ " ACK expected, received %u-%u-%x.", m_packet_req.m_code, m_packet_req.m_id, m_packet_req.m_flags));
    }

    m_packet_res.m_code  = EapCodeResponse;
    m_packet_res.m_id    = m_packet_req.m_id;
    m_packet_res.m_flags = 0;

    if (pReceivedPacket->Code == EapCodeRequest && (m_packet_req.m_flags & flags_req_start)) {
        // This is the EAP-TLS start message: (re)initialize method.
        m_phase = phase_handshake_init;
        m_sc_queue.assign(m_packet_req.m_data.begin(), m_packet_req.m_data.end());
    } else
        m_sc_queue.insert(m_sc_queue.end(), m_packet_req.m_data.begin(), m_packet_req.m_data.end());

    switch (m_phase) {
    case phase_handshake_init:
    case phase_handshake_cont:
        process_handshake();
        break;

    case phase_application_data:
        process_application_data();
        break;
    }

    pEapOutput->fAllowNotifications = TRUE;
    pEapOutput->action = EapPeerMethodResponseActionSend;

    // EAP-Request packet was processed. Clear its data since we use the absence of data to detect first of fragmented message packages.
    m_packet_req.m_data.clear();
}


void eap::method_tls::get_response_packet(
    _Inout_bytecap_(*dwSendPacketSize) EapPacket *pSendPacket,
    _Inout_                            DWORD     *pdwSendPacketSize)
{
    assert(pdwSendPacketSize);
    assert(pSendPacket);

    unsigned int
        size_data   = (unsigned int)m_packet_res.m_data.size(),
        size_packet = size_data + 6;
    unsigned short size_packet_limit = (unsigned short)std::min<unsigned int>(*pdwSendPacketSize, USHRT_MAX);
    unsigned char *data_dst;

    if (!(m_packet_res.m_flags & flags_res_more_frag)) {
        // Not fragmented.
        if (size_packet <= size_packet_limit) {
            // No need to fragment the packet.
            m_packet_res.m_flags &= ~flags_res_length_incl; // No need to explicitly include the Length field either.
            data_dst = pSendPacket->Data + 2;
            m_module.log_event(&EAPMETHOD_TLS_PACKET_SEND, event_data((unsigned int)eap_type_tls), event_data((unsigned int)size_data), event_data::blank);
        } else {
            // But it should be fragmented.
            m_packet_res.m_flags |= flags_res_length_incl | flags_res_more_frag;
            *(unsigned int*)(pSendPacket->Data + 2) = (unsigned int)size_packet;
            data_dst = pSendPacket->Data + 6;
            size_data   = size_packet_limit - 10;
            size_packet = size_packet_limit;
            m_module.log_event(&EAPMETHOD_TLS_PACKET_SEND_FRAG_FIRST, event_data((unsigned int)eap_type_tls), event_data((unsigned int)size_data), event_data((unsigned int)(m_packet_res.m_data.size() - size_data)), event_data::blank);
        }
    } else {
        // Continuing the fragmented packet...
        if (size_packet > size_packet_limit) {
            // This is a mid fragment.
            m_packet_res.m_flags &= ~flags_res_length_incl;
            size_data   = size_packet_limit - 6;
            size_packet = size_packet_limit;
            m_module.log_event(&EAPMETHOD_TLS_PACKET_SEND_FRAG_MID, event_data((unsigned int)eap_type_tls), event_data((unsigned int)size_data), event_data((unsigned int)(m_packet_res.m_data.size() - size_data)), event_data::blank);
        } else {
            // This is the last fragment.
            m_packet_res.m_flags &= ~(flags_res_length_incl | flags_res_more_frag);
            m_module.log_event(&EAPMETHOD_TLS_PACKET_SEND_FRAG_LAST, event_data((unsigned int)eap_type_tls), event_data((unsigned int)size_data), event_data((unsigned int)(m_packet_res.m_data.size() - size_data)), event_data::blank);
        }
        data_dst = pSendPacket->Data + 2;
    }

    pSendPacket->Code = (BYTE)m_packet_res.m_code;
    pSendPacket->Id   = m_packet_res.m_id;
    *(unsigned short*)pSendPacket->Length = htons((unsigned short)size_packet);
    pSendPacket->Data[0] = (BYTE)eap_type_tls;
    pSendPacket->Data[1] = m_packet_res.m_flags;
    memcpy(data_dst, m_packet_res.m_data.data(), size_data);
    m_packet_res.m_data.erase(m_packet_res.m_data.begin(), m_packet_res.m_data.begin() + size_data);
    *pdwSendPacketSize = size_packet;
}


void eap::method_tls::get_result(
    _In_    EapPeerMethodResultReason reason,
    _Inout_ EapPeerMethodResult       *ppResult)
{
    assert(ppResult);

    config_provider &cfg_prov(m_cfg.m_providers.front());
    config_method_tls *cfg_method = dynamic_cast<config_method_tls*>(cfg_prov.m_methods.front().get());
    assert(cfg_method);

    switch (reason) {
    case EapPeerMethodResultSuccess: {
        m_module.log_event(&EAPMETHOD_TLS_SUCCESS, event_data((unsigned int)eap_type_tls), event_data::blank);

        // Derive MSK/EMSK for line encryption.
        SecPkgContext_EapKeyBlock key_block;
        SECURITY_STATUS status = QueryContextAttributes(m_sc_ctx, SECPKG_ATTR_EAP_KEY_BLOCK, &key_block);
        if (FAILED(status))
            throw sec_runtime_error(status, __FUNCTION__ "Error generating MSK in Schannel.");
        const unsigned char *_key_block = key_block.rgbKeys;

        // Fill array with RADIUS attributes.
        eap_attr a;
        m_eap_attr.clear();
        m_eap_attr.reserve(3);
        a.create_ms_mppe_key(16, _key_block, sizeof(tls_random));
        m_eap_attr.push_back(std::move(a));
        _key_block += sizeof(tls_random);
        a.create_ms_mppe_key(17, _key_block, sizeof(tls_random));
        m_eap_attr.push_back(std::move(a));
        _key_block += sizeof(tls_random);
        m_eap_attr.push_back(eap_attr::blank);

        m_eap_attr_desc.dwNumberOfAttributes = (DWORD)m_eap_attr.size();
        m_eap_attr_desc.pAttribs = m_eap_attr.data();
        ppResult->pAttribArray = &m_eap_attr_desc;

        // Clear credentials as failed.
        cfg_method->m_auth_failed = false;

        ppResult->fIsSuccess = TRUE;
        ppResult->dwFailureReasonCode = ERROR_SUCCESS;

        break;
    }

    case EapPeerMethodResultFailure:
        m_module.log_event(&EAPMETHOD_TLS_FAILURE, event_data((unsigned int)eap_type_tls), event_data::blank);

        // Mark credentials as failed, so GUI can re-prompt user.
        cfg_method->m_auth_failed = true;

        // Do not report failure to EAPHost, as it will not save updated configuration then. But we need it to save it, to alert user on next connection attempt.
        // EAPHost is well aware of the failed condition.
        //ppResult->fIsSuccess = FALSE;
        //ppResult->dwFailureReasonCode = EAP_E_AUTHENTICATION_FAILED;

        break;

    default:
        throw win_runtime_error(ERROR_NOT_SUPPORTED, __FUNCTION__ " Not supported.");
    }

    // Always ask EAP host to save the connection data.
    ppResult->fSaveConnectionData = TRUE;
    m_module.pack(m_cfg, &ppResult->pConnectionData, &ppResult->dwSizeofConnectionData);
    if (m_blob_cfg)
        m_module.free_memory(m_blob_cfg);
    m_blob_cfg = ppResult->pConnectionData;

#ifdef EAP_USE_NATIVE_CREDENTIAL_CACHE
    ppResult->fSaveUserData = TRUE;
    m_module.pack(m_cred, &ppResult->pUserData, &ppResult->dwSizeofUserData);
    if (m_blob_cred)
        m_module.free_memory(m_blob_cred);
    m_blob_cred = ppResult->pUserData;
#endif
}


void eap::method_tls::process_handshake()
{
    // Prepare input buffer(s).
    SecBuffer buf_in[] = {
        {
            (unsigned long)m_sc_queue.size(),
            SECBUFFER_TOKEN,
            m_sc_queue.data()
        },
        { 0, SECBUFFER_EMPTY, NULL },
    };
    SecBufferDesc buf_in_desc = {
        SECBUFFER_VERSION,
        _countof(buf_in),
        buf_in
    };

    // Prepare output buffer(s).
    SecBuffer buf_out[] = {
        { 0, SECBUFFER_TOKEN, NULL },
        { 0, SECBUFFER_ALERT, NULL },
    };
    sec_buffer_desc buf_out_desc(buf_out, _countof(buf_out));

    user_impersonator impersonating(m_user_ctx);
    SECURITY_STATUS status;
    if (m_phase == phase_handshake_init) {
        m_module.log_event(&EAPMETHOD_TLS_HANDSHAKE_START2, event_data((unsigned int)eap_type_tls), event_data::blank);
        status = m_sc_ctx.initialize(
            m_sc_cred,
            !m_sc_target_name.empty() ? m_sc_target_name.c_str() : NULL,
            ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_INTEGRITY | ISC_REQ_STREAM | /*ISC_REQ_USE_SUPPLIED_CREDS |*/ ISC_REQ_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY,
            0,
            &buf_in_desc,
            &buf_out_desc);
    } else {
        status = m_sc_ctx.process(
            m_sc_cred,
            !m_sc_target_name.empty() ? m_sc_target_name.c_str() : NULL,
            ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_INTEGRITY | ISC_REQ_STREAM | /*ISC_REQ_USE_SUPPLIED_CREDS |*/ ISC_REQ_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY,
            0,
            &buf_in_desc,
            &buf_out_desc);
    }

#ifndef SCHANNEL_SRV_CERT_CHECK
    if (status == SEC_E_OK)
        verify_server_trust();
#endif

    if (status == SEC_E_OK || status == SEC_I_CONTINUE_NEEDED) {
        // Send Schannel's token via EAP.
        assert(buf_out[0].BufferType == SECBUFFER_TOKEN);
        assert(m_sc_ctx.m_attrib & ISC_RET_ALLOCATED_MEMORY);
        m_packet_res.m_data.assign((const unsigned char*)buf_out[0].pvBuffer, (const unsigned char*)buf_out[0].pvBuffer + buf_out[0].cbBuffer);
        if (buf_in[1].BufferType == SECBUFFER_EXTRA) {
            // Server appended extra data. Process it.
            process_application_data(&*(m_sc_queue.end() - buf_in[1].cbBuffer), buf_in[1].cbBuffer);
        }
        m_sc_queue.clear();

        m_phase = status == SEC_E_OK ? phase_application_data : phase_handshake_cont;
    } else if (status == SEC_E_INCOMPLETE_MESSAGE) {
        // Schannel neeeds more data. Send ACK packet to server to send more.
    } else if (FAILED(status)) {
        if (m_sc_ctx.m_attrib & ISC_RET_EXTENDED_ERROR) {
            // Send alert via EAP. Not that EAP will transmit it once we throw this is an error...
            assert(buf_out[1].BufferType == SECBUFFER_ALERT);
            assert(m_sc_ctx.m_attrib & ISC_RET_ALLOCATED_MEMORY);
            m_packet_res.m_data.assign((const unsigned char*)buf_out[1].pvBuffer, (const unsigned char*)buf_out[1].pvBuffer + buf_out[1].cbBuffer);
        }

        throw sec_runtime_error(status, __FUNCTION__ " Schannel error.");
    }
}


void eap::method_tls::process_application_data()
{
    if (m_sc_queue.empty()) {
        // An ACK packet received. Nothing to unencrypt.
        process_application_data(NULL, 0);
        return;
    }

    if (!(m_sc_ctx.m_attrib & ISC_RET_CONFIDENTIALITY))
        throw runtime_error(__FUNCTION__ " Connection is not encrypted.");

    // Prepare input/output buffer(s).
    SecBuffer buf[] = {
        { 0, SECBUFFER_TOKEN, NULL },
        { 0, SECBUFFER_ALERT, NULL },
        {
            (unsigned long)m_sc_queue.size(),
            SECBUFFER_DATA,
            m_sc_queue.data()
        },
    };
    SecBufferDesc buf_desc = {
        SECBUFFER_VERSION,
        _countof(buf),
        buf
    };

    // Decrypt the message.
    SECURITY_STATUS status = DecryptMessage(m_sc_ctx, &buf_desc, 0, NULL);
    if (status == SEC_E_OK) {
        assert(buf[2].BufferType == SECBUFFER_DATA);
        process_application_data(buf[2].pvBuffer, buf[2].cbBuffer);
    } else if (status == SEC_E_INCOMPLETE_MESSAGE) {
        // Schannel neeeds more data. Send ACK packet to server to send more.
    } else if (status == SEC_I_CONTEXT_EXPIRED) {
        // Server initiated connection shutdown.
        m_sc_queue.clear();
        m_phase = phase_shutdown;
    } else if (status == SEC_I_RENEGOTIATE) {
        // Re-negotiation required.
        m_sc_queue.clear();
        m_phase = phase_handshake_init;
        process_handshake();
    } else if (FAILED(status)) {
        if (m_sc_ctx.m_attrib & ISC_RET_EXTENDED_ERROR) {
            // Send alert via EAP. Not that EAP will transmit it once we throw this is an error...
            assert(buf[1].BufferType == SECBUFFER_ALERT);
            assert(m_sc_ctx.m_attrib & ISC_RET_ALLOCATED_MEMORY);
            m_packet_res.m_data.assign((const unsigned char*)buf[1].pvBuffer, (const unsigned char*)buf[1].pvBuffer + buf[1].cbBuffer);
        }

        throw sec_runtime_error(status, __FUNCTION__ " Schannel error.");
    }
}


void eap::method_tls::process_application_data(_In_bytecount_(size_msg) const void *msg, _In_ size_t size_msg)
{
    UNREFERENCED_PARAMETER(msg);
    UNREFERENCED_PARAMETER(size_msg);

    // TODO: Parse application data (Diameter AVP)
}


#ifndef SCHANNEL_SRV_CERT_CHECK

void eap::method_tls::verify_server_trust() const
{
    SECURITY_STATUS status;

    cert_context cert;
    status = QueryContextAttributes(m_sc_ctx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, (PVOID)&cert);
    if (FAILED(status))
        throw sec_runtime_error(status, __FUNCTION__ " Error retrieving server certificate from Schannel.");

    const config_provider &cfg_prov(m_cfg.m_providers.front());
    const config_method_tls *cfg_method = dynamic_cast<const config_method_tls*>(cfg_prov.m_methods.front().get());
    assert(cfg_method);

    // Check server name.
    if (!cfg_method->m_server_names.empty()) {
        bool found = false;

        // Search subjectAltName2 and subjectAltName.
        for (DWORD i = 0; !found && i < cert->pCertInfo->cExtension; i++) {
            unique_ptr<CERT_ALT_NAME_INFO, LocalFree_delete<CERT_ALT_NAME_INFO> > san_info;
            if (strcmp(cert->pCertInfo->rgExtension[i].pszObjId, szOID_SUBJECT_ALT_NAME2) == 0) {
                unsigned char *output = NULL;
                DWORD size_output;
                if (!CryptDecodeObjectEx(
                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                        szOID_SUBJECT_ALT_NAME2,
                        cert->pCertInfo->rgExtension[i].Value.pbData, cert->pCertInfo->rgExtension[i].Value.cbData,
                        CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_ENABLE_PUNYCODE_FLAG,
                        NULL,
                        &output, &size_output))
                    throw win_runtime_error(__FUNCTION__ " Error decoding certificate extension.");
                san_info.reset((CERT_ALT_NAME_INFO*)output);
            } else if (strcmp(cert->pCertInfo->rgExtension[i].pszObjId, szOID_SUBJECT_ALT_NAME) == 0) {
                unsigned char *output = NULL;
                DWORD size_output;
                if (!CryptDecodeObjectEx(
                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                        szOID_SUBJECT_ALT_NAME,
                        cert->pCertInfo->rgExtension[i].Value.pbData, cert->pCertInfo->rgExtension[i].Value.cbData,
                        CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_ENABLE_PUNYCODE_FLAG,
                        NULL,
                        &output, &size_output))
                    throw win_runtime_error(__FUNCTION__ " Error decoding certificate extension.");
                san_info.reset((CERT_ALT_NAME_INFO*)output);
            } else {
                // Skip this extension.
                continue;
            }

            for (list<wstring>::const_iterator s = cfg_method->m_server_names.cbegin(), s_end = cfg_method->m_server_names.cend(); !found && s != s_end; ++s) {
                for (DWORD i = 0; !found && i < san_info->cAltEntry; i++) {
                    if (san_info->rgAltEntry[i].dwAltNameChoice == CERT_ALT_NAME_DNS_NAME &&
                        _wcsicmp(s->c_str(), san_info->rgAltEntry[i].pwszDNSName) == 0)
                    {
                        m_module.log_event(&EAPMETHOD_TLS_SERVER_NAME_TRUSTED1, event_data(san_info->rgAltEntry[i].pwszDNSName), event_data::blank);
                        found = true;
                        break;
                    }
                }
            }
        }

        if (!found)
            throw win_runtime_error(ERROR_INVALID_DOMAINNAME, __FUNCTION__ " Server name is not on the list of trusted server names.");
    }

    if (cert->pCertInfo->Issuer.cbData == cert->pCertInfo->Subject.cbData &&
        memcmp(cert->pCertInfo->Issuer.pbData, cert->pCertInfo->Subject.pbData, cert->pCertInfo->Issuer.cbData) == 0)
        throw com_runtime_error(CRYPT_E_SELF_SIGNED, __FUNCTION__ " Server is using a self-signed certificate. Cannot trust it.");

    // Create temporary certificate store of our trusted root CAs.
    cert_store store;
    if (!store.create(CERT_STORE_PROV_MEMORY, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, NULL, 0, NULL))
        throw win_runtime_error(ERROR_INVALID_DOMAINNAME, __FUNCTION__ " Error creating temporary certificate store.");
    for (list<cert_context>::const_iterator c = cfg_method->m_trusted_root_ca.cbegin(), c_end = cfg_method->m_trusted_root_ca.cend(); c != c_end; ++c)
        CertAddCertificateContextToStore(store, *c, CERT_STORE_ADD_REPLACE_EXISTING, NULL);

    // Add all intermediate certificates from the server's certificate chain.
    for (cert_context c(cert); c;) {
        DWORD flags = 0;
        c.attach(CertGetIssuerCertificateFromStore(cert->hCertStore, c, NULL, &flags));
        if (!c) break;

        if (c->pCertInfo->Issuer.cbData == c->pCertInfo->Subject.cbData &&
            memcmp(c->pCertInfo->Issuer.pbData, c->pCertInfo->Subject.pbData, c->pCertInfo->Issuer.cbData) == 0)
        {
            // Skip the root CA certificates (self-signed). We define in whom we trust!
            continue;
        }

        CertAddCertificateContextToStore(store, c, CERT_STORE_ADD_REPLACE_EXISTING, NULL);
    }

    // Prepare the certificate chain validation, and check.
    CERT_CHAIN_PARA chain_params = {
        sizeof(chain_params),      // cbSize
        {
            USAGE_MATCH_TYPE_AND,  // RequestedUsage.dwType
            {},                    // RequestedUsage.Usage
        },
#ifdef CERT_CHAIN_PARA_HAS_EXTRA_FIELDS
        {},                        // RequestedIssuancePolicy
        1,                         // dwUrlRetrievalTimeout (1ms to speed up checking)
#else
#define _S2(x) #x
#define _S(x) _S2(x)
#pragma message(__FILE__ "(" _S(__LINE__) "): warning X0000: Please define CERT_CHAIN_PARA_HAS_EXTRA_FIELDS constant when compiling this project.")
#endif
    };
    cert_chain_context context;
    if (!context.create(NULL, cert, NULL, store, &chain_params, 0))
        throw win_runtime_error(__FUNCTION__ " Error creating certificate chain context.");

    // Check chain validation error flags. Ignore CERT_TRUST_IS_UNTRUSTED_ROOT flag since we check root CA explicitly.
    if (context->TrustStatus.dwErrorStatus != CERT_TRUST_NO_ERROR &&
        (cfg_method->m_trusted_root_ca.empty() || (context->TrustStatus.dwErrorStatus & ~CERT_TRUST_IS_UNTRUSTED_ROOT) != CERT_TRUST_NO_ERROR))
        throw win_runtime_error(context->TrustStatus.dwErrorStatus, "Error validating certificate chain.");

    if (!cfg_method->m_trusted_root_ca.empty()) {
        // Verify Root CA against our trusted root CA list
        if (context->cChain != 1)
            throw win_runtime_error(ERROR_NOT_SUPPORTED, __FUNCTION__ " Multiple chain verification not supported.");
        if (context->rgpChain[0]->cElement == 0)
            throw win_runtime_error(ERROR_NOT_SUPPORTED, __FUNCTION__ " Can not verify empty certificate chain.");

        PCCERT_CONTEXT cert_root = context->rgpChain[0]->rgpElement[context->rgpChain[0]->cElement-1]->pCertContext;
        for (list<cert_context>::const_iterator c = cfg_method->m_trusted_root_ca.cbegin(), c_end = cfg_method->m_trusted_root_ca.cend();; ++c) {
            if (c != c_end) {
                if (cert_root->cbCertEncoded == (*c)->cbCertEncoded &&
                    memcmp(cert_root->pbCertEncoded, (*c)->pbCertEncoded, cert_root->cbCertEncoded) == 0)
                {
                    // Trusted root CA found.
                    break;
                }
            } else {
                // Not found.
                throw win_runtime_error(ERROR_FILE_NOT_FOUND, __FUNCTION__ " Server's certificate not issued by one of configured trusted root CAs.");
            }
        }
    }

    m_module.log_event(&EAPMETHOD_TLS_SERVER_CERT_TRUSTED, event_data::blank);
}

#endif
