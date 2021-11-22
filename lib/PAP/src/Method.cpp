/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2020 Amebis
    Copyright © 2016 GÉANT
*/

#include "PCH.h"

using namespace std;
using namespace winstd;


//////////////////////////////////////////////////////////////////////
// eap::method_pap_diameter
//////////////////////////////////////////////////////////////////////

eap::method_pap_diameter::method_pap_diameter(_In_ module &mod, _In_ config_method_pap &cfg, _In_ credentials_pass &cred) :
    m_cfg(cfg),
    m_cred(cred),
    m_phase(phase_t::unknown),
    method(mod)
{
}


void eap::method_pap_diameter::begin_session(
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

    m_phase = phase_t::init;
}


EapPeerMethodResponseAction eap::method_pap_diameter::process_request_packet(
    _In_bytecount_(dwReceivedPacketSize) const void  *pReceivedPacket,
    _In_                                       DWORD dwReceivedPacketSize)
{
    UNREFERENCED_PARAMETER(pReceivedPacket);
    UNREFERENCED_PARAMETER(dwReceivedPacketSize);

    switch (m_phase) {
    case phase_t::init: {
        m_module.log_event(&EAPMETHOD_METHOD_HANDSHAKE_START2, event_data((unsigned int)eap_type_t::legacy_pap), event_data::blank);

        // Convert username and password to UTF-8.
        sanitizing_string identity_utf8, password_utf8;
        WideCharToMultiByte(CP_UTF8, 0, m_cred.m_identity, identity_utf8, NULL, NULL);
        WideCharToMultiByte(CP_UTF8, 0, m_cred.m_password, password_utf8, NULL, NULL);

        // PAP passwords must be padded to 16B boundary according to RFC 5281. Will not add random extra padding here, as length obfuscation should be done by outer transport layers.
        size_t padding_password_ex = (16 - password_utf8.length()) % 16;
        password_utf8.append(padding_password_ex, 0);

        // Diameter AVP (User-Name=1, User-Password=2)
        m_packet_res.clear();
        diameter_avp_append(1, diameter_avp_flag_mandatory, identity_utf8.data(), (unsigned int)identity_utf8.size(), m_packet_res);
        diameter_avp_append(2, diameter_avp_flag_mandatory, password_utf8.data(), (unsigned int)password_utf8.size(), m_packet_res);

        m_phase = phase_t::finished;
        m_cfg.m_last_status = config_method::status_t::cred_invalid; // Blame credentials if we fail beyond this point.
        return EapPeerMethodResponseActionSend;
    }

    case phase_t::finished:
        return EapPeerMethodResponseActionNone;

    default:
        throw invalid_argument(string_printf(__FUNCTION__ " Unknown phase (phase %u).", m_phase));
    }
}


void eap::method_pap_diameter::get_response_packet(
    _Out_    sanitizing_blob &packet,
    _In_opt_ DWORD           size_max)
{
    if (m_packet_res.size() > size_max)
        throw invalid_argument(string_printf(__FUNCTION__ " This method does not support packet fragmentation, but the data size is too big to fit in one packet (packet: %zu, maximum: %u).", m_packet_res.size(), size_max));

    packet.assign(m_packet_res.begin(), m_packet_res.end());
}


void eap::method_pap_diameter::get_result(
    _In_    EapPeerMethodResultReason reason,
    _Inout_ EapPeerMethodResult       *pResult)
{
    assert(pResult);

    method::get_result(reason, pResult);

    if (reason == EapPeerMethodResultSuccess)
        m_cfg.m_last_status = config_method::status_t::success;

    // Ask EAP host to save the configuration (connection data).
    pResult->fSaveConnectionData = TRUE;
}
