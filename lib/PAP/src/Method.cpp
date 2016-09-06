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
// eap::method_pap
//////////////////////////////////////////////////////////////////////

eap::method_pap::method_pap(_In_ module &module, _In_ config_method_pap &cfg, _In_ credentials_pap &cred) :
    m_cred(cred),
    m_phase(phase_unknown),
    method_noneap(module, cfg, cred)
{
}


eap::method_pap::method_pap(_Inout_ method_pap &&other) :
    m_cred       (          other.m_cred       ),
    m_phase      (std::move(other.m_phase     )),
    method_noneap(std::move(other             ))
{
}


eap::method_pap& eap::method_pap::operator=(_Inout_ method_pap &&other)
{
    if (this != std::addressof(other)) {
        assert(std::addressof(m_cred) == std::addressof(other.m_cred)); // Move method with same credentials only!
        (method_noneap&)*this = std::move(other             );
        m_phase               = std::move(other.m_phase     );
    }

    return *this;
}


void eap::method_pap::begin_session(
    _In_        DWORD         dwFlags,
    _In_  const EapAttributes *pAttributeArray,
    _In_        HANDLE        hTokenImpersonateUser,
    _In_opt_    DWORD         dwMaxSendPacketSize)
{
    method_noneap::begin_session(dwFlags, pAttributeArray, hTokenImpersonateUser, dwMaxSendPacketSize);

    m_module.log_event(&EAPMETHOD_METHOD_HANDSHAKE_START2, event_data((unsigned int)eap_type_legacy_pap), event_data::blank);
    m_phase = phase_init;
}


void eap::method_pap::process_request_packet(
    _In_bytecount_(dwReceivedPacketSize) const void                *pReceivedPacket,
    _In_                                       DWORD               dwReceivedPacketSize,
    _Inout_                                    EapPeerMethodOutput *pEapOutput)
{
    assert(pReceivedPacket || dwReceivedPacketSize == 0);
    assert(pEapOutput);

    m_module.log_event(&EAPMETHOD_PACKET_RECV, event_data((unsigned int)eap_type_legacy_pap), event_data((unsigned int)dwReceivedPacketSize), event_data::blank);

    switch (m_phase) {
    case phase_init: {
        // Convert username and password to UTF-8.
        sanitizing_string identity_utf8, password_utf8;
        WideCharToMultiByte(CP_UTF8, 0, m_cred.m_identity.c_str(), (int)m_cred.m_identity.length(), identity_utf8, NULL, NULL);
        WideCharToMultiByte(CP_UTF8, 0, m_cred.m_password.c_str(), (int)m_cred.m_password.length(), password_utf8, NULL, NULL);

        // PAP passwords must be padded to 16B boundary according to RFC 5281. Will not add random extra padding here, as length obfuscation should be done by outer transport layers.
        size_t padding_password_ex = (16 - password_utf8.length()) % 16;
        password_utf8.append(padding_password_ex, 0);

        m_packet_res.clear();

        // Diameter AVP (User-Name=1, User-Password=2)
        append_avp(1, diameter_avp_flag_mandatory, identity_utf8.data(), (unsigned int)identity_utf8.size());
        append_avp(2, diameter_avp_flag_mandatory, password_utf8.data(), (unsigned int)password_utf8.size());

        m_phase = phase_finished;
        m_cfg.m_last_status = config_method_with_cred::status_cred_invalid; // Blame credentials if we fail beyond this point.
        break;
    }

    case phase_finished:
        break;
    }

    pEapOutput->fAllowNotifications = TRUE;
    pEapOutput->action = EapPeerMethodResponseActionSend;
}
