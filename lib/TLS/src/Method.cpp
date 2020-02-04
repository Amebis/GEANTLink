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
// eap::method_defrag
//////////////////////////////////////////////////////////////////////

eap::method_defrag::method_defrag(_In_ module &mod, _In_ unsigned char version_max, _In_ method *inner) :
    m_version(version_max),
    m_phase(phase_t::unknown),
    m_send_res(false),
    method(mod, inner)
{
}


void eap::method_defrag::begin_session(
    _In_        DWORD         dwFlags,
    _In_  const EapAttributes *pAttributeArray,
    _In_        HANDLE        hTokenImpersonateUser,
    _In_opt_    DWORD         dwMaxSendPacketSize)
{
    // Inner method may generate packets of up to 4GB.
    // But, we can not do the fragmentation if we have less space than flags+length.
    if (dwMaxSendPacketSize < 5)
        throw invalid_argument(string_printf(__FUNCTION__ " Maximum packet size too small (minimum: %u, available: %u).", 5, dwMaxSendPacketSize));
    method::begin_session(dwFlags, pAttributeArray, hTokenImpersonateUser, MAXDWORD);

    m_phase = phase_t::init;
}


EapPeerMethodResponseAction eap::method_defrag::process_request_packet(
    _In_bytecount_(dwReceivedPacketSize) const void  *pReceivedPacket,
    _In_                                       DWORD dwReceivedPacketSize)
{
    auto data_packet = reinterpret_cast<const unsigned char*>(pReceivedPacket);

    if (dwReceivedPacketSize < 1)
        throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Incomplete packet flags.");

    // To prevent version downgrade attacks, negotiate protocol version on binding exchange only. Then stick to it!
    unsigned char data_version = data_packet[0] & flags_ver_mask;
    if (m_phase == phase_t::init) {
        m_version = min<unsigned char>(data_version, m_version);
        m_module.log_event(&EAPMETHOD_DEFRAG_VERSION,
            event_data(m_version),
            event_data(data_version),
            event_data::blank);
        m_phase = phase_t::established;
    } else if (data_version != m_version)
        throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Protocol version mismatch.");

    // Get packet content pointers for more readable code later on.
    auto
        data_content     = data_packet + (data_packet[0] & flags_length_incl ? 5 : 1),
        data_content_end = data_packet + dwReceivedPacketSize;
    if (data_content > data_content_end)
        throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Incomplete data.");

    // Do the defragmentation.
    if (data_packet[0] & flags_more_frag) {
        if (m_data_req.empty()) {
            // Start a new packet.
            if (data_packet[0] & flags_length_incl) {
                // Preallocate data according to the Length field.
                m_data_req.reserve(ntohl(*reinterpret_cast<const unsigned int*>(data_packet + 1)));
            }
        }
        m_data_req.insert(m_data_req.end(), data_content, data_content_end);

        // Respond with ACK packet (empty packet).
        m_data_res.clear();
        m_send_res = true;
        return EapPeerMethodResponseActionSend;
    } else if (!m_data_req.empty()) {
        // Last fragment received. Append data.
        m_data_req.insert(m_data_req.end(), data_content, data_content_end);
    } else {
        // This is a complete non-fragmented packet.
        m_data_req.assign(data_content, data_content_end);
    }

    if (m_send_res) {
        // We are sending a fragmented message.
        if (m_data_req.empty() && (data_packet[0] & (flags_length_incl | flags_more_frag | flags_start)) == 0) {
            // Received packet is the ACK of our fragmented message packet. Send the next fragment.
            return EapPeerMethodResponseActionSend;
        } else
            throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " ACK expected.");
    }

    // Process the data with underlying method.
    auto action = method::process_request_packet(m_data_req.data(), (DWORD)m_data_req.size());

    // Packet was processed. Clear its data since we use the absence of data to detect first of fragmented message packages.
    m_data_req.clear();
    return action;
}


void eap::method_defrag::get_response_packet(
    _Out_    sanitizing_blob &packet,
    _In_opt_ DWORD           size_max)
{
    assert(size_max >= 5); // We can not do the fragmentation if we have less space than flags+length.

    if (!m_send_res) {
        // Get data from underlying method.
        method::get_response_packet(m_data_res, MAXDWORD);
    }

    size_t size_data = m_data_res.size();
    assert(size_data <= MAXDWORD); // Packets spanning over 4GB are not supported.

    packet.clear();
    if (size_data + 1 > size_max) {
        // Write one fragment.
        packet.push_back(flags_length_incl | flags_more_frag | m_version);
        unsigned int length = htonl((unsigned int)size_data);
        packet.insert(packet.end(), reinterpret_cast<const unsigned char*>(&length), reinterpret_cast<const unsigned char*>(&length + 1));
        auto data_begin = m_data_res.begin() + 0, data_end = data_begin + (size_max - 5);
        packet.insert(packet.end(), data_begin, data_end);
        m_data_res.erase(data_begin, data_end);
        m_send_res = true;
    } else {
        // Write single/last fragment.
        packet.push_back(m_version);
        packet.insert(packet.end(), m_data_res.begin(), m_data_res.end());
        m_data_res.clear();
        m_send_res = false;
    }
}
