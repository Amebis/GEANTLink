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
// eap::method_eaphost
//////////////////////////////////////////////////////////////////////

eap::method_eaphost::method_eaphost(_In_ module &module, _In_ config_method_eaphost &cfg, _In_ credentials_eaphost &cred) :
    m_session_id(0),
    method_noneap(module, cfg, cred)
{
}


eap::method_eaphost::method_eaphost(_Inout_ method_eaphost &&other) :
    m_session_id (std::move(other.m_session_id)),
    method_noneap(std::move(other             ))
{
}


eap::method_eaphost& eap::method_eaphost::operator=(_Inout_ method_eaphost &&other)
{
    if (this != std::addressof(other)) {
        (method_noneap&)*this = std::move(other             );
        m_session_id          = std::move(other.m_session_id);
    }

    return *this;
}


void eap::method_eaphost::begin_session(
    _In_        DWORD         dwFlags,
    _In_  const EapAttributes *pAttributeArray,
    _In_        HANDLE        hTokenImpersonateUser,
    _In_opt_    DWORD         dwMaxSendPacketSize)
{
    // Create EapHost peer session using available connection data (m_cfg) and user data (m_cred).
    auto &cfg  = dynamic_cast<config_method_eaphost&>(m_cfg);
    auto &cred = dynamic_cast<credentials_eaphost  &>(m_cred);
    eap_error_runtime error;
    DWORD dwResult = EapHostPeerBeginSession(
        dwFlags,
        cfg.get_type(),
        pAttributeArray,
        hTokenImpersonateUser,
        (DWORD)cfg.m_cfg_blob.size(),
        cfg.m_cfg_blob.data(),
        (DWORD)cred.m_cred_blob.size(),
        cred.m_cred_blob.data(),
        dwMaxSendPacketSize,
        NULL, NULL, NULL,
        &m_session_id,
        &error._Myptr);
    if (dwResult == ERROR_SUCCESS) {
        // Session succesfully created.
        method_noneap::begin_session(dwFlags, pAttributeArray, hTokenImpersonateUser, dwMaxSendPacketSize);

        m_module.log_event(&EAPMETHOD_METHOD_HANDSHAKE_START2, event_data((unsigned int)m_cfg.get_method_id()), event_data::blank);
    } else if (error)
        throw eap_runtime_error(*error  , __FUNCTION__ " EapHostPeerBeginSession failed.");
    else
        throw win_runtime_error(dwResult, __FUNCTION__ " EapHostPeerBeginSession failed.");
}


void eap::method_eaphost::end_session()
{
    // End EapHost peer session.
    eap_error_runtime error;
    DWORD dwResult = EapHostPeerEndSession(m_session_id, &error._Myptr);
    if (dwResult == ERROR_SUCCESS) {
        // Session successfuly ended.
    } else if (error)
        throw eap_runtime_error(*error  , __FUNCTION__ " EapHostPeerEndSession failed.");
    else
        throw win_runtime_error(dwResult, __FUNCTION__ " EapHostPeerEndSession failed.");
}


void eap::method_eaphost::process_request_packet(
    _In_bytecount_(dwReceivedPacketSize) const void                *pReceivedPacket,
    _In_                                       DWORD               dwReceivedPacketSize,
    _Out_                                      EapPeerMethodOutput *pEapOutput)
{
    assert(pReceivedPacket || dwReceivedPacketSize == 0);
    assert(pEapOutput);

    m_module.log_event(&EAPMETHOD_PACKET_RECV, event_data((unsigned int)m_cfg.get_method_id()), event_data((unsigned int)dwReceivedPacketSize), event_data::blank);

    // Let EapHost peer process the packet.
    EapHostPeerResponseAction action;
    eap_error_runtime error;
    DWORD dwResult = EapHostPeerProcessReceivedPacket(
        m_session_id,
        dwReceivedPacketSize,
        reinterpret_cast<const BYTE*>(pReceivedPacket),
        &action,
        &error._Myptr);
    if (dwResult == ERROR_SUCCESS) {
        // Packet successfuly processed.
        action_to_output(action, pEapOutput);
    } else if (error)
        throw eap_runtime_error(*error  , __FUNCTION__ " EapHostPeerProcessReceivedPacket failed.");
    else
        throw win_runtime_error(dwResult, __FUNCTION__ " EapHostPeerProcessReceivedPacket failed.");
}


void eap::method_eaphost::get_response_packet(
    _Inout_bytecap_(*dwSendPacketSize) void  *pSendPacket,
    _Inout_                            DWORD *pdwSendPacketSize)
{
    assert(pdwSendPacketSize);
    assert(pSendPacket || !*pdwSendPacketSize);

    // Let EapHost peer prepare response packet.
    DWORD size_max = *pdwSendPacketSize;
    eap_blob_runtime packet;
    eap_error_runtime error;
    DWORD dwResult = EapHostPeerGetSendPacket(
        m_session_id,
        pdwSendPacketSize,
        &packet._Myptr,
        &error._Myptr);
    if (dwResult == ERROR_SUCCESS) {
        // Packet successfuly prepared.
        memcpy_s(pSendPacket, size_max, packet.get(), *pdwSendPacketSize);
    } else if (error)
        throw eap_runtime_error(*error  , __FUNCTION__ " EapHostPeerGetSendPacket failed.");
    else
        throw win_runtime_error(dwResult, __FUNCTION__ " EapHostPeerGetSendPacket failed.");
}


void eap::method_eaphost::get_result(
    _In_    EapPeerMethodResultReason reason,
    _Inout_ EapPeerMethodResult       *pResult)
{
    assert(pResult);

    if (reason == EapPeerMethodResultSuccess) {
        // Let EapHost peer return result.
        eap_error_runtime error;
        EapHostPeerMethodResult result = {};
        DWORD dwResult = EapHostPeerGetResult(
            m_session_id,
            EapHostPeerMethodResultFromMethod,
            &result,
            &error._Myptr);
        if (dwResult == ERROR_SUCCESS) {
            // Result successfuly returned.
            pResult->fIsSuccess          = result.fIsSuccess;
            pResult->dwFailureReasonCode = result.dwFailureReasonCode;
            pResult->pAttribArray        = result.pAttribArray;
            pResult->pEapError           = result.pEapError;

            if (result.fSaveConnectionData)
                dynamic_cast<config_method_eaphost&>(m_cfg).m_cfg_blob.assign(result.pConnectionData, result.pConnectionData + result.dwSizeofConnectionData);

            if (result.fSaveUserData)
                dynamic_cast<credentials_eaphost  &>(m_cred).m_cred_blob.assign(result.pUserData, result.pUserData + result.dwSizeofUserData);
        } else if (error)
            throw eap_runtime_error(*error  , __FUNCTION__ " EapHostPeerGetResult failed.");
        else
            throw win_runtime_error(dwResult, __FUNCTION__ " EapHostPeerGetResult failed.");
    }
}


void eap::method_eaphost::get_ui_context(
    _Inout_ BYTE  **ppUIContextData,
    _Inout_ DWORD *pdwUIContextDataSize)
{
    // Get EapHost peer UI context data.
    eap_error_runtime error;
    DWORD dwResult = EapHostPeerGetUIContext(
        m_session_id,
        pdwUIContextDataSize,
        ppUIContextData,
        &error._Myptr);
    if (dwResult == ERROR_SUCCESS) {
        // UI context data successfuly returned.
    } else if (error)
        throw eap_runtime_error(*error  , __FUNCTION__ " EapHostPeerGetUIContext failed.");
    else
        throw win_runtime_error(dwResult, __FUNCTION__ " EapHostPeerGetUIContext failed.");
}


void eap::method_eaphost::set_ui_context(
    _In_count_(dwUIContextDataSize) const BYTE                *pUIContextData,
    _In_                                  DWORD               dwUIContextDataSize,
    _Out_                                 EapPeerMethodOutput *pEapOutput)
{
    assert(pEapOutput);

    // Set EapHost peer UI context data.
    EapHostPeerResponseAction action;
    eap_error_runtime error;
    DWORD dwResult = EapHostPeerSetUIContext(
        m_session_id,
        dwUIContextDataSize,
        pUIContextData,
        &action,
        &error._Myptr);
    if (dwResult == ERROR_SUCCESS) {
        // UI context data successfuly returned.
        action_to_output(action, pEapOutput);
    } else if (error)
        throw eap_runtime_error(*error  , __FUNCTION__ " EapHostPeerSetUIContext failed.");
    else
        throw win_runtime_error(dwResult, __FUNCTION__ " EapHostPeerSetUIContext failed.");
}


void eap::method_eaphost::get_response_attributes(_Inout_ EapAttributes *pAttribs)
{
    // Get response attributes from EapHost peer.
    eap_error_runtime error;
    DWORD dwResult = EapHostPeerGetResponseAttributes(
        m_session_id,
        pAttribs,
        &error._Myptr);
    if (dwResult == ERROR_SUCCESS) {
        // Response attributes successfuly returned.
    } else if (error)
        throw eap_runtime_error(*error  , __FUNCTION__ " EapHostPeerGetResponseAttributes failed.");
    else
        throw win_runtime_error(dwResult, __FUNCTION__ " EapHostPeerGetResponseAttributes failed.");
}


void eap::method_eaphost::set_response_attributes(
    _In_ const EapAttributes       *pAttribs,
    _Out_      EapPeerMethodOutput *pEapOutput)
{
    // Set response attributes for EapHost peer.
    EapHostPeerResponseAction action;
    eap_error_runtime error;
    DWORD dwResult = EapHostPeerSetResponseAttributes(
        m_session_id,
        pAttribs,
        &action,
        &error._Myptr);
    if (dwResult == ERROR_SUCCESS) {
        // Response attributes successfuly set.
        action_to_output(action, pEapOutput);
    } else if (error)
        throw eap_runtime_error(*error  , __FUNCTION__ " EapHostPeerGetResponseAttributes failed.");
    else
        throw win_runtime_error(dwResult, __FUNCTION__ " EapHostPeerGetResponseAttributes failed.");
}
