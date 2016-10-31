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

eap::method_eaphost::method_eaphost(_In_ module &mod, _In_ config_method_eaphost &cfg, _In_ credentials_eaphost &cred) :
    m_cfg(cfg),
    m_cred(cred),
    m_session_id(0),
    method(mod)
{
}


eap::method_eaphost::method_eaphost(_Inout_ method_eaphost &&other) :
    m_cfg       (          other.m_cfg        ),
    m_cred      (          other.m_cred       ),
    m_session_id(std::move(other.m_session_id)),
    method      (std::move(other             ))
{
}


eap::method_eaphost& eap::method_eaphost::operator=(_Inout_ method_eaphost &&other)
{
    if (this != std::addressof(other)) {
        assert(std::addressof(m_cfg ) == std::addressof(other.m_cfg )); // Move method within same configuration only!
        assert(std::addressof(m_cred) == std::addressof(other.m_cred)); // Move method within same credentials only!
        (method&)*this = std::move(other             );
        m_session_id   = std::move(other.m_session_id);
    }

    return *this;
}


void eap::method_eaphost::begin_session(
    _In_        DWORD         dwFlags,
    _In_  const EapAttributes *pAttributeArray,
    _In_        HANDLE        hTokenImpersonateUser,
    _In_opt_    DWORD         dwMaxSendPacketSize)
{
    method::begin_session(dwFlags, pAttributeArray, hTokenImpersonateUser, dwMaxSendPacketSize);

    // Presume authentication will fail with generic protocol failure. (Pesimist!!!)
    // We will reset once we get get_result(Success) call.
    m_cfg.m_last_status = config_method::status_auth_failed;
    m_cfg.m_last_msg.clear();

    // Create EapHost peer session using available connection data (m_cfg) and user data (m_cred).
    eap_error_runtime error;
    DWORD dwResult = EapHostPeerBeginSession(
        dwFlags,
        m_cfg.get_type(),
        pAttributeArray,
        hTokenImpersonateUser,
        (DWORD)m_cfg.m_cfg_blob.size(),
        m_cfg.m_cfg_blob.data(),
        (DWORD)m_cred.m_cred_blob.size(),
        m_cred.m_cred_blob.data(),
        dwMaxSendPacketSize,
        NULL, NULL, NULL,
        &m_session_id,
        &error._Myptr);
    if (dwResult == ERROR_SUCCESS) {
        // Session succesfully created.
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

    method::end_session();
}


EapPeerMethodResponseAction eap::method_eaphost::process_request_packet(
    _In_bytecount_(dwReceivedPacketSize) const void  *pReceivedPacket,
    _In_                                       DWORD dwReceivedPacketSize)
{
    assert(pReceivedPacket || dwReceivedPacketSize == 0);

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
        return action_h2p(action);
    } else if (error)
        throw eap_runtime_error(*error  , __FUNCTION__ " EapHostPeerProcessReceivedPacket failed.");
    else
        throw win_runtime_error(dwResult, __FUNCTION__ " EapHostPeerProcessReceivedPacket failed.");
}


void eap::method_eaphost::get_response_packet(
    _Out_    sanitizing_blob &packet,
    _In_opt_ DWORD           size_max)
{
    // Let EapHost peer prepare response packet.
    eap_blob_runtime _packet;
    eap_error_runtime error;
    DWORD dwResult = EapHostPeerGetSendPacket(
        m_session_id,
        &size_max,
        &_packet._Myptr,
        &error._Myptr);
    if (dwResult == ERROR_SUCCESS) {
        // Packet successfuly prepared.
        packet.assign(_packet.get(), _packet.get() + size_max);
    } else if (error)
        throw eap_runtime_error(*error  , __FUNCTION__ " EapHostPeerGetSendPacket failed.");
    else
        throw win_runtime_error(dwResult, __FUNCTION__ " EapHostPeerGetSendPacket failed.");
}


void eap::method_eaphost::get_result(
    _In_    EapPeerMethodResultReason reason,
    _Inout_ EapPeerMethodResult       *pResult)
{
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
        method::get_result(reason, pResult);

        pResult->dwFailureReasonCode = result.dwFailureReasonCode;
        pResult->pAttribArray        = result.pAttribArray;

        if (result.pEapError) {
            // Transfer error to our module memory space.
            pResult->pEapError = m_module.make_error(result.pEapError);
            EapHostPeerFreeEapError(result.pEapError);
            result.pEapError = NULL;
        }

        if (result.fSaveConnectionData) {
            // Update configuration BLOB.
            m_cfg.m_cfg_blob.assign(result.pConnectionData, result.pConnectionData + result.dwSizeofConnectionData);
        }

        if (result.fSaveUserData) {
            // Update credentials BLOB.
            m_cred.m_cred_blob.assign(result.pUserData, result.pUserData + result.dwSizeofUserData);
        }

        if (reason == EapPeerMethodResultSuccess)
            m_cfg.m_last_status = config_method::status_success;

        // Always ask EAP host to save the connection data. And it will save it *only* when we report "success".
        // Don't worry. EapHost is well aware of failed authentication condition.
        pResult->fSaveConnectionData = TRUE;
        pResult->fIsSuccess          = TRUE;
    } else if (error)
        throw eap_runtime_error(*error  , __FUNCTION__ " EapHostPeerGetResult failed.");
    else
        throw win_runtime_error(dwResult, __FUNCTION__ " EapHostPeerGetResult failed.");
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


EapPeerMethodResponseAction eap::method_eaphost::set_ui_context(
    _In_count_(dwUIContextDataSize) const BYTE  *pUIContextData,
    _In_                                  DWORD dwUIContextDataSize)
{
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
        return action_h2p(action);
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


EapPeerMethodResponseAction eap::method_eaphost::set_response_attributes(_In_ const EapAttributes *pAttribs)
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
        return action_h2p(action);
    } else if (error)
        throw eap_runtime_error(*error  , __FUNCTION__ " EapHostPeerGetResponseAttributes failed.");
    else
        throw win_runtime_error(dwResult, __FUNCTION__ " EapHostPeerGetResponseAttributes failed.");
}
