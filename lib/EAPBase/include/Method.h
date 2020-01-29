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

namespace eap
{
    class method;
    class method_tunnel;
    class method_eap;
}

#pragma once

#include "Config.h"
#include "Credentials.h"
#include "Module.h"

#include <WinStd/EAP.h>

#include <Windows.h>
#include <eaptypes.h> // Must include after <Windows.h>
extern "C" {
#include <eapmethodpeerapis.h>
}
#include <sal.h>


namespace eap
{
    ///
    /// \defgroup EAPBaseMethod  Methods
    /// Methods
    ///
    /// @{

    ///
    /// Method base class
    ///
    class method
    {
    public:
        ///
        /// Constructs a method
        ///
        /// \param[in] mod  Module to use for global services
        ///
        method(_In_ module &mod);

        /// \name Session management
        /// @{

        ///
        /// Starts an EAP authentication session on the peer EapHost using the EAP method.
        ///
        /// \sa [EapPeerBeginSession function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363600.aspx)
        ///
        /// \param[in] dwFlags                A combination of EAP flags that describe the new EAP authentication session behavior.
        /// \param[in] pAttributeArray        A pointer to an array structure that specifies the EAP attributes of the entity to authenticate.
        /// \param[in] hTokenImpersonateUser  Specifies a handle to the user impersonation token to use in this session.
        /// \param[in] dwMaxSendPacketSize    Specifies the maximum size in bytes of an EAP packet sent during the session. If the method needs to send a packet larger than the maximum size, the method must accommodate fragmentation and reassembly.
        ///
        virtual void begin_session(
            _In_        DWORD         dwFlags,
            _In_  const EapAttributes *pAttributeArray,
            _In_        HANDLE        hTokenImpersonateUser,
            _In_opt_    DWORD         dwMaxSendPacketSize = MAXDWORD);

        ///
        /// Ends an EAP authentication session for the EAP method.
        ///
        /// \sa [EapPeerEndSession function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363604.aspx)
        ///
        virtual void end_session();

        /// @}

        /// \name Packet processing
        /// @{

        ///
        /// Processes a packet received by EapHost from a supplicant.
        ///
        /// \sa [EapPeerProcessRequestPacket function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363621.aspx)
        ///
        /// \param[in] pReceivedPacket       Received packet data
        /// \param[in] dwReceivedPacketSize  \p pReceivedPacket size in bytes
        ///
        /// \returns Action peer wants EapHost to do next.
        ///
        virtual EapPeerMethodResponseAction process_request_packet(
            _In_bytecount_(dwReceivedPacketSize) const void  *pReceivedPacket,
            _In_                                       DWORD dwReceivedPacketSize) = 0;

        ///
        /// Obtains a response packet from the EAP method.
        ///
        /// \sa [EapPeerGetResponsePacket function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363610.aspx)
        ///
        /// \param[out] packet    Response packet
        /// \param[in]  size_max  The maximum size in bytes \p packet must not exceed. If the method needs to send a packet larger than the maximum size, the method must accommodate fragmentation and reassembly.
        ///
        virtual void get_response_packet(
            _Out_    sanitizing_blob &packet,
            _In_opt_ DWORD           size_max = MAXDWORD) = 0;

        /// @}

        ///
        /// Obtains the result of an authentication session from the EAP method.
        ///
        /// \sa [EapPeerGetResult function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363611.aspx)
        ///
        /// \param[in   ] reason   The reason code for the authentication result returned in \p pResult.
        /// \param[inout] pResult  A pointer to a structure that contains the authentication results.
        ///
        virtual void get_result(
            _In_    EapPeerMethodResultReason reason,
            _Inout_ EapPeerMethodResult       *pResult);

        /// \name User Interaction
        /// @{

        ///
        /// Obtains the user interface context from the EAP method.
        ///
        /// \note This function is always followed by the `EapPeerInvokeInteractiveUI()` function, which is followed by the `EapPeerSetUIContext()` function.
        ///
        /// \sa [EapPeerGetUIContext function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363612.aspx)
        ///
        /// \param[out] context_data  Supplicant user interface context data from EAPHost.
        ///
        virtual void get_ui_context(_Out_ sanitizing_blob &context_data);

        ///
        /// Provides a user interface context to the EAP method.
        ///
        /// \note This function is called after the UI has been raised through the `EapPeerGetUIContext()` function.
        ///
        /// \sa [EapPeerSetUIContext function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363626.aspx)
        ///
        /// \param[in] pUIContextData       A pointer to an address that contains a byte buffer with the new supplicant UI context data to set on EAPHost.
        /// \param[in] dwUIContextDataSize  \p pUIContextData size in bytes
        ///
        /// \returns Action peer wants EapHost to do next.
        ///
        virtual EapPeerMethodResponseAction set_ui_context(
            _In_count_(dwUIContextDataSize) const BYTE  *pUIContextData,
            _In_                                  DWORD dwUIContextDataSize);

        /// @}

        /// \name EAP Response Attributes
        /// @{

        ///
        /// Obtains an array of EAP response attributes from the EAP method.
        ///
        /// \sa [EapPeerGetResponseAttributes function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363609.aspx)
        ///
        /// \param[out] pAttribs  A pointer to a structure that contains an array of EAP authentication response attributes for the supplicant.
        ///
        virtual void get_response_attributes(_Out_ EapAttributes *pAttribs);

        ///
        /// Provides an updated array of EAP response attributes to the EAP method.
        ///
        /// \sa [EapPeerSetResponseAttributes function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363625.aspx)
        ///
        /// \param[in] pAttribs  A pointer to a structure that contains an array of new EAP authentication response attributes to set for the supplicant on EAPHost.
        ///
        /// \returns Action peer wants EapHost to do next.
        ///
        virtual EapPeerMethodResponseAction set_response_attributes(_In_ const EapAttributes *pAttribs);

        /// @}

    public:
        module &m_module;   ///< Module for global services
        method *m_outer;    ///< Outer method
    };


    ///
    /// Tunnel method base class
    ///
    /// This is a base class for all the methods that encapsulate inner methods to provide stacking framework.
    ///
    class method_tunnel : public method
    {
    public:
        ///
        /// Constructs a method
        ///
        /// \param[in] mod    Module to use for global services
        /// \param[in] inner  Inner method
        ///
        method_tunnel(_In_ module &mod, _In_ method *inner);

        /// \name Session management
        /// @{

        virtual void begin_session(
            _In_        DWORD         dwFlags,
            _In_  const EapAttributes *pAttributeArray,
            _In_        HANDLE        hTokenImpersonateUser,
            _In_opt_    DWORD         dwMaxSendPacketSize = MAXDWORD);

        virtual void end_session();

        /// @}

        /// \name Packet processing
        /// @{

        virtual EapPeerMethodResponseAction process_request_packet(
            _In_bytecount_(dwReceivedPacketSize) const void  *pReceivedPacket,
            _In_                                       DWORD dwReceivedPacketSize);

        virtual void get_response_packet(
            _Out_    sanitizing_blob &packet,
            _In_opt_ DWORD           size_max = MAXDWORD);

        /// @}

        virtual void get_result(
            _In_    EapPeerMethodResultReason reason,
            _Inout_ EapPeerMethodResult       *pResult);

        /// \name User Interaction
        /// @{

        virtual void get_ui_context(_Out_ sanitizing_blob &context_data);

        virtual EapPeerMethodResponseAction set_ui_context(
            _In_count_(dwUIContextDataSize) const BYTE  *pUIContextData,
            _In_                                  DWORD dwUIContextDataSize);

        /// @}

        /// \name EAP Response Attributes
        /// @{

        virtual void get_response_attributes(_Out_ EapAttributes *pAttribs);

        virtual EapPeerMethodResponseAction set_response_attributes(_In_ const EapAttributes *pAttribs);

        /// @}

    protected:
        std::unique_ptr<method> m_inner;    ///< Inner method
    };


    ///
    /// EAP tunnel method
    ///
    /// This method encapsulates inner data in EAP packets.
    ///
    class method_eap : public method_tunnel
    {
    public:
        ///
        /// Constructs a method
        ///
        /// \param[in] mod         Module to use for global services
        /// \param[in] eap_method  EAP method type
        /// \param[in] cred        User credentials
        /// \param[in] inner       Inner method
        ///
        method_eap(_In_ module &mod, _In_ winstd::eap_type_t eap_method, _In_ credentials &cred, _In_ method *inner);

        /// \name Session management
        /// @{

        virtual void begin_session(
            _In_        DWORD         dwFlags,
            _In_  const EapAttributes *pAttributeArray,
            _In_        HANDLE        hTokenImpersonateUser,
            _In_opt_    DWORD         dwMaxSendPacketSize = MAXDWORD);

        /// @}

        /// \name Packet processing
        /// @{

        virtual EapPeerMethodResponseAction process_request_packet(
            _In_bytecount_(dwReceivedPacketSize) const void  *pReceivedPacket,
            _In_                                       DWORD dwReceivedPacketSize);

        virtual void get_response_packet(
            _Out_    sanitizing_blob &packet,
            _In_opt_ DWORD           size_max = MAXDWORD);

        /// @}

        virtual void get_result(
            _In_    EapPeerMethodResultReason reason,
            _Inout_ EapPeerMethodResult       *pResult);

    protected:
        ///
        /// Creates an EAP response packet
        ///
        /// \param[in] eap_type                  EAP type
        /// \param[in] pResponsePacketData       Packet data
        /// \param[in] dwResponsePacketDataSize  \p pResponsePacketData size in bytes
        ///
        void make_response_packet(
            _In_                                           winstd::eap_type_t eap_type,
            _In_bytecount_(dwResponsePacketDataSize) const void               *pResponsePacketData,
            _In_                                           DWORD              dwResponsePacketDataSize);

    protected:
        const winstd::eap_type_t m_eap_method;  ///< EAP method type
        credentials &m_cred;                    ///< User credentials
        unsigned char m_id;                     ///< Request packet ID
        EapPeerMethodResultReason m_result;     ///< The result the authenticator reported with EAP-Success or EAP-Failure
        sanitizing_blob m_packet_res;           ///< Buffer to hold response packet data
    };

    /// @}
}
