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

namespace eap
{
    ///
    /// EAP and non-EAP method base class
    ///
    class method;

    ///
    /// Non-EAP method base class
    ///
    class method_noneap;
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
    class method
    {
        WINSTD_NONCOPYABLE(method)

    public:
        ///
        /// Constructs an EAP method
        ///
        /// \param[in] mod   EAP module to use for global services
        /// \param[in] cfg   Method configuration
        /// \param[in] cred  User credentials
        ///
        method(_In_ module &module, _In_ config_method &cfg, _In_ credentials &cred);

        ///
        /// Moves an EAP method
        ///
        /// \param[in] other  EAP method to move from
        ///
        method(_Inout_ method &&other);

        ///
        /// Moves an EAP method
        ///
        /// \param[in] other  EAP method to move from
        ///
        /// \returns Reference to this object
        ///
        method& operator=(_Inout_ method &&other);

        /// \name Packet processing
        /// @{

        ///
        /// Starts an EAP authentication session on the peer EapHost using the EAP method.
        ///
        /// \sa [EapPeerBeginSession function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363600.aspx)
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

        ///
        /// Processes a packet received by EapHost from a supplicant.
        ///
        /// \sa [EapPeerProcessRequestPacket function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363621.aspx)
        ///
        virtual void process_request_packet(
            _In_bytecount_(dwReceivedPacketSize) const void                *pReceivedPacket,
            _In_                                       DWORD               dwReceivedPacketSize,
            _Inout_                                    EapPeerMethodOutput *pEapOutput) = 0;

        ///
        /// Obtains a response packet from the EAP method.
        ///
        /// \sa [EapPeerGetResponsePacket function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363610.aspx)
        ///
        virtual void get_response_packet(
            _Inout_bytecap_(*dwSendPacketSize) void  *pSendPacket,
            _Inout_                            DWORD *pdwSendPacketSize) = 0;

        ///
        /// Obtains the result of an authentication session from the EAP method.
        ///
        /// \sa [EapPeerGetResult function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363611.aspx)
        ///
        virtual void get_result(
            _In_    EapPeerMethodResultReason reason,
            _Inout_ EapPeerMethodResult       *ppResult);

        /// @}

        /// \name User Interaction
        /// @{

        ///
        /// Obtains the user interface context from the EAP method.
        ///
        /// \note This function is always followed by the `EapPeerInvokeInteractiveUI()` function, which is followed by the `EapPeerSetUIContext()` function.
        ///
        /// \sa [EapPeerGetUIContext function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363612.aspx)
        ///
        virtual void get_ui_context(
            _Inout_ BYTE  **ppUIContextData,
            _Inout_ DWORD *pdwUIContextDataSize);

        ///
        /// Provides a user interface context to the EAP method.
        ///
        /// \note This function is called after the UI has been raised through the `EapPeerGetUIContext()` function.
        ///
        /// \sa [EapPeerSetUIContext function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363626.aspx)
        ///
        virtual void set_ui_context(
            _In_count_(dwUIContextDataSize) const BYTE                *pUIContextData,
            _In_                                  DWORD               dwUIContextDataSize,
            _In_                            const EapPeerMethodOutput *pEapOutput);

        /// @}

        /// \name EAP Response Attributes
        /// @{

        ///
        /// Obtains an array of EAP response attributes from the EAP method.
        ///
        /// \sa [EapPeerGetResponseAttributes function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363609.aspx)
        ///
        virtual void get_response_attributes(_Inout_ EapAttributes *pAttribs);

        ///
        /// Provides an updated array of EAP response attributes to the EAP method.
        ///
        /// \sa [EapPeerSetResponseAttributes function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363625.aspx)
        ///
        virtual void set_response_attributes(
            _In_ const EapAttributes       *pAttribs,
            _Inout_    EapPeerMethodOutput *pEapOutput);

        /// @}

    public:
        module &m_module;                           ///< EAP module
        config_method &m_cfg;                       ///< Connection configuration
        credentials &m_cred;                        ///< User credentials
        std::vector<winstd::eap_attr> m_eap_attr;   ///< EAP attributes
    };


    class method_noneap : public method
    {
        WINSTD_NONCOPYABLE(method_noneap)

    public:
        ///
        /// Constructs an EAP method
        ///
        /// \param[in] mod   EAP module to use for global services
        /// \param[in] cfg   Method configuration
        /// \param[in] cred  User credentials
        ///
        method_noneap(_In_ module &module, _In_ config_method &cfg, _In_ credentials &cred);

        ///
        /// Moves an EAP method
        ///
        /// \param[in] other  EAP method to move from
        ///
        method_noneap(_Inout_ method_noneap &&other);

        ///
        /// Moves an EAP method
        ///
        /// \param[in] other  EAP method to move from
        ///
        /// \returns Reference to this object
        ///
        method_noneap& operator=(_Inout_ method_noneap &&other);

        /// \name Packet processing
        /// @{

        ///
        /// Obtains a response packet from the EAP method.
        ///
        /// \sa [EapPeerGetResponsePacket function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363610.aspx)
        ///
        virtual void get_response_packet(
            _Inout_bytecap_(*dwSendPacketSize) void  *pSendPacket,
            _Inout_                            DWORD *pdwSendPacketSize);

        /// @}

    protected:
        ///
        /// Appends Diameter AVP to response packet
        ///
        /// \param[in] code     AVP code
        /// \param[in] flags    AVP flags
        /// \param[in] data     AVP data (<16777212B)
        /// \param[in] size     Size of \p data in bytes
        ///
        void append_avp(_In_ unsigned int code, _In_ unsigned char flags, _In_bytecount_(size) const void *data, _In_ unsigned int size);

        ///
        /// Appends Diameter AVP to response packet
        ///
        /// \param[in] code       AVP code
        /// \param[in] vendor_id  Vendor-ID
        /// \param[in] flags      AVP flags
        /// \param[in] data       AVP data (<16777212B)
        /// \param[in] size       Size of \p data in bytes
        ///
        void append_avp(_In_ unsigned int code, _In_ unsigned int vendor_id, _In_ unsigned char flags, _In_bytecount_(size) const void *data, _In_ unsigned int size);

    protected:
        sanitizing_blob m_packet_res;   ///< Response packet
    };
}
