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
    class method_gtc;
}

#pragma once

#include "Config.h"

#include "../../EAPBase/include/Method.h"


namespace eap
{
    /// \addtogroup EAPBaseMethod
    /// @{

    ///
    /// GTC method
    ///
    class method_gtc : public method
    {
        WINSTD_NONCOPYABLE(method_gtc)

    public:
        ///
        /// Constructs a GTC method
        ///
        /// \param[in] mod   GTC module to use for global services
        /// \param[in] cfg   Method configuration
        /// \param[in] cred  User credentials
        ///
        method_gtc(_In_ module &mod, _In_ config_method_eapgtc &cfg, _In_ credentials &cred);

        ///
        /// Moves a GTC method
        ///
        /// \param[in] other  GTC method to move from
        ///
        method_gtc(_Inout_ method_gtc &&other) noexcept;

        ///
        /// Moves a GTC method
        ///
        /// \param[in] other  GTC method to move from
        ///
        /// \returns Reference to this object
        ///
        method_gtc& operator=(_Inout_ method_gtc &&other) noexcept;

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

        /// \name User Interaction
        /// @{

        virtual void get_ui_context(_Out_ sanitizing_blob &context_data);

        virtual EapPeerMethodResponseAction set_ui_context(
            _In_count_(dwUIContextDataSize) const BYTE  *pUIContextData,
            _In_                                  DWORD dwUIContextDataSize);

        /// @}

    protected:
        config_method_eapgtc &m_cfg;            ///< Method configuration
        credentials &m_cred;                    ///< Method user credentials
        winstd::sanitizing_wstring m_challenge; ///< GTC challenge
        winstd::sanitizing_wstring m_response;  ///< GTC response
    };

    /// @}
}
