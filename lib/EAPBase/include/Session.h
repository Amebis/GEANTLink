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
    /// EAP session
    ///
    template <class _Tcred, class _Tint, class _Tintres> class session;
}

#pragma once

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
    template <class _Tcred, class _Tint, class _Tintres>
    class session
    {
    public:
        ///
        /// Credentials data type
        ///
        typedef _Tcred credentials_type;

        ///
        /// Interactive request data type
        ///
        typedef _Tint interactive_request_type;

    public:
        ///
        /// Constructs a session
        ///
        /// \param[in] mod  EAP module to use for global services
        ///
        session(_In_ module &mod) :
            m_module(mod),
            m_cfg(mod),
            m_cred(mod),
            m_eap_flags(0),
            m_token(NULL),
            m_send_packet_size_max((DWORD)-1)
        {
        }


        ///
        /// Copies session
        ///
        /// \param[in] other  Session to copy from
        ///
        session(_In_ const session &other) :
            m_module(other.m_module),
            m_cfg(other.m_cfg),
            m_cred(other.m_cred),
            m_eap_flags(other.m_eap_flags),
            m_token(other.m_token),
            m_send_packet_size_max(other.m_send_packet_size_max)
        {
        }


        ///
        /// Moves session
        ///
        /// \param[in] other  Session to move from
        ///
        session(_Inout_ session &&other) :
            m_module(other.m_module),
            m_cfg(std::move(other.m_cfg)),
            m_cred(std::move(other.m_cred)),
            m_eap_flags(std::move(other.m_eap_flags)),
            m_token(std::move(other.m_token)),
            m_send_packet_size_max(std::move(other.m_send_packet_size_max))
        {
        }


        ///
        /// Copies session
        ///
        /// \param[in] other  Session to copy from
        ///
        /// \returns Reference to this object
        ///
        session& operator=(_In_ const session &other)
        {
            if (this != std::addressof(other)) {
                assert(std::addressof(m_module) ==std::addressof(other.m_module)); // Copy session within same module only!
                m_cfg                  = other.m_cfg;
                m_cred                 = other.m_cred;
                m_eap_flags            = other.m_eap_flags;
                m_token                = other.m_token;
                m_send_packet_size_max = other.m_send_packet_size_max;
            }
            return *this;
        }


        ///
        /// Moves session
        ///
        /// \param[in] other  Session to move from
        ///
        /// \returns Reference to this object
        ///
        session& operator=(_Inout_ session &&other)
        {
            if (this != std::addressof(other)) {
                assert(std::addressof(m_module) ==std::addressof(other.m_module)); // Move session within same module only!
                m_cfg                  = std::move(other.m_cfg);
                m_cred                 = std::move(other.m_cred);
                m_eap_flags            = std::move(other.m_eap_flags);
                m_token                = std::move(other.m_token);
                m_send_packet_size_max = std::move(other.m_send_packet_size_max);
            }
            return *this;
        }


        /// \name Session start/end
        /// @{

        ///
        /// Starts an EAP authentication session on the peer EAPHost using the EAP method.
        ///
        /// \sa [EapPeerBeginSession function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363600.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool begin(
            _In_        DWORD         dwFlags,
            _In_  const EapAttributes *pAttributeArray,
            _In_        HANDLE        hTokenImpersonateUser,
            _In_        DWORD         dwMaxSendPacketSize,
            _Out_       EAP_ERROR     **ppEapError)
        {
            UNREFERENCED_PARAMETER(pAttributeArray);
            UNREFERENCED_PARAMETER(ppEapError);

            // Save session parameters.
            m_eap_flags            = dwFlags;
            m_token                = hTokenImpersonateUser;
            m_send_packet_size_max = dwMaxSendPacketSize;

            return true;
        }


        ///
        /// Ends an EAP authentication session for the EAP method.
        ///
        /// \sa [EapPeerEndSession function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363604.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool end(_Out_ EAP_ERROR **ppEapError)
        {
            UNREFERENCED_PARAMETER(ppEapError);

            return true;
        }

        /// @}

        /// \name Packet processing
        /// @{

        ///
        /// Processes a packet received by EAPHost from a supplicant.
        ///
        /// \sa [EapPeerProcessRequestPacket function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363621.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool process_request_packet(
            _In_                                       DWORD               dwReceivedPacketSize,
            _In_bytecount_(dwReceivedPacketSize) const EapPacket           *pReceivedPacket,
            _Out_                                      EapPeerMethodOutput *pEapOutput,
            _Out_                                      EAP_ERROR           **ppEapError) = 0;

        ///
        /// Obtains a response packet from the EAP method.
        ///
        /// \sa [EapPeerGetResponsePacket function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363610.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool get_response_packet(
            _Inout_                            DWORD     *pdwSendPacketSize,
            _Inout_bytecap_(*dwSendPacketSize) EapPacket *pSendPacket,
            _Out_                              EAP_ERROR **ppEapError) = 0;

        ///
        /// Obtains the result of an authentication session from the EAP method.
        ///
        /// \sa [EapPeerGetResult function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363611.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool get_result(
            _In_  EapPeerMethodResultReason reason,
            _Out_ EapPeerMethodResult       *ppResult,
            _Out_ EAP_ERROR                 **ppEapError) = 0;

        /// @}

        /// \name UI interaction
        /// @{

        ///
        /// Obtains the user interface context from the EAP method.
        ///
        /// \note This function is always followed by the `EapPeerInvokeInteractiveUI()` function, which is followed by the `EapPeerSetUIContext()` function.
        ///
        /// \sa [EapPeerGetUIContext function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363612.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool get_ui_context(
            _Out_ BYTE      **ppUIContextData,
            _Out_ DWORD     *pdwUIContextDataSize,
            _Out_ EAP_ERROR **ppEapError)
        {
            return m_module.pack(m_intreq, ppUIContextData, pdwUIContextDataSize, ppEapError);
        }


        ///
        /// Provides a user interface context to the EAP method.
        ///
        /// \note This function is called after the UI has been raised through the `EapPeerGetUIContext()` function.
        ///
        /// \sa [EapPeerSetUIContext function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363626.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool set_ui_context(
            _In_count_(dwUIContextDataSize) const BYTE                *pUIContextData,
            _In_                                  DWORD               dwUIContextDataSize,
            _In_                            const EapPeerMethodOutput *pEapOutput,
            _Out_                                 EAP_ERROR           **ppEapError)
        {
            UNREFERENCED_PARAMETER(pUIContextData);
            UNREFERENCED_PARAMETER(dwUIContextDataSize);
            UNREFERENCED_PARAMETER(pEapOutput);
            assert(ppEapError);

            *ppEapError = m_module.make_error(ERROR_NOT_SUPPORTED, _T(__FUNCTION__) _T(" Not supported."));
            return false;
        }

        /// @}

        /// \name Response attributes
        /// @{

        ///
        /// Obtains an array of EAP response attributes from the EAP method.
        ///
        /// \sa [EapPeerGetResponseAttributes function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363609.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool get_response_attributes(_Out_ EapAttributes *pAttribs, _Out_ EAP_ERROR **ppEapError)
        {
            UNREFERENCED_PARAMETER(pAttribs);
            assert(ppEapError);

            *ppEapError = m_module.make_error(ERROR_NOT_SUPPORTED, _T(__FUNCTION__) _T(" Not supported."));
            return false;
        }


        ///
        /// Provides an updated array of EAP response attributes to the EAP method.
        ///
        /// \sa [EapPeerSetResponseAttributes function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363625.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool set_response_attributes(const _In_ EapAttributes *pAttribs, _Out_ EapPeerMethodOutput *pEapOutput, _Out_ EAP_ERROR **ppEapError)
        {
            UNREFERENCED_PARAMETER(pAttribs);
            UNREFERENCED_PARAMETER(pEapOutput);
            assert(ppEapError);

            *ppEapError = m_module.make_error(ERROR_NOT_SUPPORTED, _T(__FUNCTION__) _T(" Not supported."));
            return false;
        }

        /// @}

    public:
        module &m_module;                   ///< EAP module
        config_providers m_cfg;             ///< Providers configuration
        credentials_type m_cred;            ///< User credentials
        interactive_request_type m_intreq;  ///< Interactive UI request data
        DWORD m_eap_flags;                  ///< A combination of EAP flags that describe the new EAP authentication session behavior
        HANDLE m_token;                     ///< Specifies a handle to the user impersonation token to use in this session
        DWORD m_send_packet_size_max;       ///< Specifies the maximum size in bytes of an EAP packet sent during the session. If the method needs to send a packet larger than the maximum size, the method must accommodate fragmentation and reassembly.
    };
}
