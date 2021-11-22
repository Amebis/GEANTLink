/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2021 Amebis
    Copyright © 2016 GÉANT
*/

namespace eap
{
    class method_defrag;
    class method_tls;
}

#pragma once

#include "Config.h"
#include "Credentials.h"

#include "../../EAPBase/include/Method.h"

#include <WinStd/Sec.h>


namespace eap
{
    /// \addtogroup EAPBaseMethod
    /// @{

    ///
    /// EAP-(T)TLS/PEAP class defragging method tunnel
    ///
    class method_defrag : public method
    {
    public:
#pragma warning(push)
#pragma warning(disable: 4480)

        ///
        /// EAP-(T)TLS/PEAP request/response packet flags
        ///
        /// \sa [The EAP-TLS Authentication Protocol (Chapter: 3.1 EAP-TLS Request Packet)](https://tools.ietf.org/html/rfc5216#section-3.1)
        /// \sa [The EAP-TLS Authentication Protocol (Chapter: 3.2 EAP-TLS Response Packet)](https://tools.ietf.org/html/rfc5216#section-3.2)
        /// \sa [The EAP-TTLS Authentication Protocol Version 0 (Chapter: 9.1. Packet Format)](https://tools.ietf.org/html/rfc5281#section-9.1)
        /// \sa [Protected EAP Protocol (PEAP) (Chapter: 3.1. PEAP Packet Format)](https://tools.ietf.org/html/draft-josefsson-pppext-eap-tls-eap-05#section-3.1)
        ///
        enum flags_t : unsigned char {
            flags_length_incl     = 0x80,   ///< Length included
            flags_more_frag       = 0x40,   ///< More fragments
            flags_start           = 0x20,   ///< Start
            flags_ver_mask        = 0x07,   ///< Version mask
        };

#pragma warning(pop)

    public:
        ///
        /// Constructs a method
        ///
        /// \param[in] mod          Module to use for global services
        /// \param[in] version_max  Maximum protocol version supported by peer
        /// \param[in] inner        Inner method
        ///
        method_defrag(_In_ module &mod, _In_ unsigned char version_max, _In_ method *inner);

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

    public:
        unsigned char m_version;    ///< Negotiated protocol version

    protected:
        sanitizing_blob m_data_req; ///< Data in request
        sanitizing_blob m_data_res; ///< Data in response
        bool m_send_res;            ///< Are we sending a response?

        ///
        /// Communication phase
        ///
        enum class phase_t {
            unknown = -1,           ///< Unknown phase
            init = 0,               ///< Binding exchange
            established,            ///< Connection established
        } m_phase;                  ///< What phase is our communication at?
    };


    ///
    /// EAP-TLS method
    ///
    class method_tls : public method
    {
    public:
        ///
        /// Constructs an EAP-TLS method
        ///
        /// \param[in] mod    EAP module to use for global services
        /// \param[in] cfg    Method configuration
        /// \param[in] cred   User credentials
        /// \param[in] inner  Inner method
        ///
        method_tls(_In_ module &mod, _In_ config_method_tls &cfg, _In_ credentials_tls &cred, _In_opt_ method *inner = nullptr);

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

    protected:
        ///
        /// Pushes keying material to the inner method.
        ///
        virtual void push_keying_material();

        ///
        /// Retrieves keying material.
        ///
        /// \param[out] recv_key  Enc-RECV-Key, 32 bytes
        /// \param[out] send_key  Enc-SEND-Key, 32 bytes
        ///
        virtual void get_keying_material(_Out_ sanitizing_blob_xf<32> &recv_key, _Out_ sanitizing_blob_xf<32> &send_key);

        ///
        /// Decrypts data and forwards it to the inner method.
        ///
        EapPeerMethodResponseAction decrypt_request_data();

#if EAP_TLS < EAP_TLS_SCHANNEL_FULL
        ///
        /// Verifies server certificate if trusted by configuration
        ///
        void verify_server_trust() const;
#endif

    protected:
        config_method_tls &m_cfg;                   ///< Method configuration
        credentials_tls &m_cred;                    ///< Method user credentials
        HANDLE m_user_ctx;                          ///< Handle to user context
        winstd::cert_store m_store;                 ///< User certificate store
        winstd::tstring m_sc_target_name;           ///< Schannel target name
        winstd::sec_credentials m_sc_cred;          ///< Schannel client credentials
        std::vector<unsigned char> m_sc_queue;      ///< TLS data queue
        winstd::sec_context m_sc_ctx;               ///< Schannel context
        winstd::cert_context m_sc_cert;             ///< Server certificate

        ///
        /// Communication phase
        ///
        enum class phase_t {
            unknown = -1,                           ///< Unknown phase
            handshake_init = 0,                     ///< Handshake initialize
            handshake_cont,                         ///< Handshake continue
            finished,                               ///< Exchange application data
        } m_phase;                                  ///< What phase is our communication at?

        sanitizing_blob m_packet_res;               ///< Response packet
        bool m_packet_res_inner;                    ///< Get and encrypt data from inner method too?

        std::vector<winstd::eap_attr> m_eap_attr;   ///< EAP attributes returned by get_result() method
        EAP_ATTRIBUTES m_eap_attr_desc;             ///< EAP attributes descriptor (required to avoid memory leakage in get_result())
    };

    /// @}
}
