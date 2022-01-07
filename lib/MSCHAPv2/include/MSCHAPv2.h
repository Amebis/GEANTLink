/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2022 Amebis
    Copyright © 2016 GÉANT
*/

#include <WinStd/Crypt.h>


namespace eap
{
    enum class chap_packet_code_t : unsigned char;
    struct chap_header;
    struct challenge_mschapv2;
    struct challenge_hash;
    struct nt_password_hash;
    struct nt_response;
    struct authenticator_response;

    ///
    /// \defgroup MSCHAPv2  MSCHAPv2
    /// Microsoft Challenge-Handshake Authentication Protocol (version 2)
    ///
    /// @{

    ///
    /// Creates DES encryption key with given plaintext key
    ///
    /// \param[in] cp    Handle of the cryptographics provider
    /// \param[in] key   The key (without parity bits)
    /// \param[in] size  Size of \p key (maximum 7B)
    ///
    /// \returns DES encryption key
    ///
    winstd::crypt_key create_des_key(_In_ HCRYPTPROV cp, _In_count_(size) const unsigned char *key, _In_ size_t size);

    /// @}
}

#pragma once

#include "../../EAPBase/include/EAP.h"


namespace eap
{
    /// \addtogroup MSCHAPv2
    /// @{

    ///
    /// CHAP packet codes
    ///
    #pragma warning(suppress: 4480)
    enum class chap_packet_code_t : unsigned char {
        challenge       = 1,    ///< Challenge
        response        = 2,    ///< Response
        success         = 3,    ///< Success
        failure         = 4,    ///< Failure
        change_password = 7,    ///< Change password
    };


#pragma pack(push)
#pragma pack(1)

    ///
    /// CHAP packet header base class
    ///
    struct chap_header
    {
        chap_packet_code_t code;    ///< CHAP packet code
        unsigned char ident;        ///< CHAP identifier
        unsigned char length[2];    ///< CHAP packet length
    };


    ///
    /// MSCHAPv2 Challenge
    ///
    struct challenge_mschapv2 : public sanitizing_blob_xf<16>
    {
        ///
        /// Generates random challenge
        ///
        /// \param[in] cp  Handle of the cryptographics provider
        ///
        void randomize(_In_ HCRYPTPROV cp);
    };


    ///
    /// MSCHAPv2 Challenge Hash
    ///
    struct challenge_hash : public sanitizing_blob_xf<8>
    {
        ///
        /// Constructor
        ///
        challenge_hash();

        ///
        /// Constructs a challenge hash
        ///
        /// \sa [Microsoft PPP CHAP Extensions, Version 2 (Chapter 8.2. ChallengeHash())](https://tools.ietf.org/html/rfc2759#section-8.2)
        ///
        /// \param[in] cp                Handle of the cryptographics provider
        /// \param[in] challenge_server  Authenticator challenge
        /// \param[in] challenge_client  Peer challenge
        /// \param[in] username          Username
        ///
        challenge_hash(
            _In_         HCRYPTPROV         cp,
            _In_   const sanitizing_blob    &challenge_server,
            _In_   const challenge_mschapv2 &challenge_client,
            _In_z_ const char               *username);

        ///
        /// Copies a challenge hash
        ///
        /// \param[in] other  Challenge hash to copy from
        ///
        challenge_hash(_In_ const sanitizing_blob_f<8> &other);

#ifdef _DEBUG
        ///
        /// Moves the challenge hash
        ///
        /// \param[inout] other  Challenge hash to move from
        ///
        challenge_hash(_Inout_ sanitizing_blob_zf<8> &&other);
#endif
    };


    ///
    /// NT-Password Hash
    ///
    struct nt_password_hash : public sanitizing_blob_xf<16>
    {
        ///
        /// Constructor
        ///
        nt_password_hash();

        ///
        /// Constructs a NT-Password hash
        ///
        /// \sa [Microsoft PPP CHAP Extensions, Version 2 (Chapter 8.3. NtPasswordHash())](https://tools.ietf.org/html/rfc2759#section-8.3)
        ///
        /// \param[in] cp        Handle of the cryptographics provider
        /// \param[in] password  Password
        ///
        nt_password_hash(
            _In_         HCRYPTPROV cp,
            _In_z_ const wchar_t    *password);

        ///
        /// Constructs a hash of NT-Password hash
        ///
        /// \sa [Microsoft PPP CHAP Extensions, Version 2 (Chapter 8.4. HashNtPasswordHash())](https://tools.ietf.org/html/rfc2759#section-8.4)
        ///
        /// \param[in] cp        Handle of the cryptographics provider
        /// \param[in] pwd_hash  NT-Password hash
        ///
        nt_password_hash(
            _In_       HCRYPTPROV       cp,
            _In_ const nt_password_hash &pwd_hash);

        ///
        /// Copies a NT-Password hash
        ///
        /// \param[in] other  NT-Password to copy from
        ///
        nt_password_hash(_In_ const sanitizing_blob_f<16> &other);

#ifdef _DEBUG
        ///
        /// Moves the NT-Password hash
        ///
        /// \param[inout] other  NT-Password hash to move from
        ///
        nt_password_hash(_Inout_ sanitizing_blob_zf<16> &&other);
#endif
    };


    ///
    /// NT-Response
    ///
    struct nt_response : public sanitizing_blob_xf<24>
    {
        ///
        /// Constructor
        ///
        nt_response();

        ///
        /// Constructs a NT-Response
        ///
        /// \sa [Microsoft PPP CHAP Extensions, Version 2 (Chapter 8.1. GenerateNTResponse())](https://tools.ietf.org/html/rfc2759#section-8.1)
        ///
        /// \param[in] cp                Handle of the cryptographics provider
        /// \param[in] challenge_server  Authenticator challenge
        /// \param[in] challenge_client  Peer challenge
        /// \param[in] username          Username
        /// \param[in] password          Password
        ///
        nt_response(
            _In_         HCRYPTPROV         cp,
            _In_   const sanitizing_blob    &challenge_server,
            _In_   const challenge_mschapv2 &challenge_client,
            _In_z_ const char               *username,
            _In_z_ const wchar_t            *password);

        ///
        /// Copies a NT-Response
        ///
        /// \param[in] other  NT-Response to copy from
        ///
        nt_response(_In_ const sanitizing_blob_f<24> &other);

#ifdef _DEBUG
        ///
        /// Moves the NT-Response
        ///
        /// \param[inout] other  NT-Response to move from
        ///
        nt_response(_Inout_ sanitizing_blob_zf<24> &&other);
#endif
    };


    ///
    /// Authenticator Response
    ///
    struct authenticator_response : public sanitizing_blob_xf<20>
    {
        ///
        /// Constructor
        ///
        authenticator_response();

        ///
        /// Constructs an authenticator response
        ///
        /// \sa [Microsoft PPP CHAP Extensions, Version 2 (Chapter 8.7. GenerateAuthenticatorResponse())](https://tools.ietf.org/html/rfc2759#section-8.7)
        ///
        /// \param[in] cp                Handle of the cryptographics provider
        /// \param[in] challenge_server  Authenticator challenge
        /// \param[in] challenge_client  Peer challenge
        /// \param[in] username          Username
        /// \param[in] password          Password
        /// \param[in] nt_resp           NT-Response
        ///
        authenticator_response(
            _In_         HCRYPTPROV         cp,
            _In_   const sanitizing_blob    &challenge_server,
            _In_   const challenge_mschapv2 &challenge_client,
            _In_z_ const char               *username,
            _In_z_ const wchar_t            *password,
            _In_   const nt_response        &nt_resp);

        ///
        /// Copies an authenticator response
        ///
        /// \param[in] other  Authenticator response to copy from
        ///
        authenticator_response(_In_ const sanitizing_blob_f<20> &other);

#ifdef _DEBUG
        ///
        /// Moves the authenticator response
        ///
        /// \param[inout] other  Authenticator response to move from
        ///
        authenticator_response(_Inout_ sanitizing_blob_zf<20> &&other);
#endif
    };

#pragma pack(pop)

    /// @}
}
