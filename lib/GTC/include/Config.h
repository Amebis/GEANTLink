/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2020 Amebis
    Copyright © 2016 GÉANT
*/

#include <sal.h>

namespace eap
{
    class config_method_eapgtc;
}

#pragma once

#include "../../EAPBase/include/Config.h"

#include <Windows.h>
#include <sal.h>
#include <tchar.h>


namespace eap
{
    /// \addtogroup EAPBaseConfig
    /// @{

    ///
    /// EAP-GTC configuration
    ///
    class config_method_eapgtc : public config_method_with_cred
    {
    public:
        ///
        /// Authentication mode
        ///
        enum class auth_mode_t {
            response = 0,   ///< Challenge/Response
            password,       ///< Password
        };

    public:
        ///
        /// Constructs configuration
        ///
        /// \param[in] mod    EAP module to use for global services
        /// \param[in] level  Config level (0=outer, 1=inner, 2=inner-inner...)
        ///
        config_method_eapgtc(_In_ module &mod, _In_ unsigned int level);

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        config_method_eapgtc(_In_ const config_method_eapgtc &other);

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        config_method_eapgtc(_Inout_ config_method_eapgtc &&other) noexcept;

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        /// \returns Reference to this object
        ///
        config_method_eapgtc& operator=(_In_ const config_method_eapgtc &other);

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        /// \returns Reference to this object
        ///
        config_method_eapgtc& operator=(_Inout_ config_method_eapgtc &&other) noexcept;

        virtual config* clone() const;

        /// \name XML management
        /// @{
        virtual void save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot) const;
        virtual void load(_In_ IXMLDOMNode *pConfigRoot);
        /// @}

        /// \name BLOB management
        /// @{
        virtual void operator<<(_Inout_ cursor_out &cursor) const;
        virtual size_t get_pk_size() const;
        virtual void operator>>(_Inout_ cursor_in &cursor);
        /// @}

        ///
        /// @copydoc eap::config_method::get_method_id()
        /// \returns This implementation always returns `winstd::eap_type_t::gtc`
        ///
        virtual winstd::eap_type_t get_method_id() const;

        ///
        /// @copydoc eap::config_method::get_method_str()
        /// \returns This implementation always returns `L"EAP-GTC"`
        ///
        virtual const wchar_t* get_method_str() const;

        ///
        /// @copydoc eap::config_method::make_credentials()
        /// \returns This implementation returns `eap::credentials_identity` or `eap::credentials_pass` type of credentials, depending on authentication mode.
        ///
        virtual credentials* make_credentials() const;
    };

    /// @}
}


/// \addtogroup EAPBaseStream
/// @{

///
/// Packs an EAP-GTC method authentication mode
///
/// \param[inout] cursor  Memory cursor
/// \param[in]    val     Authentication mode to pack
///
inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const eap::config_method_eapgtc::auth_mode_t &val)
{
    cursor << (unsigned char)val;
}


///
/// Returns packed size of an EAP-GTC method authentication mode
///
/// \param[in] val  Authentication mode to pack
///
/// \returns Size of data when packed (in bytes)
///
inline size_t pksizeof(_In_ const eap::config_method_eapgtc::auth_mode_t &val)
{
    return pksizeof((unsigned char)val);
}


///
/// Unpacks an EAP-GTC method authentication mode
///
/// \param[inout] cursor  Memory cursor
/// \param[out]   val     Authentication mode to unpack to
///
inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ eap::config_method_eapgtc::auth_mode_t &val)
{
    val = (eap::config_method_eapgtc::auth_mode_t)0; // Reset higher bytes to zero before reading to lower byte.
    cursor >> (unsigned char&)val;
}

/// @}
