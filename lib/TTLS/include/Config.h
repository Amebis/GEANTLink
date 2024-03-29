/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2022 Amebis
    Copyright © 2016 GÉANT
*/

#include <sal.h>

namespace eap
{
    class config_method_tls_tunnel;
    class config_method_ttls;
}

#pragma once

#include "Credentials.h"
#include "TTLS.h"

#include "../../TLS/include/Config.h"

#include <Windows.h>
#include <assert.h>

#include <memory>


namespace eap
{
    /// \addtogroup EAPBaseMethod
    /// @{

    ///
    /// TLS tunnel configuration
    ///
    class config_method_tls_tunnel : public config_method_tls
    {
    public:
        ///
        /// Constructs configuration
        ///
        /// \param[in] mod    EAP module to use for global services
        /// \param[in] level  Config level (0=outer, 1=inner, 2=inner-inner...)
        ///
        config_method_tls_tunnel(_In_ module &mod, _In_ unsigned int level);

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        config_method_tls_tunnel(const _In_ config_method_tls_tunnel &other);

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        config_method_tls_tunnel(_Inout_ config_method_tls_tunnel &&other) noexcept;

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        /// \returns Reference to this object
        ///
        config_method_tls_tunnel& operator=(const _In_ config_method_tls_tunnel &other);

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        /// \returns Reference to this object
        ///
        config_method_tls_tunnel& operator=(_Inout_ config_method_tls_tunnel &&other) noexcept;

        /// \name BLOB management
        /// @{
        virtual void operator<<(_Inout_ cursor_out &cursor) const;
        virtual size_t get_pk_size() const;
        virtual void operator>>(_Inout_ cursor_in &cursor);
        /// @}

        ///
        /// @copydoc eap::config_method::make_credentials()
        /// \returns This implementation always returns `eap::credentials_tls_tunnel` type of credentials
        ///
        virtual credentials* make_credentials() const;

    protected:
        ///
        /// Makes a new inner method config
        ///
        /// \param[in] eap_type  EAP type
        ///
        /// \returns A new inner method config of given type
        ///
        virtual config_method* make_inner_config(_In_ winstd::eap_type_t eap_type) const = 0;

        ///
        /// Makes a new inner method config
        ///
        /// \param[in] eap_type  EAP type
        ///
        /// \returns A new inner method config of given type
        ///
        virtual config_method* make_inner_config(_In_ const wchar_t *eap_type) const = 0;

    public:
        std::unique_ptr<config_method> m_inner; ///< Inner authentication configuration
    };


    ///
    /// EAP-TTLS configuration
    ///
    class config_method_ttls : public config_method_tls_tunnel
    {
    public:
        ///
        /// Constructs configuration
        ///
        /// \param[in] mod    EAP module to use for global services
        /// \param[in] level  Config level (0=outer, 1=inner, 2=inner-inner...)
        ///
        config_method_ttls(_In_ module &mod, _In_ unsigned int level);

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        config_method_ttls(const _In_ config_method_ttls &other);

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        config_method_ttls(_Inout_ config_method_ttls &&other) noexcept;

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        /// \returns Reference to this object
        ///
        config_method_ttls& operator=(const _In_ config_method_ttls &other);

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        /// \returns Reference to this object
        ///
        config_method_ttls& operator=(_Inout_ config_method_ttls &&other) noexcept;

        virtual config* clone() const;

        /// \name XML management
        /// @{
        virtual void save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot) const;
        virtual void load(_In_ IXMLDOMNode *pConfigRoot);
        /// @}

        ///
        /// @copydoc eap::config_method::get_method_id()
        /// \returns This implementation always returns `winstd::eap_type_t::ttls`
        ///
        virtual winstd::eap_type_t get_method_id() const;

        ///
        /// @copydoc eap::config_method::get_method_str()
        /// \returns This implementation always returns `L"EAP-TTLS"`
        ///
        virtual const wchar_t* get_method_str() const;

    protected:
        ///
        /// @copydoc eap::config_method_tls_tunnel::make_inner_config()
        ///
        virtual config_method* make_inner_config(_In_ winstd::eap_type_t eap_type) const;

        ///
        /// @copydoc eap::config_method_tls_tunnel::make_inner_config()
        ///
        virtual config_method* make_inner_config(_In_ const wchar_t *eap_type) const;
    };

    /// @}
}
