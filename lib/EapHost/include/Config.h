/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2021 Amebis
    Copyright © 2016 GÉANT
*/

#include <sal.h>

namespace eap
{
    class config_method_eaphost;
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
    /// EapHost peer method configuration
    ///
    class config_method_eaphost : public config_method
    {
    public:
        ///
        /// Constructs configuration
        ///
        /// \param[in] mod    EAP module to use for global services
        /// \param[in] level  Config level (0=outer, 1=inner, 2=inner-inner...)
        ///
        config_method_eaphost(_In_ module &mod, _In_ unsigned int level);

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        config_method_eaphost(_In_ const config_method_eaphost &other);

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        config_method_eaphost(_Inout_ config_method_eaphost &&other) noexcept;

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        /// \returns Reference to this object
        ///
        config_method_eaphost& operator=(_In_ const config_method_eaphost &other);

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        /// \returns Reference to this object
        ///
        config_method_eaphost& operator=(_Inout_ config_method_eaphost &&other) noexcept;

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

        virtual winstd::eap_type_t get_method_id() const;
        virtual const wchar_t* get_method_str() const;

        ///
        /// @copydoc eap::config_method::make_credentials()
        /// \returns This implementation always returns `eap::credentials_eaphost` type of credentials
        ///
        virtual credentials* make_credentials() const;

        ///
        /// Returns method EAP_METHOD_TYPE
        ///
        inline const EAP_METHOD_TYPE& get_type() const
        {
            return m_type;
        }

        ///
        /// Set method EAP_METHOD_TYPE
        ///
        inline void set_type(_In_ const EAP_METHOD_TYPE &type)
        {
            m_type = type;
        }

    protected:
        EAP_METHOD_TYPE m_type;     ///< EapHost method type: (EAP type, vendor ID, vendor type, author ID) tuple

    public:
        sanitizing_blob m_cfg_blob; ///< Method configuration BLOB
    };

    /// @}
}
