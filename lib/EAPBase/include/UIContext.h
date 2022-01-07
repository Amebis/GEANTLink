/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2022 Amebis
    Copyright © 2016-2017 GÉANT
*/

namespace eap
{
    class ui_context;
}

#pragma once

#include "Config.h"
#include "Credentials.h"
#include "Module.h"

#include "../../../include/Version.h"


namespace eap
{
    ///
    /// \defgroup EAPBaseUICtx  UI Context
    /// Back and front-end inter-process data exchange
    ///
    /// @{

    ///
    /// UI context
    ///
    class ui_context : public packable
    {
    public:
        ///
        /// Constructs context
        ///
        /// \param[in] cfg   Connection configuration
        /// \param[in] cred  Connection credentials
        ///
        ui_context(_In_ config_connection &cfg, _In_ credentials_connection &cred);

        ///
        /// Copies context
        ///
        /// \param[in] other  Credentials to copy from
        ///
        ui_context(_In_ const ui_context &other);

        ///
        /// Moves context
        ///
        /// \param[in] other  Credentials to move from
        ///
        ui_context(_Inout_ ui_context &&other) noexcept;

        ///
        /// Copies context
        ///
        /// \param[in] other  Credentials to copy from
        ///
        /// \returns Reference to this object
        ///
        ui_context& operator=(_In_ const ui_context &other);

        ///
        /// Moves context
        ///
        /// \param[in] other  Configuration to move from
        ///
        /// \returns Reference to this object
        ///
        ui_context& operator=(_Inout_ ui_context &&other) noexcept;

        /// \name BLOB management
        /// @{
        virtual void operator<<(_Inout_ cursor_out &cursor) const;
        virtual size_t get_pk_size() const;
        virtual void operator>>(_Inout_ cursor_in &cursor);
        /// @}

    public:
        config_connection &m_cfg;       ///< Connection configuration
        credentials_connection &m_cred; ///< Connection credentials
        sanitizing_blob m_data;         ///< Context data
    };

    /// @}
}
