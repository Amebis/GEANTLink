/*
    Copyright 2015-2020 Amebis
    Copyright 2016 G�ANT

    This file is part of G�ANTLink.

    G�ANTLink is free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    G�ANTLink is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with G�ANTLink. If not, see <http://www.gnu.org/licenses/>.
*/

namespace eap
{
    class peer_tls_tunnel;
    class peer_ttls;
}

#pragma once

#include "Config.h"
#include "Credentials.h"
#include "Method.h"
#include "TTLS.h"

#include "..\..\TLS\include\Module.h"


namespace eap
{
    /// \addtogroup EAPBaseModule
    /// @{

    ///
    /// TLS tunnel peer
    ///
    class peer_tls_tunnel : public peer_tls_base
    {
    public:
        ///
        /// Constructs a TLS tunnel peer module
        ///
        /// \param[in] eap_method  EAP method type ID
        ///
        peer_tls_tunnel(_In_ winstd::eap_type_t eap_method);

        virtual void initialize();
        virtual void shutdown();

    protected:
        ///
        /// @copydoc eap::peer::combine_credentials()
        ///
        _Success_(return != 0) virtual const config_method_with_cred* combine_credentials(
            _In_                             DWORD                   dwFlags,
            _In_                       const config_connection       &cfg,
            _In_count_(dwUserDataSize) const BYTE                    *pUserData,
            _In_                             DWORD                   dwUserDataSize,
            _Inout_                          credentials_connection& cred_out);
    };


    ///
    /// EAP-TTLS peer
    ///
    class peer_ttls : public peer_tls_tunnel
    {
    public:
        ///
        /// Constructs a EAP-TTLS peer module
        ///
        peer_ttls();

        ///
        /// @copydoc eap::method::make_config()
        /// \returns This implementation always returns `eap::config_method_ttls` type of configuration
        ///
        virtual config_method* make_config();

    protected:
        ///
        /// @copydoc eap::peer::make_method()
        ///
        virtual method* make_method(_In_ config_method &cfg, _In_ credentials &cred);
    };

    /// @}
}
