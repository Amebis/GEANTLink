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
    /// TTLS peer
    ///
    class peer_ttls;
}

#pragma once

#include "Config.h"
#include "Credentials.h"
#include "../../EAPBase/include/Module.h"


namespace eap
{
    class peer_ttls : public peer
    {
    public:
        ///
        /// Constructs a EAP TTLS peer module
        ///
        peer_ttls();

        ///
        /// Makes a new method config
        ///
        virtual config_method* make_config_method();

        ///
        /// Initializes an EAP peer method for EAPHost.
        ///
        /// \sa [EapPeerGetInfo function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363613.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool initialize(_Out_ EAP_ERROR **ppEapError);

        ///
        /// Shuts down the EAP method and prepares to unload its corresponding DLL.
        ///
        /// \sa [EapPeerShutdown function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363627.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool shutdown(_Out_ EAP_ERROR **ppEapError);

        ///
        /// Returns the user data and user identity after being called by EAPHost.
        ///
        /// \sa [EapPeerGetIdentity function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363607.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool get_identity(
            _In_                                   DWORD     dwFlags,
            _In_count_(dwConnectionDataSize) const BYTE      *pConnectionData,
            _In_                                   DWORD     dwConnectionDataSize,
            _In_count_(dwUserDataSize)       const BYTE      *pUserData,
            _In_                                   DWORD     dwUserDataSize,
            _Out_                                  BYTE      **ppUserDataOut,
            _Out_                                  DWORD     *pdwUserDataOutSize,
            _In_                                   HANDLE    hTokenImpersonateUser,
            _Out_                                  BOOL      *pfInvokeUI,
            _Out_                                  WCHAR     **ppwszIdentity,
            _Out_                                  EAP_ERROR **ppEapError);

        ///
        /// Defines the implementation of an EAP method-specific function that retrieves the properties of an EAP method given the connection and user data.
        ///
        /// \sa [EapPeerGetMethodProperties function](https://msdn.microsoft.com/en-us/library/windows/desktop/hh706636.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool get_method_properties(
            _In_                                   DWORD                     dwVersion,
            _In_                                   DWORD                     dwFlags,
            _In_                                   HANDLE                    hUserImpersonationToken,
            _In_count_(dwConnectionDataSize) const BYTE                      *pConnectionData,
            _In_                                   DWORD                     dwConnectionDataSize,
            _In_count_(dwUserDataSize)       const BYTE                      *pUserData,
            _In_                                   DWORD                     dwUserDataSize,
            _Out_                                  EAP_METHOD_PROPERTY_ARRAY *pMethodPropertyArray,
            _Out_                                  EAP_ERROR                 **ppEapError);

        ///
        /// Converts XML into the configuration BLOB. The XML based credentials can come from group policy or from a system administrator.
        ///
        /// \sa [EapPeerCredentialsXml2Blob function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363603.aspx)
        ///
        virtual bool credentials_xml2blob(
            _In_                                   DWORD       dwFlags,
            _In_                                   IXMLDOMNode *pConfigRoot,
            _In_count_(dwConnectionDataSize) const BYTE        *pConnectionData,
            _In_                                   DWORD       dwConnectionDataSize,
            _Out_                                  BYTE        **ppCredentialsOut,
            _Out_                                  DWORD       *pdwCredentialsOutSize,
            _Out_                                  EAP_ERROR   **ppEapError);
    };
}
