/*
    Copyright 2015-2020 Amebis
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
    class peer_ttls_ui;
}

#pragma once

#include "../../TTLS/include/Config.h"
#include "../../TTLS/include/Credentials.h"
#include "../../EAPBase_UI/include/Module.h"
#include "../../EAPBase_UI/include/wxEAP_UIBase.h"


namespace eap
{
    /// \addtogroup EAPBaseModule
    /// @{

    ///
    /// PEAP UI peer
    ///
    class peer_peap_ui : public peer_ui
    {
    public:
        ///
        /// Constructs a PEAP UI peer module
        ///
        peer_peap_ui();

    protected:
        ///
        /// Constructs a peer module
        ///
        /// \param[in] eap_method  EAP method type ID
        /// \param[in] domain      Localization catalog domain name. Usually EAP method name followed by "_UI".
        ///
        peer_peap_ui(_In_ winstd::eap_type_t eap_method, _In_opt_ LPCTSTR domain);

    public:
        virtual void invoke_config_ui(
            _In_                                     HWND  hwndParent,
            _In_count_(dwConnectionDataInSize) const BYTE  *pConnectionDataIn,
            _In_                                     DWORD dwConnectionDataInSize,
            _Out_                                    BYTE  **ppConnectionDataOut,
            _Out_                                    DWORD *pdwConnectionDataOutSize);

        virtual void invoke_identity_ui(
            _In_                                   HWND   hwndParent,
            _In_                                   DWORD  dwFlags,
            _In_count_(dwConnectionDataSize) const BYTE   *pConnectionData,
            _In_                                   DWORD  dwConnectionDataSize,
            _In_count_(dwUserDataSize)       const BYTE   *pUserData,
            _In_                                   DWORD  dwUserDataSize,
            _Out_                                  BYTE   **ppUserDataOut,
            _Out_                                  DWORD  *pdwUserDataOutSize,
            _Out_                                  LPWSTR *ppwszIdentity);

        virtual void invoke_interactive_ui(
            _In_                                  HWND  hwndParent,
            _In_count_(dwUIContextDataSize) const BYTE  *pUIContextData,
            _In_                                  DWORD dwUIContextDataSize,
            _Inout_                               BYTE  **ppDataFromInteractiveUI,
            _Inout_                               DWORD *pdwDataFromInteractiveUISize);

    protected:
        virtual wxEAPCredentialsPanelBase* make_inner_credential_panel(const config_provider &prov, const config_method_with_cred &cfg, credentials *cred, wxWindow *parent) const;
    };

    ///
    /// EAP-TTLS UI peer
    ///
    class peer_ttls_ui : public peer_peap_ui
    {
    public:
        ///
        /// Constructs a EAP-TTLS UI peer module
        ///
        peer_ttls_ui();

        ///
        /// @copydoc eap::method::make_config()
        /// \returns This implementation always returns `eap::config_method_ttls` type of configuration
        ///
        virtual config_method* make_config();

        virtual void invoke_config_ui(
            _In_                                     HWND  hwndParent,
            _In_count_(dwConnectionDataInSize) const BYTE  *pConnectionDataIn,
            _In_                                     DWORD dwConnectionDataInSize,
            _Out_                                    BYTE  **ppConnectionDataOut,
            _Out_                                    DWORD *pdwConnectionDataOutSize);

    protected:
        virtual wxEAPCredentialsPanelBase* make_inner_credential_panel(const config_provider &prov, const config_method_with_cred &cfg, credentials *cred, wxWindow *parent) const;
    };

    /// @}
}
