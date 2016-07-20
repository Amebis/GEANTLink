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

#include "StdAfx.h"

using namespace std;
using namespace winstd;


//////////////////////////////////////////////////////////////////////
// eap::peer_ttls
//////////////////////////////////////////////////////////////////////

eap::peer_ttls::peer_ttls() : peer<config_method_ttls, credentials_ttls, bool, bool>(type_ttls)
{
}


bool eap::peer_ttls::initialize(_Out_ EAP_ERROR **ppEapError)
{
    UNREFERENCED_PARAMETER(ppEapError);

    // MSI's feature completeness check removed: It might invoke UI (prompt user for missing MSI),
    // which would be disasterous in EapHost system service.
#if 0
    // Perform the Microsoft Installer's feature completeness check manually.
    // If execution got this far in the first place (dependent DLLs are present and loadable).
    // Furthermore, this increments program usage counter.
    if (MsiQueryFeatureState(_T(PRODUCT_VERSION_GUID), _T("featEAPTTLS")) != INSTALLSTATE_UNKNOWN)
        MsiUseFeature(_T(PRODUCT_VERSION_GUID), _T("featEAPTTLS"));
#endif

    return true;
}


bool eap::peer_ttls::shutdown(_Out_ EAP_ERROR **ppEapError)
{
    UNREFERENCED_PARAMETER(ppEapError);
    return true;
}


bool eap::peer_ttls::get_identity(
    _In_          DWORD         dwFlags,
    _In_    const config_type   &cfg,
    _Inout_       identity_type &usr,
    _In_          HANDLE        hTokenImpersonateUser,
    _Out_         BOOL          *pfInvokeUI,
    _Out_         WCHAR         **ppwszIdentity,
    _Out_         EAP_ERROR     **ppEapError)
{
    UNREFERENCED_PARAMETER(dwFlags);
    UNREFERENCED_PARAMETER(cfg);
    UNREFERENCED_PARAMETER(usr);
    UNREFERENCED_PARAMETER(hTokenImpersonateUser);
    UNREFERENCED_PARAMETER(pfInvokeUI);
    UNREFERENCED_PARAMETER(ppwszIdentity);
    UNREFERENCED_PARAMETER(ppEapError);

    *ppEapError = make_error(ERROR_NOT_SUPPORTED, _T(__FUNCTION__) _T(" Not supported."));
    return false;
}


bool eap::peer_ttls::get_method_properties(
    _In_        DWORD                     dwVersion,
    _In_        DWORD                     dwFlags,
    _In_        HANDLE                    hUserImpersonationToken,
    _In_  const config_type               &cfg,
    _In_  const identity_type             &usr,
    _Out_       EAP_METHOD_PROPERTY_ARRAY *pMethodPropertyArray,
    _Out_       EAP_ERROR                 **ppEapError) const
{
    UNREFERENCED_PARAMETER(dwVersion);
    UNREFERENCED_PARAMETER(dwFlags);
    UNREFERENCED_PARAMETER(hUserImpersonationToken);
    UNREFERENCED_PARAMETER(cfg);
    UNREFERENCED_PARAMETER(usr);
    UNREFERENCED_PARAMETER(pMethodPropertyArray);
    UNREFERENCED_PARAMETER(ppEapError);

    *ppEapError = make_error(ERROR_NOT_SUPPORTED, _T(__FUNCTION__) _T(" Not supported."));
    return false;
}
