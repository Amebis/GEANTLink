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


//////////////////////////////////////////////////////////////////////
// eap::peer_ttls_ui
//////////////////////////////////////////////////////////////////////

eap::peer_ttls_ui::peer_ttls_ui() : peer_ui<eap::config_ttls, eap::credentials_ttls, int, int>(type_ttls)
{
}


bool eap::peer_ttls_ui::invoke_config_ui(
    _In_    HWND        hwndParent,
    _Inout_ config_type &cfg,
    _Out_   EAP_ERROR   **ppEapError)
{
    UNREFERENCED_PARAMETER(ppEapError);

    // Initialize application.
    new wxApp();
    wxEntryStart(m_instance);

    int result;
    {
        // Create wxWidget-approved parent window.
        wxWindow parent;
        parent.SetHWND((WXHWND)hwndParent);
        parent.AdoptAttributesFromHWND();
        wxTopLevelWindows.Append(&parent);

        // Create and launch configuration dialog.
        wxEAPConfigDialog<config_ttls, wxEAPTTLSConfig<provider_config_type> > dlg(cfg, &parent);
        result = dlg.ShowModal();

        wxTopLevelWindows.DeleteObject(&parent);
        parent.SetHWND((WXHWND)NULL);
    }

    // Clean-up and return.
    wxEntryCleanup();
    if (result != wxID_OK) {
        *ppEapError = make_error(ERROR_CANCELLED, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Cancelled."), NULL);
        return false;
    }

    return true;
}


bool eap::peer_ttls_ui::invoke_identity_ui(
            _In_    HWND          hwndParent,
            _In_    DWORD         dwFlags,
            _Inout_ config_type   &cfg,
            _Inout_ identity_type &usr,
            _Out_   LPWSTR        *ppwszIdentity,
            _Out_   EAP_ERROR     **ppEapError)
{
    UNREFERENCED_PARAMETER(dwFlags);
    UNREFERENCED_PARAMETER(cfg);
    UNREFERENCED_PARAMETER(usr);
    UNREFERENCED_PARAMETER(ppwszIdentity);
    UNREFERENCED_PARAMETER(ppEapError);

    InitCommonControls();
    MessageBox(hwndParent, _T(PRODUCT_NAME_STR) _T(" credential prompt goes here!"), _T(PRODUCT_NAME_STR) _T(" Credentials"), MB_OK);

    return true;
}


bool eap::peer_ttls_ui::invoke_interactive_ui(
            _In_        HWND                      hwndParent,
            _In_  const interactive_request_type  &req,
            _Out_       interactive_response_type &res,
            _Out_       EAP_ERROR                 **ppEapError)
{
    UNREFERENCED_PARAMETER(req);
    UNREFERENCED_PARAMETER(res);
    UNREFERENCED_PARAMETER(ppEapError);

    InitCommonControls();
    MessageBox(hwndParent, _T(PRODUCT_NAME_STR) _T(" interactive UI goes here!"), _T(PRODUCT_NAME_STR) _T(" Prompt"), MB_OK);

    return true;
}
