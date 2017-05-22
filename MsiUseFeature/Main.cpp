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

#pragma comment(lib, "Msi.lib")

using namespace std;
using namespace winstd;


static int MsiUseFeature()
{
    int nArgs;
    unique_ptr<LPWSTR[], LocalFree_delete<LPWSTR[]> > pwcArglist(CommandLineToArgvW(GetCommandLineW(), &nArgs));
    if (pwcArglist == NULL) {
        OutputDebugStr(_T("CommandLineToArgvW failed (error %u).\n"), GetLastError());
        return 1;
    }

    if (nArgs < 2) {
        OutputDebugStr(_T("Not enough parameters.\n"));
        return -1;
    }

    // Query the feature state.
    if (MsiQueryFeatureStateW(_L(PRODUCT_VERSION_GUID), pwcArglist[1]) == INSTALLSTATE_UNKNOWN) {
        OutputDebugStr(_T("The product is not installed or feature state is unknown.\n"));
        return 1;
    }

    // Perform the Microsoft Installer's feature completeness check.
    switch (MsiUseFeatureW(_L(PRODUCT_VERSION_GUID), pwcArglist[1])) {
    case INSTALLSTATE_LOCAL:
        // All components of the feature were checked and present.
        break;

    case INSTALLSTATE_BROKEN: {
        // Some of the components are reported missing.
        //
        // Unfortunately, the feature state is falsely reported as broken, when MsiUseFeature() lacks privilege
        // to check the presence of at least one component installed in an inaccessible folder or registry key.
        // If our process is not elevated and feature does contain such components, this is the expected result.
        // However, even when we are "Run as Administrator", this does not guarantee we can access all the
        // components. Some might be restricted from Administrators group aswell.
        win_handle token;
        TOKEN_ELEVATION Elevation; DWORD dwSize;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) &&
            GetTokenInformation(token, TokenElevation, &Elevation, sizeof(Elevation), &dwSize) &&
            !Elevation.TokenIsElevated)
        {
            // We are not elevated.
            OutputDebugStr(_T("The feature is reported broken and the elevation is required for a more reliable test. Silently assuming the feature is complete.\n"));
            break;
        }
    }

    default:
        OutputDebugStr(_T("The feature is not installed locally.\n"));
        return 2;
    }

    if (nArgs > 2) {
        reg_key key;
        if (!key.open(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\") _T(VENDOR_NAME_STR) _T("\\") _T(PRODUCT_NAME_STR), 0, KEY_READ)) {
            OutputDebugStr(_T("Product registry key cannot be opened (error %u).\n"), GetLastError());
            return 3;
        }

        wstring lang;
        LSTATUS s = RegQueryStringValue(key, _T("Language"), lang);
        if (s != ERROR_SUCCESS) {
            OutputDebugStr(_T("Error reading registry value (error %u).\n"), s);
            return 3;
        }

        if (_wcsicmp(pwcArglist[2], lang.c_str()) != 0) {
            OutputDebugStr(_T("Different language (%ls, %ls).\n"), pwcArglist[2], lang.c_str());
            return 3;
        }
    }

    return 0;
}


int CALLBACK WinMain(_In_ HINSTANCE hInstance, _In_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nCmdShow)
{
    UNREFERENCED_PARAMETER(hInstance);
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);

    int res = MsiUseFeature();
    assert(!_CrtDumpMemoryLeaks());
    return res;
}
