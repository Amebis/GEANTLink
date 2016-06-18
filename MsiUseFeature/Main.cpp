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
    if (MsiUseFeatureW(_L(PRODUCT_VERSION_GUID), pwcArglist[1]) != INSTALLSTATE_LOCAL) {
        OutputDebugStr(_T("The feature is not installed locally.\n"));
        return 2;
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
