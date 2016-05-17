/*
    Copyright 2015-2016 Amebis
    Copyright 2016 GÉANT

    This file is part of GEANTLink.

    GEANTLink is free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    GEANTLink is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with GEANTLink. If not, see <http://www.gnu.org/licenses/>.
*/

#include "StdAfx.h"

using namespace std;
using namespace winstd;


int CALLBACK WinMain(_In_ HINSTANCE hInstance, _In_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nCmdShow)
{
    UNREFERENCED_PARAMETER(hInstance);
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);

    int nArgs;
    unique_ptr<LPWSTR[], LocalFree_delete<LPWSTR[]> > pwcArglist(CommandLineToArgvW(GetCommandLineW(), &nArgs));
    if (pwcArglist == NULL) {
        OutputDebugStr(_T("CommandLineToArgvW failed (error %i).\n"), GetLastError());
        return 1;
    }

    if (nArgs < 3) {
        OutputDebugStr(_T("Not enough parameters.\n"));
        return -1;
    }

    // Decode password (Base64 >> UTF-8 >> UTF-16).
    sanitizing_vector<char> password_utf8;
    {
        base64_dec dec;
        bool is_last;
        dec.decode(password_utf8, is_last, pwcArglist[2], (size_t)-1);
    }
    sanitizing_wstring password;
    MultiByteToWideChar(CP_UTF8, 0, password_utf8.data(), (int)password_utf8.size(), password);

    return 0;
}
