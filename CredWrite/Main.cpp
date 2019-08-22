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

eap::module g_module;


static int CredWrite()
{
    int nArgs;
    unique_ptr<LPWSTR[], LocalFree_delete<LPWSTR[]> > pwcArglist(CommandLineToArgvW(GetCommandLineW(), &nArgs));
    if (pwcArglist == NULL) {
        OutputDebugStr(_T("CommandLineToArgvW failed (error %u).\n"), GetLastError());
        return 1;
    }

    if (nArgs < 3) {
        OutputDebugStr(_T("Not enough parameters.\n"));
        return -1;
    }

    eap::credentials_pass cred_pass(g_module);

    // Prepare identity (user name).
    {
        // Convert Base64 >> UTF-8.
        vector<char> identity_utf8;
        base64_dec dec;
        bool is_last;
        dec.decode(identity_utf8, is_last, pwcArglist[1], (size_t)-1);

        MultiByteToWideChar(CP_UTF8, 0, identity_utf8.data(), (int)identity_utf8.size(), cred_pass.m_identity);
    }

    // Prepare password.
    {
        // Convert Base64 >> UTF-8.
        vector<char, sanitizing_allocator<char> > password_utf8;
        base64_dec dec;
        bool is_last;
        dec.decode(password_utf8, is_last, pwcArglist[2], (size_t)-1);

        MultiByteToWideChar(CP_UTF8, 0, password_utf8.data(), (int)password_utf8.size(), cred_pass.m_password);
    }

    // Generate target name (aka realm).
    wstring target_name;
    if (nArgs > 3) {
        // User explicitly set the realm.
        target_name = pwcArglist[3];
    } else {
        // Get the realm from user name.
        LPCWSTR _identity = cred_pass.m_identity.c_str(), domain;
        if ((domain = wcschr(_identity, L'@')) != NULL) {
            target_name  = L"urn:RFC4282:realm:";
            target_name += domain + 1;
        } else
            target_name = L"*";
    }

    // Determine credential level.
    unsigned int level;
    if (nArgs > 4) {
        // User explicitly set the level.
        level = wcstoul(pwcArglist[4], NULL, 10);
    } else {
        // Set default level.
        level = 0;
    }

    // Write credentials.
#ifdef _DEBUG
    {
        eap::credentials_pass cred_stored(g_module);
        try {
            cred_stored.retrieve(target_name.c_str(), level);
        } catch(win_runtime_error &err) {
            OutputDebugStr(_T("%hs (error %u)\n"), err.what(), err.number());
        } catch(...) {
            OutputDebugStr(_T("Reading credentials failed.\n"));
        }
    }
#endif
    try {
        cred_pass.store(target_name.c_str(), level);
    } catch(win_runtime_error &err) {
        OutputDebugStr(_T("%hs (error %u)\n"), err.what(), err.number());
        return 2;
    } catch(...) {
        OutputDebugStr(_T("Writing credentials failed.\n"));
        return 2;
    }

    return 0;
}


_Use_decl_annotations_
int CALLBACK WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);

    g_module.m_instance = hInstance;

    int res = CredWrite();
    assert(!_CrtDumpMemoryLeaks());
    return res;
}
