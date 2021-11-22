/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2020 Amebis
    Copyright © 2016 GÉANT
*/

#include "PCH.h"

using namespace std;
using namespace winstd;

class module_dummy : public eap::module {
    virtual eap::config_method* make_config() { return nullptr; }
} g_module;


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

    _CrtSetDbgFlag(_crtDbgFlag | _CRTDBG_ALLOC_MEM_DF | _CRTDBG_CHECK_ALWAYS_DF | _CRTDBG_CHECK_CRT_DF | _CRTDBG_LEAK_CHECK_DF);
    g_module.m_instance = hInstance;

    int res = CredWrite();
    return res;
}
