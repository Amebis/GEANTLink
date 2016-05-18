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

    // Generate target name (aka realm).
    tstring target_name(_T(PRODUCT_NAME_STR) _T("/"));
    if (nArgs > 3) {
        // User explicitly set the realm.
        target_name += pwcArglist[3];
    } else {
        // Get the realm from user name.
        LPCTSTR domain = _tcschr(pwcArglist[1], _T('@'));
        target_name += domain ? ++domain : _T("*");
    }
    assert(target_name.length() < CRED_MAX_GENERIC_TARGET_NAME_LENGTH);

    // Prepare password.
    string password_enc_utf8;
    {
        // Convert Base64 >> UTF-8.
        sanitizing_vector<char> password_utf8;
        base64_dec dec;
        bool is_last;
        dec.decode(password_utf8, is_last, pwcArglist[2], (size_t)-1);

        // Convert UTF-8 >> UTF-16.
        sanitizing_wstring password;
        MultiByteToWideChar(CP_UTF8, 0, password_utf8.data(), (int)password_utf8.size(), password);

        // Encrypt the password.
        wstring password_enc;
        CRED_PROTECTION_TYPE cpt;
        if (!CredProtect(TRUE, password.data(), (DWORD)password.size(), password_enc, &cpt)) {
            OutputDebugStr(_T("CredProtect failed (error %u).\n"), GetLastError());
            return 2;
        }

        // Convert UTF-16 >> UTF-8.
        WideCharToMultiByte(CP_UTF8, 0, password_enc.data(), (int)password_enc.size(), password_enc_utf8, NULL, NULL);
    }
    assert(password_enc_utf8.size()*sizeof(char) < CRED_MAX_CREDENTIAL_BLOB_SIZE);

    // Write credentials.
    CREDENTIAL cred = {
        0,                                              // Flags
        CRED_TYPE_GENERIC,                              // Type
        (LPWSTR)target_name.c_str(),                    // TargetName
        _T(""),                                         // Comment
        { 0, 0 },                                       // LastWritten
        (DWORD)password_enc_utf8.size()*sizeof(char),   // CredentialBlobSize
        (LPBYTE)password_enc_utf8.data(),               // CredentialBlob
        CRED_PERSIST_ENTERPRISE,                        // Persist
        0,                                              // AttributeCount
        NULL,                                           // Attributes
        NULL,                                           // TargetAlias
        pwcArglist[1]                                   // UserName
    };
    if (!CredWrite(&cred, 0)) {
        OutputDebugStr(_T("CredWrite failed (error %u).\n"), GetLastError());
        return 3;
    }

    return 0;
}


int CALLBACK WinMain(_In_ HINSTANCE hInstance, _In_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nCmdShow)
{
    UNREFERENCED_PARAMETER(hInstance);
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);

    int res = CredWrite();
    assert(!_CrtDumpMemoryLeaks());
    return res;
}

