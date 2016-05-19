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

#pragma comment(lib, "Crypt32.lib")

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
    string password_enc;
    {
        // Convert Base64 >> UTF-8.
        sanitizing_vector<char> password;
        base64_dec dec;
        bool is_last;
        dec.decode(password, is_last, pwcArglist[2], (size_t)-1);

        // Prepare cryptographics provider.
        crypt_prov cp;
        if (!cp.create(NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            OutputDebugStr(_T("CryptAcquireContext failed (error %u).\n"), GetLastError());
            return 2;
        }

        // Import the public key.
        HRSRC res = FindResource(NULL, MAKEINTRESOURCE(1), RT_RCDATA);
        assert(res);
        HGLOBAL res_handle = LoadResource(NULL, res);
        assert(res_handle);
        crypt_key key;
        unique_ptr<CERT_PUBLIC_KEY_INFO, LocalFree_delete<CERT_PUBLIC_KEY_INFO> > keyinfo_data;
        DWORD keyinfo_size = 0;
        if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, (const BYTE*)::LockResource(res_handle), ::SizeofResource(NULL, res), CRYPT_DECODE_ALLOC_FLAG, NULL, &keyinfo_data, &keyinfo_size) ||
            !key.import_public(cp, X509_ASN_ENCODING, keyinfo_data.get()))
        {
            OutputDebugStr(_T("Public key import failed (error %u).\n"), GetLastError());
            return 2;
        }

        // Pre-allocate memory to allow space, as encryption will grow the data, and we need additional 16B at the end for MD5 hash.
        DWORD dwBlockLen;
        if (!CryptGetKeyParam(key, KP_BLOCKLEN, dwBlockLen, 0)) dwBlockLen = 0;
        password.reserve((password.size() + dwBlockLen - 1) / dwBlockLen * dwBlockLen + 16);

        // Encrypt the password using our public key. Calculate MD5 hash and append it.
        crypt_hash hash;
        if (!hash.create(cp, CALG_MD5)) {
            OutputDebugStr(_T("Creating MD5 hash failed (error %u).\n"), GetLastError());
            return 2;
        }
        if (!CryptEncrypt(key, hash, TRUE, 0, password)) {
            OutputDebugStr(_T("Encrypting password failed (error %u).\n"), GetLastError());
            return 2;
        }
        vector<char> hash_bin;
        CryptGetHashParam(hash, HP_HASHVAL, hash_bin, 0);
        password.insert(password.end(), hash_bin.begin(), hash_bin.end());

        // Convert encrypted password to Base64, since CredProtectA() fail for binary strings.
        string password_base64;
        base64_enc enc;
        enc.encode(password_base64, password.data(), password.size());

        // Encrypt the password using user's key.
        CRED_PROTECTION_TYPE cpt;
        if (!CredProtectA(TRUE, password_base64.c_str(), (DWORD)password_base64.length(), password_enc, &cpt)) {
            OutputDebugStr(_T("CredProtect failed (error %u).\n"), GetLastError());
            return 2;
        }
    }
    assert(password_enc.size()*sizeof(char) < CRED_MAX_CREDENTIAL_BLOB_SIZE);

    // Write credentials.
    CREDENTIAL cred = {
        0,                                          // Flags
        CRED_TYPE_GENERIC,                          // Type
        (LPWSTR)target_name.c_str(),                // TargetName
        _T(""),                                     // Comment
        { 0, 0 },                                   // LastWritten
        (DWORD)password_enc.size()*sizeof(char),    // CredentialBlobSize
        (LPBYTE)password_enc.data(),                // CredentialBlob
        CRED_PERSIST_ENTERPRISE,                    // Persist
        0,                                          // AttributeCount
        NULL,                                       // Attributes
        NULL,                                       // TargetAlias
        pwcArglist[1]                               // UserName
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

