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

#pragma comment(lib, "Crypt32.lib")

using namespace std;
using namespace winstd;


//////////////////////////////////////////////////////////////////////
// eap::credentials
//////////////////////////////////////////////////////////////////////

eap::credentials::credentials(_In_ module &mod) : config(mod)
{
}


eap::credentials::credentials(_In_ const credentials &other) :
    m_identity(other.m_identity),
    config(other)
{
}


eap::credentials::credentials(_Inout_ credentials &&other) :
    m_identity(std::move(other.m_identity)),
    config(std::move(other))
{
}


eap::credentials& eap::credentials::operator=(_In_ const credentials &other)
{
    if (this != &other) {
        (config&)*this = other;
        m_identity     = other.m_identity;
    }

    return *this;
}


eap::credentials& eap::credentials::operator=(_Inout_ credentials &&other)
{
    if (this != &other) {
        (config&)*this = std::move(other);
        m_identity     = std::move(other.m_identity);
    }

    return *this;
}


void eap::credentials::clear()
{
    m_identity.clear();
}


bool eap::credentials::empty() const
{
    return m_identity.empty();
}


DWORD eap::credentials::save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError) const
{
    UNREFERENCED_PARAMETER(pDoc);
    UNREFERENCED_PARAMETER(pConfigRoot);
    UNREFERENCED_PARAMETER(ppEapError);

    // Yeah, right!? Credentials are non-exportable!
    return ERROR_NOT_SUPPORTED;
}


DWORD eap::credentials::encrypt(_In_ HCRYPTPROV hProv, _In_bytecount_(size) const void *data, _In_ size_t size, _Out_ std::vector<unsigned char> &enc, _Out_ EAP_ERROR **ppEapError, _Out_opt_ HCRYPTHASH hHash) const
{
    assert(ppEapError);
    DWORD dwResult;

    // Import the public key.
    HRSRC res = FindResource(m_module.m_instance, MAKEINTRESOURCE(IDR_EAP_KEY_PUBLIC), RT_RCDATA);
    assert(res);
    HGLOBAL res_handle = LoadResource(m_module.m_instance, res);
    assert(res_handle);
    crypt_key key;
    unique_ptr<CERT_PUBLIC_KEY_INFO, LocalFree_delete<CERT_PUBLIC_KEY_INFO> > keyinfo_data;
    DWORD keyinfo_size = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, (const BYTE*)::LockResource(res_handle), ::SizeofResource(m_module.m_instance, res), CRYPT_DECODE_ALLOC_FLAG, NULL, &keyinfo_data, &keyinfo_size)) {
        *ppEapError = m_module.make_error(dwResult = GetLastError(), 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" CryptDecodeObjectEx failed."), NULL);
        return dwResult;
    }

    if (!key.import_public(hProv, X509_ASN_ENCODING, keyinfo_data.get())) {
        *ppEapError = m_module.make_error(dwResult = GetLastError(), 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Public key import failed."), NULL);
        return dwResult;
    }

    // Pre-allocate memory to allow space, as encryption will grow the data.
    DWORD dwBlockLen;
    vector<unsigned char, sanitizing_allocator<unsigned char> > buf(size);
    memcpy(buf.data(), data, size);
    if (!CryptGetKeyParam(key, KP_BLOCKLEN, dwBlockLen, 0)) dwBlockLen = 0;
    buf.reserve((size + dwBlockLen - 1) / dwBlockLen * dwBlockLen);

    // Encrypt the data using our public key.
    if (!CryptEncrypt(key, hHash, TRUE, 0, buf)) {
        *ppEapError = m_module.make_error(dwResult = GetLastError(), 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Encrypting data failed."), NULL);
        return dwResult;
    }

    // Copy encrypted data.
    enc.assign(buf.begin(), buf.end());

    return ERROR_SUCCESS;
}


//////////////////////////////////////////////////////////////////////
// eap::credentials_pass
//////////////////////////////////////////////////////////////////////

eap::credentials_pass::credentials_pass(_In_ module &mod) : credentials(mod)
{
}


eap::credentials_pass::credentials_pass(_In_ const credentials_pass &other) :
    m_password(other.m_password),
    credentials(other)
{
}


eap::credentials_pass::credentials_pass(_Inout_ credentials_pass &&other) :
    m_password(std::move(other.m_password)),
    credentials(std::move(other))
{
}


eap::credentials_pass& eap::credentials_pass::operator=(_In_ const credentials_pass &other)
{
    if (this != &other) {
        (credentials&)*this = other;
        m_password          = other.m_password;
    }

    return *this;
}


eap::credentials_pass& eap::credentials_pass::operator=(_Inout_ credentials_pass &&other)
{
    if (this != &other) {
        (credentials&)*this = std::move(other);
        m_password          = std::move(other.m_password);
    }

    return *this;
}


void eap::credentials_pass::clear()
{
    credentials::clear();
    m_password.clear();
}


bool eap::credentials_pass::empty() const
{
    return credentials::empty() && m_password.empty();
}


DWORD eap::credentials_pass::load(_In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError)
{
    assert(pConfigRoot);
    UNREFERENCED_PARAMETER(ppEapError);

    eapxml::get_element_value(pConfigRoot, bstr(L"eap-metadata:UserName"), m_identity);

    bstr pass;
    if ((eapxml::get_element_value(pConfigRoot, bstr(L"eap-metadata:Password"), &pass)) == ERROR_SUCCESS)
        m_password = pass;
    SecureZeroMemory((BSTR)pass, sizeof(OLECHAR)*pass.length());

    return ERROR_SUCCESS;
}


DWORD eap::credentials_pass::store(_In_ LPCTSTR pszTargetName, _Out_ EAP_ERROR **ppEapError) const
{
    assert(pszTargetName);
    assert(ppEapError);
    DWORD dwResult;
    string password_enc;

    // Prepare cryptographics provider.
    crypt_prov cp;
    if (!cp.create(NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        *ppEapError = m_module.make_error(dwResult = GetLastError(), 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" CryptAcquireContext failed."), NULL);
        return dwResult;
    }

    // Convert password to UTF-8.
    sanitizing_string password_utf8;
    WideCharToMultiByte(CP_UTF8, 0, m_password.c_str(), (int)m_password.length(), password_utf8, NULL, NULL);

    // Create hash.
    crypt_hash hash;
    if (!hash.create(cp, CALG_MD5)) {
        *ppEapError = m_module.make_error(dwResult = GetLastError(), 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Creating MD5 hash failed."), NULL);
        return dwResult;
    }

    // Encrypt password.
    vector<unsigned char> password;
    if ((dwResult = encrypt(cp, password_utf8.c_str(), password_utf8.length()*sizeof(sanitizing_string::value_type), password, ppEapError, hash)) != ERROR_SUCCESS)
        return dwResult;

    // Calculate MD5 hash and append it.
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
        *ppEapError = m_module.make_error(dwResult = GetLastError(), 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" CredProtect failed."), NULL);
        return dwResult;
    }

    tstring target(target_name(pszTargetName));

    // Write credentials.
    assert(password_enc.size()*sizeof(char) < CRED_MAX_CREDENTIAL_BLOB_SIZE);
    assert(m_identity.length()              < CRED_MAX_USERNAME_LENGTH     );
    CREDENTIAL cred = {
        0,                                          // Flags
        CRED_TYPE_GENERIC,                          // Type
        (LPTSTR)target.c_str(),                     // TargetName
        _T(""),                                     // Comment
        { 0, 0 },                                   // LastWritten
        (DWORD)password_enc.size()*sizeof(char),    // CredentialBlobSize
        (LPBYTE)password_enc.data(),                // CredentialBlob
        CRED_PERSIST_ENTERPRISE,                    // Persist
        0,                                          // AttributeCount
        NULL,                                       // Attributes
        NULL,                                       // TargetAlias
        (LPTSTR)m_identity.c_str()                  // UserName
    };
    if (!CredWrite(&cred, 0)) {
        *ppEapError = m_module.make_error(dwResult = GetLastError(), 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" CredWrite failed."), NULL);
        return dwResult;
    }

    return ERROR_SUCCESS;
}


DWORD eap::credentials_pass::retrieve(_In_ LPCTSTR pszTargetName, _Out_ EAP_ERROR **ppEapError)
{
    assert(pszTargetName);
    DWORD dwResult;

    // Read credentials.
    unique_ptr<CREDENTIAL, CredFree_delete<CREDENTIAL> > cred;
    if (!CredRead(target_name(pszTargetName).c_str(), CRED_TYPE_GENERIC, 0, (PCREDENTIAL*)&cred)) {
        *ppEapError = m_module.make_error(dwResult = GetLastError(), 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" CredRead failed."), NULL);
        return dwResult;
    }

    m_identity = cred->UserName;

    // Decrypt the password using user's key.
    string password_base64;
    if (!CredUnprotectA(TRUE, (LPCSTR)(cred->CredentialBlob), cred->CredentialBlobSize/sizeof(char), password_base64)) {
        *ppEapError = m_module.make_error(dwResult = GetLastError(), 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" CredUnprotect failed."), NULL);
        return dwResult;
    }

    // Convert Base64 to binary encrypted password, since CredProtectA() fail for binary strings.
    vector<char, sanitizing_allocator<char> > password;
    base64_dec dec;
    bool is_last;
    dec.decode(password, is_last, password_base64.c_str(), password_base64.length());

    // Prepare cryptographics provider.
    crypt_prov cp;
    if (!cp.create(NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        *ppEapError = m_module.make_error(dwResult = GetLastError(), 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" CryptAcquireContext failed."), NULL);
        return dwResult;
    }

    // Create hash.
    crypt_hash hash;
    if (!hash.create(cp, CALG_MD5)) {
        *ppEapError = m_module.make_error(dwResult = GetLastError(), 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Creating MD5 hash failed."), NULL);
        return dwResult;
    }
    DWORD dwHashSize, dwHashSizeSize = sizeof(dwHashSize);
    CryptGetHashParam(hash, HP_HASHSIZE, (LPBYTE)&dwHashSize, &dwHashSizeSize, 0);
    if (password.size() < dwHashSize) {
        *ppEapError = m_module.make_error(dwResult = ERROR_INVALID_DATA, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Encrypted password too short."), NULL);
        return dwResult;
    }

    // Extract hash from encrypted password.
    vector<char> hash_bin;
    size_t enc_size = password.size() - dwHashSize;
    hash_bin.assign(password.begin() + enc_size, password.end());

    // Decrypt password.
    if ((dwResult = decrypt(cp, password.data(), enc_size, password, ppEapError, hash)) != ERROR_SUCCESS)
        return dwResult;

    // Calculate MD5 hash and verify it.
    vector<char> hash2_bin;
    CryptGetHashParam(hash, HP_HASHVAL, hash2_bin, 0);
    if (hash_bin != hash2_bin) {
        *ppEapError = m_module.make_error(dwResult = ERROR_INVALID_DATA, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Invalid password data."), NULL);
        return dwResult;
    }

    // Convert password from UTF-8.
    MultiByteToWideChar(CP_UTF8, 0, password.data(), (int)password.size(), m_password);

    return ERROR_SUCCESS;
}
