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

#include <sal.h>

namespace eap
{
    ///
    /// Base class for method credential storage
    ///
    class credentials;

    ///
    /// Password based method credentials
    ///
    class credentials_pass;
}

namespace eapserial
{
    ///
    /// Packs a method credentials
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     Credentials to pack
    ///
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const eap::credentials &val);

    ///
    /// Returns packed size of a method credentials
    ///
    /// \param[in] val  Credentials to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    inline size_t get_pk_size(const eap::credentials &val);

    ///
    /// Unpacks a method credentials
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[out]   val     Credentials to unpack to
    ///
    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ eap::credentials &val);

    ///
    /// Packs a password based method credentials
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     Credentials to pack
    ///
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const eap::credentials_pass &val);

    ///
    /// Returns packed size of a password based method credentials
    ///
    /// \param[in] val  Credentials to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    inline size_t get_pk_size(const eap::credentials_pass &val);

    ///
    /// Unpacks a password based method credentials
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[out]   val     Credentials to unpack to
    ///
    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ eap::credentials_pass &val);
}

#pragma once

#include "Config.h"
#include "Module.h"
#include "EAPSerial.h"

#include "../../../include/Version.h"

#include <WinStd/Common.h>

#include <Windows.h>
#include <eaptypes.h> // Must include after <Windows.h>
#include <tchar.h>
#include <wincred.h>

#include <string>


namespace eap
{
    class credentials : public config
    {
    public:
        ///
        /// Constructs credentials
        ///
        /// \param[in] mod  Reference of the EAP module to use for global services
        ///
        credentials(_In_ module &mod);

        ///
        /// Copies credentials
        ///
        /// \param[in] other  Credentials to copy from
        ///
        credentials(_In_ const credentials &other);

        ///
        /// Moves credentials
        ///
        /// \param[in] other  Credentials to move from
        ///
        credentials(_Inout_ credentials &&other);

        ///
        /// Copies credentials
        ///
        /// \param[in] other  Credentials to copy from
        ///
        /// \returns Reference to this object
        ///
        credentials& operator=(_In_ const credentials &other);

        ///
        /// Moves credentials
        ///
        /// \param[in] other  Configuration to move from
        ///
        /// \returns Reference to this object
        ///
        credentials& operator=(_Inout_ credentials &&other);

        ///
        /// Resets credentials
        ///
        virtual void clear();

        ///
        /// Test credentials if blank
        ///
        virtual bool empty() const;

        /// \name Storage
        /// @{

        ///
        /// Save credentials to Windows Credential Manager
        ///
        /// \param[in]  pszTargetName  The name in Windows Credential Manager to store credentials as
        /// \param[out] ppEapError     Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c ERROR_SUCCESS if succeeded
        /// - error code otherwise
        ///
        virtual DWORD store(_In_ LPCTSTR pszTargetName, _Out_ EAP_ERROR **ppEapError) const = 0;

        ///
        /// Retrieve credentials from Windows Credential Manager
        ///
        /// \param[in]  pszTargetName  The name in Windows Credential Manager to retrieve credentials from
        /// \param[out] ppEapError     Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c ERROR_SUCCESS if succeeded
        /// - error code otherwise
        ///
        virtual DWORD retrieve(_In_ LPCTSTR pszTargetName, _Out_ EAP_ERROR **ppEapError) = 0;

        ///
        /// Return target suffix for Windows Credential Manager credential name
        ///
        virtual LPCTSTR target_suffix() const = 0;

        ///
        /// Returns target name for Windows Credential Manager credential name
        ///
        /// \param[in]  pszTargetName  The name in Windows Credential Manager to retrieve credentials from
        ///
        /// \returns Final target name to store/retrieve credentials in Windows Credential Manager
        ///
        inline winstd::tstring target_name(_In_ LPCTSTR pszTargetName) const
        {
            winstd::tstring target_name(_T(PRODUCT_NAME_STR) _T("/"));
            target_name += pszTargetName;
            target_name += _T('/');
            target_name += target_suffix();
            assert(target_name.length() < CRED_MAX_GENERIC_TARGET_NAME_LENGTH);
            return target_name;
        }

        /// @}

        /// \name Encryption
        /// @{

        ///
        /// Encrypts data
        ///
        /// \param[in ] hProv       Handle of cryptographics provider
        /// \param[in ] data        Pointer to data to encrypt
        /// \param[in ] size        Size of \p data in bytes
        /// \param[out] enc         Encrypted data
        /// \param[out] ppEapError  Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        /// \param[out] hHash       Handle of hashing object
        ///
        /// \returns
        /// - \c ERROR_SUCCESS if succeeded
        /// - error code otherwise
        ///
        DWORD encrypt(_In_ HCRYPTPROV hProv, _In_bytecount_(size) const void *data, _In_ size_t size, _Out_ std::vector<unsigned char> &enc, _Out_ EAP_ERROR **ppEapError, _Out_opt_ HCRYPTHASH hHash = NULL) const;

        ///
        /// Decrypts data
        ///
        /// \param[in ] hProv       Handle of cryptographics provider
        /// \param[in ] data        Pointer to data to decrypt
        /// \param[in ] size        Size of \p data in bytes
        /// \param[out] enc         Decrypted data
        /// \param[out] ppEapError  Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        /// \param[out] hHash       Handle of hashing object
        ///
        /// \returns
        /// - \c ERROR_SUCCESS if succeeded
        /// - error code otherwise
        ///
        template<class _Ty, class _Ax>
        DWORD decrypt(_In_ HCRYPTPROV hProv, _In_bytecount_(size) const void *data, _In_ size_t size, _Out_ std::vector<_Ty, _Ax> &dec, _Out_ EAP_ERROR **ppEapError, _Out_opt_ HCRYPTHASH hHash = NULL) const
        {
            assert(ppEapError);
            DWORD dwResult;

            // Import the private key.
            HRSRC res = FindResource(m_module.m_instance, MAKEINTRESOURCE(IDR_EAP_KEY_PRIVATE), RT_RCDATA);
            assert(res);
            HGLOBAL res_handle = LoadResource(m_module.m_instance, res);
            assert(res_handle);
            crypt_key key;
            unique_ptr<unsigned char[], LocalFree_delete<unsigned char[]> > keyinfo_data;
            DWORD keyinfo_size = 0;
            if (!CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, (const BYTE*)::LockResource(res_handle), ::SizeofResource(m_module.m_instance, res), CRYPT_DECODE_ALLOC_FLAG, NULL, &keyinfo_data, &keyinfo_size)) {
                *ppEapError = m_module.make_error(dwResult = GetLastError(), 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" CryptDecodeObjectEx failed."), NULL);
                return dwResult;
            }

            if (!key.import(hProv, keyinfo_data.get(), keyinfo_size, NULL, 0)) {
                *ppEapError = m_module.make_error(dwResult = GetLastError(), 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Private key import failed."), NULL);
                return dwResult;
            }

            // Decrypt the data using our private key.
            vector<unsigned char, sanitizing_allocator<unsigned char> > buf(size);
            memcpy(buf.data(), data, size);
            if (!CryptDecrypt(key, hHash, TRUE, 0, buf)) {
                *ppEapError = m_module.make_error(dwResult = GetLastError(), 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Decrypting password failed."), NULL);
                return dwResult;
            }

            dec.assign(buf.begin(), buf.end());

            return ERROR_SUCCESS;
        }

        /// @}

    public:
        std::wstring m_identity;    ///< Identity (username\@domain, certificate name etc.)
    };


    class credentials_pass : public credentials
    {
    public:
        ///
        /// Constructs credentials
        ///
        /// \param[in] mod  Reference of the EAP module to use for global services
        ///
        credentials_pass(_In_ module &mod);

        ///
        /// Copies credentials
        ///
        /// \param[in] other  Credentials to copy from
        ///
        credentials_pass(_In_ const credentials_pass &other);

        ///
        /// Moves credentials
        ///
        /// \param[in] other  Credentials to move from
        ///
        credentials_pass(_Inout_ credentials_pass &&other);

        ///
        /// Copies credentials
        ///
        /// \param[in] other  Credentials to copy from
        ///
        /// \returns Reference to this object
        ///
        credentials_pass& operator=(_In_ const credentials_pass &other);

        ///
        /// Moves credentials
        ///
        /// \param[in] other  Credentials to move from
        ///
        /// \returns Reference to this object
        ///
        credentials_pass& operator=(_Inout_ credentials_pass &&other);

        ///
        /// Resets credentials
        ///
        virtual void clear();

        ///
        /// Test credentials if blank
        ///
        virtual bool empty() const;

        /// \name XML configuration management
        /// @{

        ///
        /// Save credentials to XML document
        ///
        /// \param[in]  pDoc         XML document
        /// \param[in]  pConfigRoot  Suggested root element for saving credentials
        /// \param[out] ppEapError   Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c ERROR_SUCCESS if succeeded
        /// - error code otherwise
        ///
        virtual DWORD save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError) const;

        ///
        /// Load credentials from XML document
        ///
        /// \param[in]  pConfigRoot  Root element for loading credentials
        /// \param[out] ppEapError   Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c ERROR_SUCCESS if succeeded
        /// - error code otherwise
        ///
        virtual DWORD load(_In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError);

        /// @}

        /// \name Storage
        /// @{

        ///
        /// Save credentials to Windows Credential Manager
        ///
        /// \param[in]  pszTargetName  The name in Windows Credential Manager to store credentials as
        /// \param[out] ppEapError     Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c ERROR_SUCCESS if succeeded
        /// - error code otherwise
        ///
        virtual DWORD store(_In_ LPCTSTR pszTargetName, _Out_ EAP_ERROR **ppEapError) const;

        ///
        /// Retrieve credentials from Windows Credential Manager
        ///
        /// \param[in]  pszTargetName  The name in Windows Credential Manager to retrieve credentials from
        /// \param[out] ppEapError     Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c ERROR_SUCCESS if succeeded
        /// - error code otherwise
        ///
        virtual DWORD retrieve(_In_ LPCTSTR pszTargetName, _Out_ EAP_ERROR **ppEapError);

        /// @}

    public:
        winstd::sanitizing_wstring m_password;  ///< Password
    };
}


namespace eapserial
{
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const eap::credentials &val)
    {
        pack(cursor, (const eap::config&)val);
        pack(cursor, val.m_identity         );
    }


    inline size_t get_pk_size(const eap::credentials &val)
    {
        return
            get_pk_size((const eap::config&)val) +
            get_pk_size(val.m_identity         );
    }


    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ eap::credentials &val)
    {
        unpack(cursor, (eap::config&)val);
        unpack(cursor, val.m_identity   );
    }


    inline void pack(_Inout_ unsigned char *&cursor, _In_ const eap::credentials_pass &val)
    {
        pack(cursor, (const eap::credentials&)val);
        pack(cursor, val.m_password              );
    }


    inline size_t get_pk_size(const eap::credentials_pass &val)
    {
        return
            get_pk_size((const eap::credentials&)val) +
            get_pk_size(val.m_password              );
    }


    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ eap::credentials_pass &val)
    {
        unpack(cursor, (eap::credentials&)val);
        unpack(cursor, val.m_password        );
    }
}
