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

#define ETW_ERROR(kw, f, ...)   m_ep.write(TRACE_LEVEL_ERROR      , kw, _T(__FUNCTION__) _T(" ") f, ##__VA_ARGS__)
#define ETW_WARNING(kw, f, ...) m_ep.write(TRACE_LEVEL_WARNING    , kw, _T(__FUNCTION__) _T(" ") f, ##__VA_ARGS__)
#define ETW_INFO(kw, f, ...)    m_ep.write(TRACE_LEVEL_INFORMATION, kw, _T(__FUNCTION__) _T(" ") f, ##__VA_ARGS__)
#define ETW_VERBOSE(kw, f, ...) m_ep.write(TRACE_LEVEL_VERBOSE    , kw, _T(__FUNCTION__) _T(" ") f, ##__VA_ARGS__)
#define ETW_FN_VOID             winstd::event_fn_auto    <         &EAPMETHOD_TRACE_EVT_FN_CALL, &EAPMETHOD_TRACE_EVT_FN_RETURN        > _event_auto(m_ep, __FUNCTION__)
#define ETW_FN_DWORD(res)       winstd::event_fn_auto_ret<DWORD  , &EAPMETHOD_TRACE_EVT_FN_CALL, &EAPMETHOD_TRACE_EVT_FN_RETURN_DWORD  > _event_auto(m_ep, __FUNCTION__, res)
#define ETW_FN_HRESULT(res)     winstd::event_fn_auto_ret<HRESULT, &EAPMETHOD_TRACE_EVT_FN_CALL, &EAPMETHOD_TRACE_EVT_FN_RETURN_HRESULT> _event_auto(m_ep, __FUNCTION__, res)

namespace eap
{
    ///
    /// EAP module base class
    ///
    /// Provides basic services to EAP methods.
    ///
    class module;

    ///
    /// EAP peer base class
    ///
    /// A group of methods all EAP peers must or should implement.
    ///
    template <class _Tcfg, class _Tid, class _Tint, class _Tintres> class peer_base;

    ///
    /// EAP peer base class
    ///
    /// A group of methods all EAP peers must or should implement.
    ///
    template <class _Tcfg, class _Tid, class _Tint, class _Tintres> class peer;
}

#pragma once

#include "EAP.h"

#include <WinStd/Win.h>
#include <WinStd/ETW.h>

#include <Windows.h>
#include <eaptypes.h> // Must include after <Windows.h>
#include <sal.h>
#include <tchar.h>

#include <EventsETW.h> // Must include after <Windows.h>


namespace eap
{
    class module
    {
    public:
        ///
        /// Constructs a module for the given EAP type
        ///
        module(_In_ type_t eap_method);

        ///
        /// Destructs the module
        ///
        virtual ~module();

        /// \name Memory management
        /// @{

        ///
        /// Allocate a EAP_ERROR and fill it according to dwErrorCode
        ///
        EAP_ERROR* make_error(_In_ DWORD dwErrorCode, _In_ DWORD dwReasonCode, _In_ LPCGUID pRootCauseGuid, _In_ LPCGUID pRepairGuid, _In_ LPCGUID pHelpLinkGuid, _In_z_ LPCWSTR pszRootCauseString, _In_z_ LPCWSTR pszRepairString) const;

        ///
        /// Allocate BLOB
        ///
        BYTE* alloc_memory(_In_ size_t size);

        ///
        /// Free BLOB allocated with this peer
        ///
        void free_memory(_In_ BYTE *ptr);

        ///
        /// Free EAP_ERROR allocated with `make_error()` method
        ///
        void free_error_memory(_In_ EAP_ERROR *err);

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
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        bool encrypt(_In_ HCRYPTPROV hProv, _In_bytecount_(size) const void *data, _In_ size_t size, _Out_ std::vector<unsigned char> &enc, _Out_ EAP_ERROR **ppEapError, _Out_opt_ HCRYPTHASH hHash = NULL) const;


        ///
        /// Encrypts a string
        ///
        /// \param[in ] hProv       Handle of cryptographics provider
        /// \param[in ] val         String to encrypt
        /// \param[out] enc         Encrypted data
        /// \param[out] ppEapError  Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        /// \param[out] hHash       Handle of hashing object
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        template<class _Elem, class _Traits, class _Ax>
        bool encrypt(_In_ HCRYPTPROV hProv, _In_ const std::basic_string<_Elem, _Traits, _Ax> &val, _Out_ std::vector<unsigned char> &enc, _Out_ EAP_ERROR **ppEapError, _Out_opt_ HCRYPTHASH hHash = NULL) const
        {
            return encrypt(hProv, val.c_str(), val.length*sizeof(_Elem), enc, ppEapError, hHash);
        }


        ///
        /// Encrypts a wide string
        ///
        /// \param[in ] hProv       Handle of cryptographics provider
        /// \param[in ] val         String to encrypt
        /// \param[out] enc         Encrypted data
        /// \param[out] ppEapError  Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        /// \param[out] hHash       Handle of hashing object
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        template<class _Traits, class _Ax>
        bool encrypt(_In_ HCRYPTPROV hProv, _In_ const std::basic_string<wchar_t, _Traits, _Ax> &val, _Out_ std::vector<unsigned char> &enc, _Out_ EAP_ERROR **ppEapError, _Out_opt_ HCRYPTHASH hHash = NULL) const
        {
            winstd::sanitizing_string val_utf8;
            WideCharToMultiByte(CP_UTF8, 0, val.c_str(), (int)val.length(), val_utf8, NULL, NULL);
            return encrypt(hProv, val_utf8, enc, ppEapError, hHash);
        }


        ///
        /// Encrypts data and add MD5 hash for integrity check
        ///
        /// \param[in ] hProv       Handle of cryptographics provider
        /// \param[in ] data        Pointer to data to encrypt
        /// \param[in ] size        Size of \p data in bytes
        /// \param[out] enc         Encrypted data with 16B MD5 hash appended
        /// \param[out] ppEapError  Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        bool encrypt_md5(_In_ HCRYPTPROV hProv, _In_bytecount_(size) const void *data, _In_ size_t size, _Out_ std::vector<unsigned char> &enc, _Out_ EAP_ERROR **ppEapError) const;


        ///
        /// Encrypts a string and add MD5 hash for integrity check
        ///
        /// \param[in ] hProv       Handle of cryptographics provider
        /// \param[in ] val         String to encrypt
        /// \param[out] enc         Encrypted data with 16B MD5 hash appended
        /// \param[out] ppEapError  Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        template<class _Elem, class _Traits, class _Ax>
        bool encrypt_md5(_In_ HCRYPTPROV hProv, _In_ const std::basic_string<_Elem, _Traits, _Ax> &val, _Out_ std::vector<unsigned char> &enc, _Out_ EAP_ERROR **ppEapError) const
        {
            return encrypt_md5(hProv, val.c_str(), val.length()*sizeof(_Elem), enc, ppEapError);
        }


        ///
        /// Encrypts a wide string and add MD5 hash for integrity check
        ///
        /// \param[in ] hProv       Handle of cryptographics provider
        /// \param[in ] val         String to encrypt
        /// \param[out] enc         Encrypted data with 16B MD5 hash appended
        /// \param[out] ppEapError  Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        template<class _Traits, class _Ax>
        bool encrypt_md5(_In_ HCRYPTPROV hProv, _In_ const std::basic_string<wchar_t, _Traits, _Ax> &val, _Out_ std::vector<unsigned char> &enc, _Out_ EAP_ERROR **ppEapError) const
        {
            winstd::sanitizing_string val_utf8;
            WideCharToMultiByte(CP_UTF8, 0, val.c_str(), (int)val.length(), val_utf8, NULL, NULL);
            return encrypt_md5(hProv, val_utf8, enc, ppEapError);
        }


        ///
        /// Decrypts data
        ///
        /// \param[in ] hProv       Handle of cryptographics provider
        /// \param[in ] data        Pointer to data to decrypt
        /// \param[in ] size        Size of \p data in bytes
        /// \param[out] dec         Decrypted data
        /// \param[out] ppEapError  Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        /// \param[out] hHash       Handle of hashing object
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        template<class _Ty, class _Ax>
        bool decrypt(_In_ HCRYPTPROV hProv, _In_bytecount_(size) const void *data, _In_ size_t size, _Out_ std::vector<_Ty, _Ax> &dec, _Out_ EAP_ERROR **ppEapError, _Out_opt_ HCRYPTHASH hHash = NULL) const
        {
            assert(ppEapError);

            // Import the private key.
            HRSRC res = FindResource(m_instance, MAKEINTRESOURCE(IDR_EAP_KEY_PRIVATE), RT_RCDATA);
            assert(res);
            HGLOBAL res_handle = LoadResource(m_instance, res);
            assert(res_handle);
            crypt_key key;
            unique_ptr<unsigned char[], LocalFree_delete<unsigned char[]> > keyinfo_data;
            DWORD keyinfo_size = 0;
            if (!CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, (const BYTE*)::LockResource(res_handle), ::SizeofResource(m_instance, res), CRYPT_DECODE_ALLOC_FLAG, NULL, &keyinfo_data, &keyinfo_size)) {
                *ppEapError = make_error(GetLastError(), 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" CryptDecodeObjectEx failed."), NULL);
                return false;
            }

            if (!key.import(hProv, keyinfo_data.get(), keyinfo_size, NULL, 0)) {
                *ppEapError = make_error(GetLastError(), 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Private key import failed."), NULL);
                return false;
            }

            // Decrypt the data using our private key.
            vector<unsigned char, sanitizing_allocator<unsigned char> > buf(size);
            memcpy(buf.data(), data, size);
            if (!CryptDecrypt(key, hHash, TRUE, 0, buf)) {
                *ppEapError = make_error(GetLastError(), 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Decrypting password failed."), NULL);
                return false;
            }

            dec.assign(buf.begin(), buf.end());

            return true;
        }


        ///
        /// Decrypts a string
        ///
        /// \param[in ] hProv       Handle of cryptographics provider
        /// \param[in ] data        Pointer to data to decrypt
        /// \param[in ] size        Size of \p data in bytes
        /// \param[out] dec         Decrypted string
        /// \param[out] ppEapError  Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        /// \param[out] hHash       Handle of hashing object
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        template<class _Elem, class _Traits, class _Ax>
        bool decrypt(_In_ HCRYPTPROV hProv, _In_bytecount_(size) const void *data, _In_ size_t size, _Out_ std::basic_string<_Elem, _Traits, _Ax> &dec, _Out_ EAP_ERROR **ppEapError, _Out_opt_ HCRYPTHASH hHash = NULL) const
        {
            std::vector<_Elem, sanitizing_allocator<_Elem> > buf;
            if (!decrypt(hProv, data, size, buf, ppEapError, hHash))
                return false;
            dec.assign((const _Elem*)buf.begin(), (const _Elem*)buf.end());

            return true;
        }


        ///
        /// Decrypts a wide string
        ///
        /// \param[in ] hProv       Handle of cryptographics provider
        /// \param[in ] data        Pointer to data to decrypt
        /// \param[in ] size        Size of \p data in bytes
        /// \param[out] dec         Decrypted string
        /// \param[out] ppEapError  Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        /// \param[out] hHash       Handle of hashing object
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        template<class _Traits, class _Ax>
        bool decrypt(_In_ HCRYPTPROV hProv, _In_bytecount_(size) const void *data, _In_ size_t size, _Out_ std::basic_string<wchar_t, _Traits, _Ax> &dec, _Out_ EAP_ERROR **ppEapError, _Out_opt_ HCRYPTHASH hHash = NULL) const
        {
            winstd::sanitizing_string buf;
            if (!decrypt(hProv, data, size, buf, ppEapError, hHash))
                return false;
            MultiByteToWideChar(CP_UTF8, 0, buf.data(), (int)buf.size(), dec);

            return true;
        }


        ///
        /// Decrypts data with MD5 integrity check
        ///
        /// \param[in ] hProv       Handle of cryptographics provider
        /// \param[in ] data        Pointer to data with 16B MD5 hash appended to decrypt
        /// \param[in ] size        Size of \p data in bytes
        /// \param[out] dec         Decrypted data
        /// \param[out] ppEapError  Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        template<class _Ty, class _Ax>
        bool decrypt_md5(_In_ HCRYPTPROV hProv, _In_bytecount_(size) const void *data, _In_ size_t size, _Out_ std::vector<_Ty, _Ax> &dec, _Out_ EAP_ERROR **ppEapError) const
        {
            // Create hash.
            crypt_hash hash;
            if (!hash.create(hProv, CALG_MD5)) {
                *ppEapError = make_error(GetLastError(), 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Creating MD5 hash failed."), NULL);
                return false;
            }
            DWORD dwHashSize, dwHashSizeSize = sizeof(dwHashSize);
            CryptGetHashParam(hash, HP_HASHSIZE, (LPBYTE)&dwHashSize, &dwHashSizeSize, 0);
            if (size < dwHashSize) {
                *ppEapError = make_error(ERROR_INVALID_DATA, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Encrypted data too short."), NULL);
                return false;
            }
            size_t enc_size = size - dwHashSize;

            // Decrypt data.
            if (!decrypt(hProv, data, enc_size, dec, ppEapError, hash))
                return false;

            // Calculate MD5 hash and verify it.
            vector<unsigned char> hash_bin;
            if (!CryptGetHashParam(hash, HP_HASHVAL, hash_bin, 0)) {
                *ppEapError = make_error(GetLastError(), 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Calculating MD5 hash failed."), NULL);
                return false;
            }
            if (memcmp((unsigned char*)data + enc_size, hash_bin.data(), dwHashSize) != 0) {
                *ppEapError = make_error(ERROR_INVALID_DATA, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Invalid encrypted data."), NULL);
                return false;
            }

            return true;
        }


        ///
        /// Decrypts a string with MD5 integrity check
        ///
        /// \param[in ] hProv       Handle of cryptographics provider
        /// \param[in ] data        Pointer to data with 16B MD5 hash appended to decrypt
        /// \param[in ] size        Size of \p data in bytes
        /// \param[out] dec         Decrypted string
        /// \param[out] ppEapError  Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        template<class _Elem, class _Traits, class _Ax>
        bool decrypt_md5(_In_ HCRYPTPROV hProv, _In_bytecount_(size) const void *data, _In_ size_t size, _Out_ std::basic_string<_Elem, _Traits, _Ax> &dec, _Out_ EAP_ERROR **ppEapError) const
        {
            std::vector<_Elem, sanitizing_allocator<_Elem> > buf;
            if (!decrypt_md5(hProv, data, size, buf, ppEapError))
                return false;
            dec.assign(buf.data(), buf.size());

            return true;
        }


        ///
        /// Decrypts a wide string with MD5 integrity check
        ///
        /// \param[in ] hProv       Handle of cryptographics provider
        /// \param[in ] data        Pointer to data with 16B MD5 hash appended to decrypt
        /// \param[in ] size        Size of \p data in bytes
        /// \param[out] dec         Decrypted string
        /// \param[out] ppEapError  Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        template<class _Traits, class _Ax>
        bool decrypt_md5(_In_ HCRYPTPROV hProv, _In_bytecount_(size) const void *data, _In_ size_t size, _Out_ std::basic_string<wchar_t, _Traits, _Ax> &dec, _Out_ EAP_ERROR **ppEapError) const
        {
            winstd::sanitizing_string buf;
            if (!decrypt_md5(hProv, data, size, buf, ppEapError))
                return false;
            MultiByteToWideChar(CP_UTF8, 0, buf.data(), (int)buf.size(), dec);

            return true;
        }

        /// @}

    public:
        HINSTANCE m_instance;                   ///< Windows module instance
        const type_t m_eap_method;              ///< EAP method type

    protected:
        winstd::heap m_heap;                    ///< Heap
        mutable winstd::event_provider m_ep;    ///< Event Provider
    };


    template <class _Tcfg, class _Tid, class _Tint, class _Tintres>
    class peer_base : public module
    {
    public:
        ///
        /// Configuration data type
        ///
        typedef config_providers<config_provider<_Tcfg> > config_type;

        ///
        /// Identity data type
        ///
        typedef _Tid identity_type;

        ///
        /// Interactive request data type
        ///
        typedef _Tint interactive_request_type;

        ///
        /// Interactive response data type
        ///
        typedef _Tintres interactive_response_type;

    public:
        ///
        /// Constructs a EAP peer module for the given EAP type
        ///
        peer_base(_In_ type_t eap_method) : module(eap_method) {}
    };


    template <class _Tcfg, class _Tid, class _Tint, class _Tintres>
    class peer : public peer_base<_Tcfg, _Tid, _Tint, _Tintres>
    {
    public:
        ///
        /// Constructs a EAP peer module for the given EAP type
        ///
        peer(_In_ type_t eap_method) : peer_base<_Tcfg, _Tid, _Tint, _Tintres>(eap_method) {}

        ///
        /// Initializes an EAP peer method for EAPHost.
        ///
        /// \sa [EapPeerGetInfo function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363613.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool initialize(_Out_ EAP_ERROR **ppEapError) = 0;

        ///
        /// Shuts down the EAP method and prepares to unload its corresponding DLL.
        ///
        /// \sa [EapPeerShutdown function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363627.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool shutdown(_Out_ EAP_ERROR **ppEapError) = 0;

        ///
        /// Returns the user data and user identity after being called by EAPHost.
        ///
        /// \sa [EapPeerGetIdentity function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363607.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool get_identity(
            _In_                                   DWORD     dwFlags,
            _In_                                   DWORD     dwConnectionDataSize,
            _In_count_(dwConnectionDataSize) const BYTE      *pConnectionData,
            _In_                                   DWORD     dwUserDataSize,
            _In_count_(dwUserDataSize)       const BYTE      *pUserData,
            _In_                                   HANDLE    hTokenImpersonateUser,
            _Out_                                  BOOL      *pfInvokeUI,
            _Out_                                  DWORD     *pdwUserDataOutSize,
            _Out_                                  BYTE      **ppUserDataOut,
            _Out_                                  WCHAR     **ppwszIdentity,
            _Out_                                  EAP_ERROR **ppEapError) = 0;

        ///
        /// Defines the implementation of an EAP method-specific function that retrieves the properties of an EAP method given the connection and user data.
        ///
        /// \sa [EapPeerGetMethodProperties function](https://msdn.microsoft.com/en-us/library/windows/desktop/hh706636.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool get_method_properties(
            _In_                                DWORD                     dwVersion,
            _In_                                DWORD                     dwFlags,
            _In_                                HANDLE                    hUserImpersonationToken,
            _In_                                DWORD                     dwEapConnDataSize,
            _In_count_(dwEapConnDataSize) const BYTE                      *pEapConnData,
            _In_                                DWORD                     dwUserDataSize,
            _In_count_(dwUserDataSize)    const BYTE                      *pUserData,
            _Out_                               EAP_METHOD_PROPERTY_ARRAY *pMethodPropertyArray,
            _Out_                               EAP_ERROR                 **ppEapError) const = 0;

        ///
        /// Defines the implementation of an EAP method-specific function that obtains the EAP Single-Sign-On (SSO) credential input fields for an EAP method.
        ///
        /// \sa [EapPeerQueryCredentialInputFields function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363622.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool query_credential_input_fields(
            _In_                                HANDLE                       hUserImpersonationToken,
            _In_                                DWORD                        dwFlags,
            _In_                                DWORD                        dwEapConnDataSize,
            _In_count_(dwEapConnDataSize) const BYTE                         *pEapConnData,
            _Out_                               EAP_CONFIG_INPUT_FIELD_ARRAY *pEapConfigInputFieldsArray,
            _Out_                               EAP_ERROR                    **ppEapError) const
        {
            UNREFERENCED_PARAMETER(hUserImpersonationToken);
            UNREFERENCED_PARAMETER(dwFlags);
            UNREFERENCED_PARAMETER(dwEapConnDataSize);
            UNREFERENCED_PARAMETER(pEapConnData);
            UNREFERENCED_PARAMETER(pEapConfigInputFieldsArray);
            UNREFERENCED_PARAMETER(ppEapError);

            *ppEapError = make_error(ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Not supported."), NULL);
            return false;
        }

        ///
        /// Defines the implementation of an EAP method function that obtains the user BLOB data provided in an interactive Single-Sign-On (SSO) UI raised on the supplicant.
        ///
        /// \sa [EapPeerQueryUserBlobFromCredentialInputFields function](https://msdn.microsoft.com/en-us/library/windows/desktop/bb204697.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool query_user_blob_from_credential_input_fields(
            _In_                                HANDLE                       hUserImpersonationToken,
            _In_                                DWORD                        dwFlags,
            _In_                                DWORD                        dwEapConnDataSize,
            _In_count_(dwEapConnDataSize) const BYTE                         *pEapConnData,
            _In_                          const EAP_CONFIG_INPUT_FIELD_ARRAY *pEapConfigInputFieldArray,
            _Inout_                             DWORD                        *pdwUsersBlobSize,
            _Inout_                             BYTE                         **ppUserBlob,
            _Out_                               EAP_ERROR                    **ppEapError) const
        {
            UNREFERENCED_PARAMETER(hUserImpersonationToken);
            UNREFERENCED_PARAMETER(dwFlags);
            UNREFERENCED_PARAMETER(dwEapConnDataSize);
            UNREFERENCED_PARAMETER(pEapConnData);
            UNREFERENCED_PARAMETER(pEapConfigInputFieldArray);
            UNREFERENCED_PARAMETER(pdwUsersBlobSize);
            UNREFERENCED_PARAMETER(ppUserBlob);
            UNREFERENCED_PARAMETER(ppEapError);

            *ppEapError = make_error(ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Not supported."), NULL);
            return false;
        }

        ///
        /// Defines the implementation of an EAP method API that provides the input fields for interactive UI components to be raised on the supplicant.
        ///
        /// \sa [EapPeerQueryInteractiveUIInputFields function](https://msdn.microsoft.com/en-us/library/windows/desktop/bb204695.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool query_interactive_ui_input_fields(
            _In_                                  DWORD                   dwVersion,
            _In_                                  DWORD                   dwFlags,
            _In_                                  DWORD                   dwUIContextDataSize,
            _In_count_(dwUIContextDataSize) const BYTE                    *pUIContextData,
            _Out_                                 EAP_INTERACTIVE_UI_DATA *pEapInteractiveUIData,
            _Out_                                 EAP_ERROR               **ppEapError,
            _Inout_                               LPVOID                  *pvReserved) const
        {
            UNREFERENCED_PARAMETER(dwVersion);
            UNREFERENCED_PARAMETER(dwFlags);
            UNREFERENCED_PARAMETER(dwUIContextDataSize);
            UNREFERENCED_PARAMETER(pUIContextData);
            UNREFERENCED_PARAMETER(pEapInteractiveUIData);
            UNREFERENCED_PARAMETER(ppEapError);
            UNREFERENCED_PARAMETER(pvReserved);

            *ppEapError = make_error(ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Not supported."), NULL);
            return false;
        }

        ///
        /// Converts user information into a user BLOB that can be consumed by EAPHost run-time functions.
        ///
        /// \sa [EapPeerQueryUIBlobFromInteractiveUIInputFields function](https://msdn.microsoft.com/en-us/library/windows/desktop/bb204696.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool query_ui_blob_from_interactive_ui_input_fields(
            _In_                                  DWORD                   dwVersion,
            _In_                                  DWORD                   dwFlags,
            _In_                                  DWORD                   dwUIContextDataSize,
            _In_count_(dwUIContextDataSize) const BYTE                    *pUIContextData,
            _In_                            const EAP_INTERACTIVE_UI_DATA *pEapInteractiveUIData,
            _Out_                                 DWORD                   *pdwDataFromInteractiveUISize,
            _Out_                                 BYTE                    **ppDataFromInteractiveUI,
            _Out_                                 EAP_ERROR               **ppEapError,
            _Inout_                               LPVOID                  *ppvReserved) const
        {
            UNREFERENCED_PARAMETER(dwVersion);
            UNREFERENCED_PARAMETER(dwFlags);
            UNREFERENCED_PARAMETER(dwUIContextDataSize);
            UNREFERENCED_PARAMETER(pUIContextData);
            UNREFERENCED_PARAMETER(pEapInteractiveUIData);
            UNREFERENCED_PARAMETER(pdwDataFromInteractiveUISize);
            UNREFERENCED_PARAMETER(ppDataFromInteractiveUI);
            UNREFERENCED_PARAMETER(ppEapError);
            UNREFERENCED_PARAMETER(ppvReserved);

            *ppEapError = make_error(ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Not supported."), NULL);
            return false;
        }
    };
}
