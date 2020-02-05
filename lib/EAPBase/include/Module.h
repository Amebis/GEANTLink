/*
    Copyright 2015-2020 Amebis
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

namespace eap
{
    class module;
    class peer;
}

#pragma once

#include "EAP.h"
#include "Config.h"
#include "Credentials.h"
#include "Method.h"

#include <WinStd/Crypt.h>
#include <WinStd/ETW.h>
#include <WinStd/Win.h>

#include <Windows.h>
#include <eaptypes.h> // Must include after <Windows.h>
extern "C" {
#include <eapmethodpeerapis.h>
}
#include <sal.h>
#include <tchar.h>

#include <EventsETW.h> // Must include after <Windows.h>

#include <exception>


namespace eap
{
    /// \addtogroup EAPBaseModule
    /// @{

    ///
    /// EAP module base class
    ///
    /// Provides basic services to EAP methods.
    ///
    class module
    {
    public:
        ///
        /// Constructs a module for the given EAP type
        ///
        /// \param[in] eap_method  EAP method type ID
        ///
        module(_In_ winstd::eap_type_t eap_method = winstd::eap_type_t::undefined);

        ///
        /// Destructs the module
        ///
        virtual ~module();

        /// \name Memory management
        /// @{

        ///
        /// Allocate a EAP_ERROR and fill it according to dwErrorCode
        ///
        EAP_ERROR* make_error(_In_ DWORD dwErrorCode, _In_opt_z_ LPCWSTR pszRootCauseString = NULL, _In_opt_z_ LPCWSTR pszRepairString = NULL, _In_opt_ DWORD dwReasonCode = 0, _In_opt_ LPCGUID pRootCauseGuid = NULL, _In_opt_ LPCGUID pRepairGuid = NULL, _In_opt_ LPCGUID pHelpLinkGuid = NULL) const;

        ///
        /// Allocate a EAP_ERROR and fill it according to exception
        ///
        EAP_ERROR* make_error(_In_ std::exception &err) const;

        ///
        /// Allocate a EAP_ERROR and fill it according to another EAP_ERROR
        ///
        EAP_ERROR* make_error(_In_ const EAP_ERROR *err) const;

        ///
        /// Allocate BLOB
        ///
        BYTE* alloc_memory(_In_ size_t size) const;

        ///
        /// Free BLOB allocated with this peer
        ///
        void free_memory(_In_ BYTE *ptr) const;

        ///
        /// Free EAP_ERROR allocated with `make_error()` method
        ///
        void free_error_memory(_In_ EAP_ERROR *err) const;

        ///
        /// Makes a new method configuration
        ///
        /// \returns New method configuration
        ///
        virtual config_method* make_config();

        /// @}

        /// \name Logging
        /// @{

        ///
        /// Writes EAPMETHOD_TRACE_EVT_FN_CALL and returns auto event writer class
        ///
        /// \param[in] pszFnName  Function name
        ///
        /// \returns A new auto event writer that writes EAPMETHOD_TRACE_EVT_FN_RETURN event on destruction
        ///
        inline winstd::event_fn_auto get_event_fn_auto(_In_z_ LPCSTR pszFnName) const
        {
            return winstd::event_fn_auto(m_ep, &EAPMETHOD_TRACE_EVT_FN_CALL, &EAPMETHOD_TRACE_EVT_FN_RETURN, pszFnName);
        }

        ///
        /// Writes EAPMETHOD_TRACE_EVT_FN_CALL and returns auto event writer class
        ///
        /// \param[in] pszFnName  Function name
        /// \param[in] result     Reference to function return variable
        ///
        /// \returns A new auto event writer that writes EAPMETHOD_TRACE_EVT_FN_RETURN_DWORD event on destruction
        ///
        inline winstd::event_fn_auto_ret<DWORD> get_event_fn_auto(_In_z_ LPCSTR pszFnName, _In_ DWORD &result) const
        {
            return winstd::event_fn_auto_ret<DWORD>(m_ep, &EAPMETHOD_TRACE_EVT_FN_CALL, &EAPMETHOD_TRACE_EVT_FN_RETURN_DWORD, pszFnName, result);
        }

        ///
        /// Logs error
        ///
        void log_error(_In_ const EAP_ERROR *err) const;

        ///
        /// Logs error and optionally returns EAP_ERROR
        ///
        inline DWORD log_error(_Out_opt_ EAP_ERROR **eap_err, _In_ DWORD dwErrorCode, _In_opt_z_ LPCWSTR pszRootCauseString = NULL, _In_opt_z_ LPCWSTR pszRepairString = NULL, _In_opt_ DWORD dwReasonCode = 0, _In_opt_ LPCGUID pRootCauseGuid = NULL, _In_opt_ LPCGUID pRepairGuid = NULL, _In_opt_ LPCGUID pHelpLinkGuid = NULL) const
        {
            EAP_ERROR *e = make_error(dwErrorCode, pszRootCauseString, pszRepairString, dwReasonCode, pRootCauseGuid, pRepairGuid, pHelpLinkGuid);
            log_error(e);
            if (eap_err)
                *eap_err = e;
            else
                free_error_memory(e);
            return dwErrorCode;
        }

        ///
        /// Logs error and optionally returns EAP_ERROR
        ///
        inline DWORD log_error(_Out_opt_ EAP_ERROR **eap_err, _In_ std::exception &err) const
        {
            EAP_ERROR *e = make_error(err);
            log_error(e);
            DWORD dwWinError = e->dwWinError;
            if (eap_err)
                *eap_err = e;
            else
                free_error_memory(e);
            return dwWinError;
        }

        ///
        /// Logs Unicode string config value
        ///
        inline void log_config(_In_z_ LPCWSTR name, _In_z_ LPCWSTR value) const
        {
            EVENT_DATA_DESCRIPTOR desc[] = {
                winstd::event_data(name ),
                winstd::event_data(value)
            };

            m_ep.write(&EAPMETHOD_TRACE_EVT_CFG_VALUE_UNICODE_STRING, _countof(desc), desc);
        }

        ///
        /// Logs string list config value
        ///
        template<class _Traits, class _Ax, class _Ax_list>
        inline void log_config(_In_z_ LPCWSTR name, _In_ const std::list<std::basic_string<char, _Traits, _Ax>, _Ax_list> &value) const
        {
            // Prepare a table of event data descriptors.
            std::vector<EVENT_DATA_DESCRIPTOR> desc;
            size_t count = value.size();
            desc.reserve(count + 2);
            desc.push_back(winstd::event_data(              name ));
            desc.push_back(winstd::event_data((unsigned int)count));
            for (auto v = value.cbegin(), v_end = value.cend(); v != v_end; ++v)
                desc.push_back(winstd::event_data(*v));

            m_ep.write(&EAPMETHOD_TRACE_EVT_CFG_VALUE_ANSI_STRING_ARRAY, (ULONG)desc.size(), desc.data());
        }

        ///
        /// Logs Unicode string list config value
        ///
        template<class _Traits, class _Ax, class _Ax_list>
        inline void log_config(_In_z_ LPCWSTR name, _In_ const std::list<std::basic_string<wchar_t, _Traits, _Ax>, _Ax_list> &value) const
        {
            // Prepare a table of event data descriptors.
            std::vector<EVENT_DATA_DESCRIPTOR> desc;
            size_t count = value.size();
            desc.reserve(count + 2);
            desc.push_back(winstd::event_data(              name ));
            desc.push_back(winstd::event_data((unsigned int)count));
            for (auto v = value.cbegin(), v_end = value.cend(); v != v_end; ++v)
                desc.push_back(winstd::event_data(*v));

            m_ep.write(&EAPMETHOD_TRACE_EVT_CFG_VALUE_UNICODE_STRING_ARRAY, (ULONG)desc.size(), desc.data());
        }

        ///
        /// Logs boolean config value
        ///
        inline void log_config(_In_z_ LPCWSTR name, _In_ bool value) const
        {
            EVENT_DATA_DESCRIPTOR desc[] = {
                winstd::event_data(     name ),
                winstd::event_data((int)value)
            };

            m_ep.write(&EAPMETHOD_TRACE_EVT_CFG_VALUE_BOOL, _countof(desc), desc);
        }

        ///
        /// Logs binary config value
        ///
        inline void log_config(_In_z_ LPCWSTR name, _In_bytecount_(size) const void *data, _In_ ULONG size) const
        {
            EVENT_DATA_DESCRIPTOR desc[] = {
                winstd::event_data(      name),
                winstd::event_data(      size),
                winstd::event_data(data, size)
            };

            m_ep.write(&EAPMETHOD_TRACE_EVT_CFG_VALUE_BINARY, _countof(desc), desc);
        }

        ///
        /// Discretely logs Unicode string config value
        ///
        /// If \c _DEBUG is set the value is masked.
        ///
        /// \param[in] name   Variable name
        /// \param[in] value  Variable value
        ///
        inline void log_config_discrete(_In_z_ LPCWSTR name, _In_z_ LPCWSTR value) const
        {
#if __DANGEROUS__LOG_CONFIDENTIAL_DATA
#pragma message (__FILE__ "(" STRING(__LINE__) "): Warning: !!! DANGER !!!  Passwords and certificates will be logged as a clear-text. Please, consider setting __DANGEROUS__LOG_CONFIDENTIAL_DATA to 0.")
            log_config(name, value);
#else
            log_config(name, value ? value[0] ? L"********" : L"" : NULL);
#endif
        }

        ///
        /// Discretely logs binary config value
        ///
        /// If \c _DEBUG is set the value is masked.
        ///
        /// \param[in] name  Variable name
        /// \param[in] data  Variable data
        /// \param[in] size  \p data size in bytes
        ///
        inline void log_config_discrete(_In_z_ LPCWSTR name, _In_bytecount_(size) const void *data, _In_ ULONG size) const
        {
#if __DANGEROUS__LOG_CONFIDENTIAL_DATA
#pragma message (__FILE__ "(" STRING(__LINE__) "): Warning: !!! DANGER !!!  Passwords and certificates will be logged as a clear-text. Please, consider setting __DANGEROUS__LOG_CONFIDENTIAL_DATA to 0.")
            log_config(name, data, size);
#else
            log_config(name, data ? size ? L"********" : L"" : NULL);
#endif
        }

        ///
        /// Logs event
        ///
        /// \param[in] EventDescriptor  Event descriptor
        ///
        inline void log_event(_In_ PCEVENT_DESCRIPTOR EventDescriptor, ...) const
        {
            va_list arg;
            va_start(arg, EventDescriptor);
            m_ep.write(EventDescriptor, arg);
            va_end(arg);
        }

        /// @}

        /// \name Encryption
        /// @{

        ///
        /// Encrypts data
        ///
        /// \param[in ] hProv  Handle of cryptographics provider
        /// \param[in ] data   Pointer to data to encrypt
        /// \param[in ] size   Size of \p data in bytes
        /// \param[out] hHash  Handle of hashing object
        ///
        /// \returns Encrypted data
        ///
        std::vector<unsigned char> encrypt(_In_ HCRYPTPROV hProv, _In_bytecount_(size) const void *data, _In_ size_t size, _In_opt_ HCRYPTHASH hHash = NULL) const;


        ///
        /// Encrypts a string
        ///
        /// \param[in ] hProv  Handle of cryptographics provider
        /// \param[in ] val    String to encrypt
        /// \param[out] hHash  Handle of hashing object
        ///
        /// \returns Encrypted data
        ///
        template<class _Elem, class _Traits, class _Ax>
        std::vector<unsigned char> encrypt(_In_ HCRYPTPROV hProv, _In_ const std::basic_string<_Elem, _Traits, _Ax> &val, _In_opt_ HCRYPTHASH hHash = NULL) const
        {
            return encrypt(hProv, val.c_str(), val.length()*sizeof(_Elem), hHash);
        }


        ///
        /// Encrypts a wide string
        ///
        /// \param[in ] hProv  Handle of cryptographics provider
        /// \param[in ] val    String to encrypt
        /// \param[out] hHash  Handle of hashing object
        ///
        /// \returns Encrypted data
        ///
        template<class _Traits, class _Ax>
        std::vector<unsigned char> encrypt(_In_ HCRYPTPROV hProv, _In_ const std::basic_string<wchar_t, _Traits, _Ax> &val, _In_opt_ HCRYPTHASH hHash = NULL) const
        {
            winstd::sanitizing_string val_utf8;
            WideCharToMultiByte(CP_UTF8, 0, val, val_utf8, NULL, NULL);
            return encrypt(hProv, val_utf8, hHash);
        }


        ///
        /// Encrypts data and add MD5 hash for integrity check
        ///
        /// \param[in ] hProv  Handle of cryptographics provider
        /// \param[in ] data   Pointer to data to encrypt
        /// \param[in ] size   Size of \p data in bytes
        ///
        /// \returns Encrypted data with 16B MD5 hash appended
        ///
        std::vector<unsigned char> encrypt_md5(_In_ HCRYPTPROV hProv, _In_bytecount_(size) const void *data, _In_ size_t size) const;


        ///
        /// Encrypts a string and add MD5 hash for integrity check
        ///
        /// \param[in ] hProv  Handle of cryptographics provider
        /// \param[in ] val    String to encrypt
        ///
        /// \returns Encrypted data with 16B MD5 hash appended
        ///
        template<class _Elem, class _Traits, class _Ax>
        std::vector<unsigned char> encrypt_md5(_In_ HCRYPTPROV hProv, _In_ const std::basic_string<_Elem, _Traits, _Ax> &val) const
        {
            return encrypt_md5(hProv, val.c_str(), val.length()*sizeof(_Elem));
        }


        ///
        /// Encrypts a wide string and add MD5 hash for integrity check
        ///
        /// \param[in ] hProv  Handle of cryptographics provider
        /// \param[in ] val    String to encrypt
        ///
        /// \returns Encrypted data with 16B MD5 hash appended
        ///
        template<class _Traits, class _Ax>
        std::vector<unsigned char> encrypt_md5(_In_ HCRYPTPROV hProv, _In_ const std::basic_string<wchar_t, _Traits, _Ax> &val) const
        {
            winstd::sanitizing_string val_utf8;
            WideCharToMultiByte(CP_UTF8, 0, val, val_utf8, NULL, NULL);
            return encrypt_md5(hProv, val_utf8);
        }


        ///
        /// Decrypts data
        ///
        /// \param[in ] hProv  Handle of cryptographics provider
        /// \param[in ] data   Pointer to data to decrypt
        /// \param[in ] size   Size of \p data in bytes
        /// \param[out] hHash  Handle of hashing object
        ///
        /// \returns Decrypted data
        ///
        template<class _Ty, class _Ax>
        std::vector<_Ty, _Ax> decrypt(_In_ HCRYPTPROV hProv, _In_bytecount_(size) const void *data, _In_ size_t size, _In_opt_ HCRYPTHASH hHash = NULL) const
        {
            // Import the RSA key.
            winstd::crypt_key key_rsa;
            std::unique_ptr<unsigned char[], winstd::LocalFree_delete<unsigned char[]> > keyinfo_data;
            DWORD keyinfo_size = 0;
            if (!CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, s_rsa_key, sizeof(s_rsa_key), CRYPT_DECODE_ALLOC_FLAG, NULL, &keyinfo_data, &keyinfo_size))
                throw winstd::win_runtime_error(__FUNCTION__ " CryptDecodeObjectEx failed.");
            if (!key_rsa.import(hProv, keyinfo_data.get(), keyinfo_size, NULL, 0))
                throw winstd::win_runtime_error(__FUNCTION__ " Key import failed.");

            // Import the 256-bit AES session key.
            winstd::crypt_key key_aes;
            if (!CryptImportKey(hProv, reinterpret_cast<LPCBYTE>(data), 268, key_rsa, 0, &key_aes))
                throw winstd::win_runtime_error(__FUNCTION__ " CryptImportKey failed.");

            // Decrypt the data using AES session key.
            std::vector<unsigned char, winstd::sanitizing_allocator<unsigned char> > buf;
            buf.assign(reinterpret_cast<const unsigned char*>(data) + 268, reinterpret_cast<const unsigned char*>(data) + size);
            if (!CryptDecrypt(key_aes, hHash, TRUE, 0, buf))
                throw winstd::win_runtime_error(__FUNCTION__ " CryptDecrypt failed.");

            std::vector<_Ty, _Ax> buf_res;
            buf_res.assign(buf.cbegin(), buf.cend());
            return buf_res;
        }


        ///
        /// Decrypts a string
        ///
        /// \param[in ] hProv  Handle of cryptographics provider
        /// \param[in ] data   Pointer to data to decrypt
        /// \param[in ] size   Size of \p data in bytes
        /// \param[out] hHash  Handle of hashing object
        ///
        /// \returns Decrypted string
        ///
        template<class _Elem, class _Traits, class _Ax>
        std::basic_string<_Elem, _Traits, _Ax> decrypt_str(_In_ HCRYPTPROV hProv, _In_bytecount_(size) const void *data, _In_ size_t size, _In_opt_ HCRYPTHASH hHash = NULL) const
        {
            std::vector<_Elem, sanitizing_allocator<_Elem> > buf(std::move(decrypt(hProv, data, size, hHash)));
            return std::basic_string<_Elem, _Traits, _Ax>(buf.data(), buf.size());
        }


        ///
        /// Decrypts a wide string
        ///
        /// \param[in ] hProv  Handle of cryptographics provider
        /// \param[in ] data   Pointer to data to decrypt
        /// \param[in ] size   Size of \p data in bytes
        /// \param[out] hHash  Handle of hashing object
        ///
        /// \returns Decrypted string
        ///
        template<class _Traits, class _Ax>
        std::basic_string<wchar_t, _Traits, _Ax> decrypt_str(_In_ HCRYPTPROV hProv, _In_bytecount_(size) const void *data, _In_ size_t size, _In_opt_ HCRYPTHASH hHash = NULL) const
        {
            winstd::sanitizing_string buf(std::move(decrypt_str(hProv, data, size, hHash)));
            std::basic_string<wchar_t, _Traits, _Ax> dec;
            MultiByteToWideChar(CP_UTF8, 0, buf, dec);
            return dec;
        }


        ///
        /// Decrypts data with MD5 integrity check
        ///
        /// \param[in ] hProv  Handle of cryptographics provider
        /// \param[in ] data   Pointer to data with 16B MD5 hash appended to decrypt
        /// \param[in ] size   Size of \p data in bytes
        ///
        /// \returns Decrypted data
        ///
        template<class _Ty, class _Ax>
        std::vector<_Ty, _Ax> decrypt_md5(_In_ HCRYPTPROV hProv, _In_bytecount_(size) const void *data, _In_ size_t size) const
        {
            // Create hash.
            winstd::crypt_hash hash;
            if (!hash.create(hProv, CALG_MD5))
                throw winstd::win_runtime_error(__FUNCTION__ " Creating MD5 hash failed.");
            DWORD dwHashSize;
            CryptGetHashParam(hash, HP_HASHSIZE, dwHashSize, 0);
            if (size < dwHashSize)
                throw std::invalid_argument(__FUNCTION__ " Encrypted data too short.");
            size_t enc_size = size - dwHashSize;

            // Decrypt data.
            std::vector<_Ty, _Ax> dec(std::move(decrypt<_Ty, _Ax>(hProv, data, enc_size, hash)));

            // Calculate MD5 hash and verify it.
            std::vector<unsigned char> hash_bin;
            if (!CryptGetHashParam(hash, HP_HASHVAL, hash_bin, 0))
                throw winstd::win_runtime_error(__FUNCTION__ " Calculating MD5 hash failed.");
            if (memcmp(reinterpret_cast<const unsigned char*>(data) + enc_size, hash_bin.data(), dwHashSize) != 0)
                throw std::invalid_argument(__FUNCTION__ " Invalid encrypted data.");

            return dec;
        }


        ///
        /// Decrypts a string with MD5 integrity check
        ///
        /// \param[in ] hProv  Handle of cryptographics provider
        /// \param[in ] data   Pointer to data with 16B MD5 hash appended to decrypt
        /// \param[in ] size   Size of \p data in bytes
        ///
        /// \returns Decrypted string
        ///
        template<class _Elem, class _Traits, class _Ax>
        std::basic_string<_Elem, _Traits, _Ax> decrypt_str_md5(_In_ HCRYPTPROV hProv, _In_bytecount_(size) const void *data, _In_ size_t size) const
        {
            std::vector<_Elem, sanitizing_allocator<_Elem> > buf(std::move(decrypt_md5<_Elem, sanitizing_allocator<_Elem> >(hProv, data, size)));
            return std::basic_string<_Elem, _Traits, _Ax>(buf.data(), buf.size());
        }


        ///
        /// Decrypts a wide string with MD5 integrity check
        ///
        /// \param[in ] hProv  Handle of cryptographics provider
        /// \param[in ] data   Pointer to data with 16B MD5 hash appended to decrypt
        /// \param[in ] size   Size of \p data in bytes
        ///
        /// \returns Decrypted string
        ///
        template<class _Traits, class _Ax>
        std::basic_string<wchar_t, _Traits, _Ax> decrypt_str_md5(_In_ HCRYPTPROV hProv, _In_bytecount_(size) const void *data, _In_ size_t size) const
        {
            winstd::sanitizing_string buf(std::move(decrypt_str_md5<char, std::char_traits<char>, sanitizing_allocator<char> >(hProv, data, size)));
            std::basic_string<wchar_t, _Traits, _Ax> dec;
            MultiByteToWideChar(CP_UTF8, 0, buf, dec);
            return dec;
        }

        /// @}

        /// \name BLOB management
        /// @{

        ///
        /// Decrypts a BLOB
        ///
        /// \note When EAP_ENCRYPT_BLOBS is defined non-zero, the BLOB is decrypted; otherwise, it is copied only.
        ///
        /// \param[in   ] pDataIn       Pointer to encrypted BLOB
        /// \param[in   ] dwDataInSize  Size of \p pDataIn
        ///
        /// \returns Encrypted BLOB
        ///
        sanitizing_blob unpack(
            _In_count_(dwDataInSize) const BYTE  *pDataIn,
            _In_                           DWORD dwDataInSize)
        {
#if EAP_ENCRYPT_BLOBS
            // Prepare cryptographics provider.
            winstd::crypt_prov cp;
            if (!cp.create(NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
                throw winstd::win_runtime_error(__FUNCTION__ " CryptAcquireContext failed.");

            // Decrypt data.
            return std::move(decrypt_md5<unsigned char, winstd::sanitizing_allocator<unsigned char> >(cp, pDataIn, dwDataInSize));
#else
            return sanitizing_blob(pDataIn, pDataIn + dwDataInSize);
#endif
        }


        ///
        /// Decrypts and unpacks the BLOB
        ///
        /// \note When EAP_ENCRYPT_BLOBS is defined non-zero, the BLOB is decrypted and unpacked to the \p record; otherwise, it is unpacked to the \p record only.
        ///
        /// \param[out] record        Object to unpack to
        /// \param[in ] pDataIn       Pointer to encrypted BLOB
        /// \param[in ] dwDataInSize  Size of \p pDataIn
        ///
        template<class T>
        void unpack(
            _Out_                          T     &record,
            _In_count_(dwDataInSize) const BYTE  *pDataIn,
            _In_                           DWORD dwDataInSize)
        {
#if EAP_ENCRYPT_BLOBS
            // Prepare cryptographics provider.
            winstd::crypt_prov cp;
            if (!cp.create(NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
                throw winstd::win_runtime_error(__FUNCTION__ " CryptAcquireContext failed.");

            // Decrypt data.
            std::vector<unsigned char, winstd::sanitizing_allocator<unsigned char> > data(std::move(decrypt_md5<unsigned char, winstd::sanitizing_allocator<unsigned char> >(cp, pDataIn, dwDataInSize)));

            cursor_in cursor = { data.data(), data.data() + data.size() };
#else
            cursor_in cursor = { pDataIn, pDataIn + dwDataInSize };
#endif
            cursor >> record;
            assert(cursor.ptr == cursor.ptr_end);
        }


        ///
        /// Encrypts a BLOB
        ///
        /// \note When EAP_ENCRYPT_BLOBS is defined non-zero, the BLOB is encrypted; otherwise, it is copied only.
        ///
        /// \param[in ] data            BLOB to encrypt
        /// \param[out] ppDataOut       Pointer to pointer to receive encrypted BLOB. Pointer must be freed using `module::free_memory()`.
        /// \param[out] pdwDataOutSize  Pointer to \p ppDataOut size
        ///
        void pack(
            _In_  const sanitizing_blob &data,
            _Out_       BYTE            **ppDataOut,
            _Out_       DWORD           *pdwDataOutSize)
        {
            assert(ppDataOut);
            assert(pdwDataOutSize);

#if EAP_ENCRYPT_BLOBS
            // Prepare cryptographics provider.
            winstd::crypt_prov cp;
            if (!cp.create(NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
                throw winstd::win_runtime_error(__FUNCTION__ " CryptAcquireContext failed.");

            // Encrypt BLOB.
            std::vector<unsigned char> data_enc(std::move(encrypt_md5(cp, data.data(), data.size())));

            // Copy encrypted BLOB to output.
            *pdwDataOutSize = (DWORD)data_enc.size();
            *ppDataOut = alloc_memory(*pdwDataOutSize);
            memcpy(*ppDataOut, data_enc.data(), *pdwDataOutSize);
#else
            // Allocate and copy BLOB.
            *pdwDataOutSize = (DWORD)data.size();
            memcpy(*ppDataOut = alloc_memory(*pdwDataOutSize), data.data(), *pdwDataOutSize);
#endif
        }


        ///
        /// Packs and encrypts to the BLOB
        ///
        /// \note When EAP_ENCRYPT_BLOBS is defined non-zero, the \p record is packed and encrypted; otherwise, it is packed to an unencrypted BLOB only.
        ///
        /// \param[in ] record          Object to pack
        /// \param[out] ppDataOut       Pointer to pointer to receive encrypted BLOB. Pointer must be freed using `module::free_memory()`.
        /// \param[out] pdwDataOutSize  Pointer to \p ppDataOut size
        ///
        template<class T>
        void pack(
            _In_  const T     &record,
            _Out_       BYTE  **ppDataOut,
            _Out_       DWORD *pdwDataOutSize)
        {
            assert(ppDataOut);
            assert(pdwDataOutSize);

#if EAP_ENCRYPT_BLOBS
            // Allocate BLOB.
            std::vector<unsigned char, winstd::sanitizing_allocator<unsigned char> > data;
            data.resize(pksizeof(record));

            // Pack to BLOB.
            cursor_out cursor = { data.data(), data.data() + data.size() };
            cursor << record;
            assert(cursor.ptr == cursor.ptr_end);

            // Prepare cryptographics provider.
            winstd::crypt_prov cp;
            if (!cp.create(NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
                throw winstd::win_runtime_error(__FUNCTION__ " CryptAcquireContext failed.");

            // Encrypt BLOB.
            std::vector<unsigned char> data_enc(std::move(encrypt_md5(cp, data.data(), data.size())));

            // Copy encrypted BLOB to output.
            *pdwDataOutSize = (DWORD)data_enc.size();
            *ppDataOut = alloc_memory(*pdwDataOutSize);
            memcpy(*ppDataOut, data_enc.data(), *pdwDataOutSize);
#else
            // Allocate BLOB.
            *pdwDataOutSize = (DWORD)pksizeof(record);
            *ppDataOut = alloc_memory(*pdwDataOutSize);

            // Pack to BLOB.
            cursor_out cursor = { *ppDataOut, *ppDataOut + *pdwDataOutSize };
            cursor << record;
            assert(cursor.ptr == cursor.ptr_end);
            *pdwDataOutSize = cursor.ptr - *ppDataOut;
#endif
        }

        /// @}

    public:
        HINSTANCE m_instance;                       ///< Windows module instance
        const winstd::eap_type_t m_eap_method;      ///< EAP method type

    protected:
        winstd::heap m_heap;                        ///< Heap
        mutable winstd::event_provider m_ep;        ///< Event Provider

        /// \cond internal
        static const unsigned char s_rsa_key[1191];
        /// \endcond
    };


    ///
    /// EAP peer base class
    ///
    /// A group of methods all EAP peers must or should implement.
    ///
    class peer : public module
    {
    public:
        ///
        /// Constructs a EAP peer module for the given EAP type
        ///
        /// \param[in] eap_method  EAP method type ID
        ///
        peer(_In_ winstd::eap_type_t eap_method);

        ///
        /// Initializes an EAP peer method for EapHost.
        ///
        /// \sa [EapPeerGetInfo function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363613.aspx)
        ///
        virtual void initialize();

        ///
        /// Shuts down the EAP method and prepares to unload its corresponding DLL.
        ///
        /// \sa [EapPeerShutdown function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363627.aspx)
        ///
        virtual void shutdown();

        ///
        /// Returns the user data and user identity after being called by EapHost.
        ///
        /// \sa [EapPeerGetIdentity function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363607.aspx)
        ///
        /// \param[in ] dwFlags                  A combination of EAP flags that describe the EAP authentication session behavior.
        /// \param[in ] pConnectionData          Connection data used for the EAP method. If set to \c NULL, the static property of the method, as configured in the registry, is returned.
        /// \param[in ] dwConnectionDataSize     The size, in bytes, of the connection data buffer provided in \p pConnectionData.
        /// \param[in ] pUserData                A pointer to a byte buffer that contains the opaque user data BLOB. This parameter can be \c NULL.
        /// \param[in ] dwUserDataSize           The size, in bytes, of the user data buffer provided in \p pUserData.
        /// \param[out] ppUserDataOut            A pointer to a pointer to the returned user data. The data is passed to \p EapPeerBeginSession() as input \p pUserData.
        /// \param[out] pdwUserDataOutSize       Specifies the size, in bytes, of the \p ppUserDataOut buffer.
        /// \param[in ] hTokenImpersonateUser    A handle to the user impersonation token to use in this session.
        /// \param[out] pfInvokeUI               Returns \c TRUE if the user identity and user data blob aren't returned successfully, and the method seeks to collect the information from the user through the user interface dialog.
        /// \param[out] ppwszIdentity            A pointer to the returned user identity. The pointer will be included in the identity response packet and returned to the server.
        ///
        virtual void get_identity(
            _In_                                   DWORD  dwFlags,
            _In_count_(dwConnectionDataSize) const BYTE   *pConnectionData,
            _In_                                   DWORD  dwConnectionDataSize,
            _In_count_(dwUserDataSize)       const BYTE   *pUserData,
            _In_                                   DWORD  dwUserDataSize,
            _Out_                                  BYTE   **ppUserDataOut,
            _Out_                                  DWORD  *pdwUserDataOutSize,
            _In_                                   HANDLE hTokenImpersonateUser,
            _Out_                                  BOOL   *pfInvokeUI,
            _Out_                                  WCHAR  **ppwszIdentity);

        ///
        /// Defines the implementation of an EAP method-specific function that retrieves the properties of an EAP method given the connection and user data.
        ///
        /// \sa [EapPeerGetMethodProperties function](https://msdn.microsoft.com/en-us/library/windows/desktop/hh706636.aspx)
        ///
        /// \param[in ] dwVersion                The version number of the API.
        /// \param[in ] dwFlags                  A combination of EAP flags that describe the EAP authentication session behavior.
        /// \param[in ] hUserImpersonationToken  A handle to the user impersonation token to use in this session.
        /// \param[in ] pConnectionData          Connection data used for the EAP method. If set to \c NULL, the static property of the method, as configured in the registry, is returned.
        /// \param[in ] dwConnectionDataSize     The size, in bytes, of the connection data buffer provided in \p pConnectionData.
        /// \param[in ] pUserData                A pointer to a byte buffer that contains the opaque user data BLOB. This parameter can be \c NULL.
        /// \param[in ] dwUserDataSize           The size, in bytes, of the user data buffer provided in \p pUserData.
        /// \param[out] pMethodPropertyArray     A pointer to the method properties array. Caller should free the inner pointers using `EapHostPeerFreeMemory()` starting at the innermost pointer. The caller should free an \c empvtString value only when the type is \c empvtString.
        ///
        virtual void get_method_properties(
            _In_                                   DWORD                     dwVersion,
            _In_                                   DWORD                     dwFlags,
            _In_                                   HANDLE                    hUserImpersonationToken,
            _In_count_(dwConnectionDataSize) const BYTE                      *pConnectionData,
            _In_                                   DWORD                     dwConnectionDataSize,
            _In_count_(dwUserDataSize)       const BYTE                      *pUserData,
            _In_                                   DWORD                     dwUserDataSize,
            _Out_                                  EAP_METHOD_PROPERTY_ARRAY *pMethodPropertyArray) = 0;

        ///
        /// Converts XML into the configuration BLOB. The XML based credentials can come from group policy or from a system administrator.
        ///
        /// \sa [EapPeerCredentialsXml2Blob function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363603.aspx)
        ///
        /// \param[in ] dwFlags                A combination of EAP flags that describe the EAP authentication session behavior.
        /// \param[in ] pConfigRoot            A pointer to an XML node that contains credentials, which are either user or machine credentials depending on the configuration passed in. The XML document is created with the EapHostUserCredentials Schema.
        /// \param[in ] dwConnectionDataSize   The size of the EAP SSO configuration data pointed to by \p pConnectionData, in bytes.
        /// \param[in ] pConnectionData        A pointer to an opaque byte buffer that contains the EAP SSO configuration data BLOB.
        /// \param[out] ppCredentialsOut       A pointer to the byte buffer that receives the credentials BLOB buffer generated by the input XML. The buffer can is of size \p pdwCredentialsOutSize. After consuming the data, this memory must be freed by calling `EapPeerFreeMemory()`.
        /// \param[out] pdwCredentialsOutSize  The size, in bytes, of the buffer pointed to by \p ppCredentialsOut.
        ///
        virtual void credentials_xml2blob(
            _In_                                   DWORD       dwFlags,
            _In_                                   IXMLDOMNode *pConfigRoot,
            _In_count_(dwConnectionDataSize) const BYTE        *pConnectionData,
            _In_                                   DWORD       dwConnectionDataSize,
            _Out_                                  BYTE        **ppCredentialsOut,
            _Out_                                  DWORD       *pdwCredentialsOutSize);

        ///
        /// Defines the implementation of an EAP method-specific function that obtains the EAP Single-Sign-On (SSO) credential input fields for an EAP method.
        ///
        /// \sa [EapPeerQueryCredentialInputFields function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363622.aspx)
        ///
        /// \param[in ] hUserImpersonationToken     An impersonation token for the user whose credentials are to be requested and obtained.
        /// \param[in ] dwFlags                     A combination of EAP flags that describe the EAP authentication session behavior.
        /// \param[in ] dwConnectionDataSize        The size of the EAP SSO configuration data pointed to by \p pConnectionData, in bytes.
        /// \param[in ] pConnectionData             A pointer to an opaque byte buffer that contains the EAP SSO configuration data BLOB.
        /// \param[out] pEapConfigInputFieldsArray  A Pointer to a structure that contains the input fields to display to the supplicant user. The `pwszData` fields in the individual `EAP_CONFIG_INPUT_FIELD_DATA` elements are initialized to \c NULL.
        ///
        virtual void query_credential_input_fields(
            _In_                                   HANDLE                       hUserImpersonationToken,
            _In_                                   DWORD                        dwFlags,
            _In_                                   DWORD                        dwConnectionDataSize,
            _In_count_(dwConnectionDataSize) const BYTE                         *pConnectionData,
            _Out_                                  EAP_CONFIG_INPUT_FIELD_ARRAY *pEapConfigInputFieldsArray) const;

        ///
        /// Defines the implementation of an EAP method function that obtains the user BLOB data provided in an interactive Single-Sign-On (SSO) UI raised on the supplicant.
        ///
        /// \sa [EapPeerQueryUserBlobFromCredentialInputFields function](https://msdn.microsoft.com/en-us/library/windows/desktop/bb204697.aspx)
        ///
        /// \param[in ] hUserImpersonationToken    An impersonation token for the user whose credentials are to be requested and obtained.
        /// \param[in ] dwFlags                    A combination of EAP flags that describe the EAP authentication session behavior.
        /// \param[in ] dwConnectionDataSize       The size of the EAP SSO configuration data pointed to by \p pConnectionData, in bytes.
        /// \param[in ] pConnectionData            A pointer to an opaque byte buffer that contains the EAP SSO configuration data BLOB.
        /// \param[in ] pEapConfigInputFieldArray  A pointer to a structure that contains the input fields to display to the supplicant user. The `pwszData` fields in the individual `EAP_CONFIG_INPUT_FIELD_DATA` elements are initialized to \c NULL.
        /// \param[out] pdwUsersBlobSize           A pointer to a buffer that contains the size, in bytes, of the opaque user configuration data BLOB in \p ppUserBlob.
        /// \param[out] ppUserBlob                 A pointer that contains the opaque user data BLOB.
        ///
        virtual void query_user_blob_from_credential_input_fields(
            _In_                                   HANDLE                       hUserImpersonationToken,
            _In_                                   DWORD                        dwFlags,
            _In_                                   DWORD                        dwConnectionDataSize,
            _In_count_(dwConnectionDataSize) const BYTE                         *pConnectionData,
            _In_                             const EAP_CONFIG_INPUT_FIELD_ARRAY *pEapConfigInputFieldArray,
            _Out_                                  DWORD                        *pdwUsersBlobSize,
            _Out_                                  BYTE                         **ppUserBlob) const;

        ///
        /// Defines the implementation of an EAP method API that provides the input fields for interactive UI components to be raised on the supplicant.
        ///
        /// \sa [EapPeerQueryInteractiveUIInputFields function](https://msdn.microsoft.com/en-us/library/windows/desktop/bb204695.aspx)
        ///
        /// \param[in ] dwVersion              The version number of the API.
        /// \param[in ] dwFlags                A combination of EAP flags that describe the EAP authentication session behavior.
        /// \param[in ] dwUIContextDataSize    The size of the context data in \p pUIContextData, in bytes.
        /// \param[in ] pUIContextData         A pointer to a BLOB that contains UI context data, represented as inner pointers to field data. The supplicant obtained these inner pointers from EAPHost run-time APIs.
        /// \param[out] pEapInteractiveUIData  Pointer that receives a structure that contains configuration information for interactive UI components raised on an EAP supplicant.
        ///
        virtual void query_interactive_ui_input_fields(
            _In_                                  DWORD                   dwVersion,
            _In_                                  DWORD                   dwFlags,
            _In_                                  DWORD                   dwUIContextDataSize,
            _In_count_(dwUIContextDataSize) const BYTE                    *pUIContextData,
            _Out_                                 EAP_INTERACTIVE_UI_DATA *pEapInteractiveUIData) const;

        ///
        /// Converts user information into a user BLOB that can be consumed by EapHost run-time functions.
        ///
        /// \sa [EapPeerQueryUIBlobFromInteractiveUIInputFields function](https://msdn.microsoft.com/en-us/library/windows/desktop/bb204696.aspx)
        ///
        /// \param[in ] dwVersion                     The version number of the API.
        /// \param[in ] dwFlags                       A combination of EAP flags that describe the EAP authentication session behavior.
        /// \param[in ] dwUIContextDataSize           The size of the context data in \p pUIContextData, in bytes.
        /// \param[in ] pUIContextData                A pointer to a BLOB that contains UI context data, represented as inner pointers to field data. The supplicant obtained these inner pointers from EAPHost run-time APIs.
        /// \param[in ] pEapInteractiveUIData         Pointer with a structure that contains configuration information for interactive user interface components raised on an EAP supplicant.
        /// \param[out] pdwDataFromInteractiveUISize  A pointer to a `DWORD` that specifies the size of the buffer pointed to by the \p ppDataFromInteractiveUI parameter, in bytes. If this value is not set to \c 0, then a pointer to a buffer of the size specified in this parameter must be supplied in the \p ppDataFromInteractiveUI parameter.
        /// \param[out] ppDataFromInteractiveUI       A pointer that receives a credentials BLOB that can be used in authentication. The caller should free the inner pointers using the function \p EapPeerFreeMemory(), starting at the innermost pointer. If a non-NULL value is supplied for this parameter, meaning that an existing data BLOB is passed to it, the supplied data BLOB will be updated and returned in this parameter.
        ///
        virtual void query_ui_blob_from_interactive_ui_input_fields(
            _In_                                                        DWORD                   dwVersion,
            _In_                                                        DWORD                   dwFlags,
            _In_                                                        DWORD                   dwUIContextDataSize,
            _In_count_(dwUIContextDataSize)                       const BYTE                    *pUIContextData,
            _In_                                                  const EAP_INTERACTIVE_UI_DATA *pEapInteractiveUIData,
            _Out_                                                       DWORD                   *pdwDataFromInteractiveUISize,
            _Outptr_result_buffer_(*pdwDataFromInteractiveUISize)       BYTE                    **ppDataFromInteractiveUI) const;

        /// \name Session management
        /// @{

        ///
        /// Starts an EAP authentication session on the peer EapHost using the EAP method.
        ///
        /// \sa [EapPeerBeginSession function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363600.aspx)
        ///
        /// \param[in] dwFlags                A combination of EAP flags that describe the new EAP authentication session behavior.
        /// \param[in] pAttributeArray        A pointer to an array structure that specifies the EAP attributes of the entity to authenticate.
        /// \param[in] hTokenImpersonateUser  Specifies a handle to the user impersonation token to use in this session.
        /// \param[in] pConnectionData        Connection data specific to this method used to decide the user data returned from this API, where the user data depends on certain connection data configuration. When this parameter is NULL the method implementation should use default values for connection.
        /// \param[in] dwConnectionDataSize   Specifies the size, in bytes, of the connection data buffer provided in \p pConnectionData.
        /// \param[in] pUserData              A pointer to a byte buffer that contains the opaque user data BLOB.
        /// \param[in] dwUserDataSize         Specifies the size in bytes of the user data buffer provided in \p pUserData.
        /// \param[in] dwMaxSendPacketSize    Specifies the maximum size in bytes of an EAP packet sent during the session. If the method needs to send a packet larger than the maximum size, the method must accommodate fragmentation and reassembly.
        ///
        /// \returns Session handle
        ///
        virtual EAP_SESSION_HANDLE begin_session(
            _In_                                   DWORD         dwFlags,
            _In_                             const EapAttributes *pAttributeArray,
            _In_                                   HANDLE        hTokenImpersonateUser,
            _In_count_(dwConnectionDataSize) const BYTE          *pConnectionData,
            _In_                                   DWORD         dwConnectionDataSize,
            _In_count_(dwUserDataSize)       const BYTE          *pUserData,
            _In_                                   DWORD         dwUserDataSize,
            _In_                                   DWORD         dwMaxSendPacketSize);

        ///
        /// Ends an EAP authentication session for the EAP method.
        ///
        /// \sa [EapPeerEndSession function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363604.aspx)
        ///
        /// \param[in] hSession  A unique handle for this EAP authentication session on the EAPHost server. This handle is returned in the \p pSessionHandle parameter in a previous call to `EapPeerBeginSession()`.
        ///
        virtual void end_session(_In_ EAP_SESSION_HANDLE hSession);

        /// @}

        /// \name Packet processing
        /// @{

        ///
        /// Processes a packet received by EapHost from a supplicant.
        ///
        /// \sa [EapPeerProcessRequestPacket function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363621.aspx)
        ///
        /// \param[in] hSession              A unique handle for this EAP authentication session on the EAPHost server. This handle is returned in the \p pSessionHandle parameter in a previous call to `EapPeerBeginSession()`.
        /// \param[in] pReceivedPacket       Received packet data
        /// \param[in] dwReceivedPacketSize  \p pReceivedPacket size in bytes
        /// \param[in] pEapOutput            A pointer to a structure that contains the output of the packet process operation.
        ///
        virtual void process_request_packet(
            _In_                                       EAP_SESSION_HANDLE  hSession,
            _In_bytecount_(dwReceivedPacketSize) const EapPacket           *pReceivedPacket,
            _In_                                       DWORD               dwReceivedPacketSize,
            _Out_                                      EapPeerMethodOutput *pEapOutput);

        ///
        /// Obtains a response packet from the EAP method.
        ///
        /// \sa [EapPeerGetResponsePacket function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363610.aspx)
        ///
        /// \param[in   ] hSession           A unique handle for this EAP authentication session on the EAPHost server. This handle is returned in the \p pSessionHandle parameter in a previous call to `EapPeerBeginSession()`.
        /// \param[inout] pSendPacket        A pointer to a structure that contains the response packet.
        /// \param[inout] pdwSendPacketSize  A pointer to a value that contains the size in bytes of the buffer allocated for the response packet. On return, this parameter receives a pointer to the actual size in bytes of \p pSendPacket.
        ///
        virtual void get_response_packet(
            _In_                                   EAP_SESSION_HANDLE hSession,
            _Out_bytecapcount_(*pdwSendPacketSize) EapPacket          *pSendPacket,
            _Inout_                                DWORD              *pdwSendPacketSize);

        /// @}

        ///
        /// Obtains the result of an authentication session from the EAP method.
        ///
        /// \sa [EapPeerGetResult function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363611.aspx)
        ///
        /// \param[in   ] hSession  A unique handle for this EAP authentication session on the EAPHost server. This handle is returned in the \p pSessionHandle parameter in a previous call to `EapPeerBeginSession()`.
        /// \param[in   ] reason    The reason code for the authentication result returned in \p pResult.
        /// \param[inout] pResult   A pointer to a structure that contains the authentication results.
        ///
        virtual void get_result(
            _In_    EAP_SESSION_HANDLE        hSession,
            _In_    EapPeerMethodResultReason reason,
            _Inout_ EapPeerMethodResult       *pResult);

        /// \name User Interaction
        /// @{

        ///
        /// Obtains the user interface context from the EAP method.
        ///
        /// \note This function is always followed by the `EapPeerInvokeInteractiveUI()` function, which is followed by the `EapPeerSetUIContext()` function.
        ///
        /// \sa [EapPeerGetUIContext function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363612.aspx)
        ///
        /// \param[in ] hSession              A unique handle for this EAP authentication session on the EAPHost server. This handle is returned in the \p pSessionHandle parameter in a previous call to `EapPeerBeginSession()`.
        /// \param[out] ppUIContextData       A pointer to an address that contains a byte buffer with the supplicant user interface context data from EAPHost.
        /// \param[out] pdwUIContextDataSize  A pointer to a value that specifies the size of the user interface context data byte buffer returned in \p ppUIContextData.
        ///
        virtual void get_ui_context(
            _In_  EAP_SESSION_HANDLE hSession,
            _Out_ BYTE               **ppUIContextData,
            _Out_ DWORD              *pdwUIContextDataSize);

        ///
        /// Provides a user interface context to the EAP method.
        ///
        /// \note This function is called after the UI has been raised through the `EapPeerGetUIContext()` function.
        ///
        /// \sa [EapPeerSetUIContext function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363626.aspx)
        ///
        /// \param[in] hSession             A unique handle for this EAP authentication session on the EAPHost server. This handle is returned in the \p pSessionHandle parameter in a previous call to `EapPeerBeginSession()`.
        /// \param[in] pUIContextData       A pointer to an address that contains a byte buffer with the new supplicant UI context data to set on EAPHost.
        /// \param[in] dwUIContextDataSize  \p pUIContextData size in bytes
        /// \param[in] pEapOutput           A pointer to a structure that contains the output of the packet process operation.
        ///
        virtual void set_ui_context(
            _In_                                  EAP_SESSION_HANDLE  hSession,
            _In_count_(dwUIContextDataSize) const BYTE                *pUIContextData,
            _In_                                  DWORD               dwUIContextDataSize,
            _Out_                                 EapPeerMethodOutput *pEapOutput);

        /// @}

        /// \name EAP Response Attributes
        /// @{

        ///
        /// Obtains an array of EAP response attributes from the EAP method.
        ///
        /// \sa [EapPeerGetResponseAttributes function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363609.aspx)
        ///
        /// \param[in ] hSession  A unique handle for this EAP authentication session on the EAPHost server. This handle is returned in the \p pSessionHandle parameter in a previous call to `EapPeerBeginSession()`.
        /// \param[out] pAttribs  A pointer to a structure that contains an array of EAP authentication response attributes for the supplicant.
        ///
        virtual void get_response_attributes(
            _In_  EAP_SESSION_HANDLE hSession,
            _Out_ EapAttributes      *pAttribs);

        ///
        /// Provides an updated array of EAP response attributes to the EAP method.
        ///
        /// \sa [EapPeerSetResponseAttributes function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363625.aspx)
        ///
        /// \param[in] hSession    A unique handle for this EAP authentication session on the EAPHost server. This handle is returned in the \p pSessionHandle parameter in a previous call to `EapPeerBeginSession()`.
        /// \param[in] pAttribs    A pointer to a structure that contains an array of new EAP authentication response attributes to set for the supplicant on EAPHost.
        /// \param[in] pEapOutput  A pointer to a structure that contains the output of the packet process operation.
        ///
        virtual void set_response_attributes(
            _In_       EAP_SESSION_HANDLE  hSession,
            _In_ const EapAttributes       *pAttribs,
            _Out_      EapPeerMethodOutput *pEapOutput);

        /// @}

    protected:
        ///
        /// Makes a new method
        ///
        /// \param[in] cfg   Method configuration
        /// \param[in] cred  Credentials
        ///
        /// \returns A new method
        ///
        virtual method* make_method(_In_ config_method &cfg, _In_ credentials &cred) = 0;

        ///
        /// Checks all configured providers and tries to combine credentials.
        ///
        _Success_(return != 0) virtual const config_method_with_cred* combine_credentials(
            _In_                             DWORD                   dwFlags,
            _In_                       const config_connection       &cfg,
            _In_count_(dwUserDataSize) const BYTE                    *pUserData,
            _In_                             DWORD                   dwUserDataSize,
            _Inout_                          credentials_connection& cred_out,
            _In_                             HANDLE                  hTokenImpersonateUser) = 0;

    protected:
        ///
        /// Peer session
        ///
        /// Maintains EapHost session context.
        ///
        class session {
        public:
            ///
            /// Constructs a session
            ///
            session(_In_ module &mod);

            ///
            /// Destructs the session
            ///
            virtual ~session();

        public:
            module &m_module;                   ///< Module
            config_connection m_cfg;            ///< Connection configuration
            credentials_connection m_cred;      ///< Connection credentials
            std::unique_ptr<method> m_method;   ///< EAP method

            // The following members are required to avoid memory leakage in get_result() and get_ui_context().
            BYTE *m_blob_cfg;                   ///< Configuration BLOB
#if EAP_USE_NATIVE_CREDENTIAL_CACHE
            BYTE *m_blob_cred;                  ///< Credentials BLOB
#endif
            BYTE *m_blob_ui_ctx;                ///< User Interface context data
        };
    };

    /// @}
}
