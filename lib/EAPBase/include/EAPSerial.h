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

#include <WinStd/Crypt.h>

#include <sal.h>

#include <list>
#include <string>
#include <vector>

namespace eapserial
{
    ///
    /// Packs a primitive data
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     Variable with data to pack
    ///
    template <class T> inline void pack(_Inout_ unsigned char *&cursor, _In_ const T &val);

    ///
    /// Returns packed size of a primitive data
    ///
    /// \param[in] val  Data to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    template <class T> inline size_t get_pk_size(_In_ const T &val);

    ///
    /// Unpacks a primitive data
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[out]   val     Variable to receive unpacked value
    ///
    template <class T> inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ T &val);

    ///
    /// Packs a string
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     String to pack
    ///
    template<class _Elem, class _Traits, class _Ax> inline void pack(_Inout_ unsigned char *&cursor, _In_ const std::basic_string<_Elem, _Traits, _Ax> &val);

    ///
    /// Returns packed size of a string
    ///
    /// \param[in] val  String to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    template<class _Elem, class _Traits, class _Ax> inline size_t get_pk_size(const std::basic_string<_Elem, _Traits, _Ax> &val);

    ///
    /// Unpacks a string
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[out]   val     String to unpack to
    ///
    template<class _Elem, class _Traits, class _Ax> inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ std::basic_string<_Elem, _Traits, _Ax> &val);

    ///
    /// Packs a wide string
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     String to pack
    ///
    template<class _Traits, class _Ax> inline void pack(_Inout_ unsigned char *&cursor, _In_ const std::basic_string<wchar_t, _Traits, _Ax> &val);

    ///
    /// Returns packed size of a wide string
    ///
    /// \param[in] val  String to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    template<class _Traits, class _Ax> inline size_t get_pk_size(const std::basic_string<wchar_t, _Traits, _Ax> &val);

    ///
    /// Unpacks a wide string
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[out]   val     String to unpack to
    ///
    template<class _Traits, class _Ax> inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ std::basic_string<wchar_t, _Traits, _Ax> &val);

    ///
    /// Packs a vector
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     Vector to pack
    ///
    template<class _Ty, class _Ax> inline void pack(_Inout_ unsigned char *&cursor, _In_ const std::vector<_Ty, _Ax> &val);

    ///
    /// Returns packed size of a vector
    ///
    /// \param[in] val  Vector to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    template<class _Ty, class _Ax> inline size_t get_pk_size(const std::vector<_Ty, _Ax> &val);

    ///
    /// Unpacks a vector
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[out]   val     Vector to unpack to
    ///
    template<class _Ty, class _Ax> inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ std::vector<_Ty, _Ax> &val);

    ///
    /// Packs a list
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     List to pack
    ///
    template<class _Ty, class _Ax> inline void pack(_Inout_ unsigned char *&cursor, _In_ const std::list<_Ty, _Ax> &val);

    ///
    /// Returns packed size of a list
    ///
    /// \param[in] val  List to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    template<class _Ty, class _Ax> inline size_t get_pk_size(const std::list<_Ty, _Ax> &val);

    ///
    /// Unpacks a list
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[out]   val     List to unpack to
    ///
    template<class _Ty, class _Ax> inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ std::list<_Ty, _Ax> &val);

    ///
    /// Packs a certificate context
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     Certificate context to pack
    ///
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const winstd::cert_context &val);

    ///
    /// Returns packed size of a certificate context
    ///
    /// \param[in] val  Certificate context to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    inline size_t get_pk_size(const winstd::cert_context &val);

    ///
    /// Unpacks a certificate context
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[out]   val     Certificate context to unpack to
    ///
    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ winstd::cert_context &val);
}

#pragma once


namespace eapserial
{
    template <class T>
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const T &val)
    {
        memcpy(cursor, &val, sizeof(T));
        cursor += sizeof(T);
    }


    template <class T>
    inline size_t get_pk_size(_In_ const T &val)
    {
        UNREFERENCED_PARAMETER(val);
        return sizeof(T);
    }


    template <class T>
    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ T &val)
    {
        memcpy(&val, cursor, sizeof(T));
        cursor += sizeof(T);
    }


    template<class _Elem, class _Traits, class _Ax>
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const std::basic_string<_Elem, _Traits, _Ax> &val)
    {
        std::basic_string<_Elem, _Traits, _Ax>::size_type count = val.length();
        *(std::basic_string<_Elem, _Traits, _Ax>::size_type*&)cursor = count;
        cursor += sizeof(std::basic_string<_Elem, _Traits, _Ax>::size_type);

        size_t nSize = sizeof(_Elem)*count;
        memcpy(cursor, (const _Elem*)val.c_str(), nSize);
        cursor += nSize;
    }


    template<class _Elem, class _Traits, class _Ax>
    inline size_t get_pk_size(const std::basic_string<_Elem, _Traits, _Ax> &val)
    {
        return sizeof(std::basic_string<_Elem, _Traits, _Ax>::size_type) + sizeof(_Elem)*val.length();
    }


    template<class _Elem, class _Traits, class _Ax>
    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ std::basic_string<_Elem, _Traits, _Ax> &val)
    {
        std::basic_string<_Elem, _Traits, _Ax>::size_type count = *(const std::basic_string<_Elem, _Traits, _Ax>::size_type*&)cursor;
        cursor += sizeof(std::basic_string<_Elem, _Traits, _Ax>::size_type);

        val.assign((const _Elem*&)cursor, count);
        cursor += sizeof(_Elem)*count;
    }


    template<class _Traits, class _Ax>
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const std::basic_string<wchar_t, _Traits, _Ax> &val)
    {
        std::string val_utf8;
        WideCharToMultiByte(CP_UTF8, 0, val.c_str(), (int)val.length(), val_utf8, NULL, NULL);
        pack(cursor, val_utf8);
    }


    template<class _Traits, class _Ax>
    inline size_t get_pk_size(const std::basic_string<wchar_t, _Traits, _Ax> &val)
    {
        return sizeof(std::string::size_type) + sizeof(char)*WideCharToMultiByte(CP_UTF8, 0, val.c_str(), (int)val.length(), NULL, 0, NULL, NULL);
    }


    template<class _Traits, class _Ax>
    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ std::basic_string<wchar_t, _Traits, _Ax> &val)
    {
        std::string val_utf8;
        unpack(cursor, val_utf8);
        MultiByteToWideChar(CP_UTF8, 0, val_utf8.c_str(), (int)val_utf8.length(), val);
    }


    template<class _Ty, class _Ax>
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const std::vector<_Ty, _Ax> &val)
    {
        std::vector<_Ty, _Ax>::size_type count = val.size();
        *(std::vector<_Ty, _Ax>::size_type*&)cursor = count;
        cursor += sizeof(std::vector<_Ty, _Ax>::size_type);

        // Since we do not know wheter vector elements are primitives or objects, iterate instead of memcpy.
        // For performance critical vectors of flat opaque data types write specialized template instantiation.
        for (std::vector<_Ty, _Ax>::size_type i = 0; i < count; i++)
            pack(cursor, val[i]);
    }


    template<class _Ty, class _Ax>
    inline size_t get_pk_size(const std::vector<_Ty, _Ax> &val)
    {
        // Since we do not know wheter vector elements are primitives or objects, iterate instead of sizeof().
        // For performance critical vectors of flat opaque data types write specialized template instantiation.
        size_t size = sizeof(std::vector<_Ty, _Ax>::size_type);
        for (std::vector<_Ty, _Ax>::size_type i = 0, count = val.size(); i < count; i++)
            size += get_pk_size(val[i]);
        return size;
    }


    template<class _Ty, class _Ax>
    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ std::vector<_Ty, _Ax> &val)
    {
        std::vector<_Ty, _Ax>::size_type count = *(const std::vector<_Ty, _Ax>::size_type*&)cursor;
        cursor += sizeof(std::vector<_Ty, _Ax>::size_type);

        // Since we do not know wheter vector elements are primitives or objects, iterate instead of assign().
        // For performance critical vectors of flat opaque data types write specialized template instantiation.
        val.clear();
        val.reserve(count);
        for (std::vector<_Ty, _Ax>::size_type i = 0; i < count; i++) {
            _Ty el;
            unpack(cursor, el);
            val.push_back(el);
        }
    }


    template<class _Ty, class _Ax>
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const std::list<_Ty, _Ax> &val)
    {
        std::list<_Ty, _Ax>::size_type count = val.size();
        *(std::list<_Ty, _Ax>::size_type*&)cursor = count;
        cursor += sizeof(std::list<_Ty, _Ax>::size_type);

        // Since we do not know wheter list elements are primitives or objects, iterate instead of memcpy.
        // For performance critical vectors of flat opaque data types write specialized template instantiation.
        for (std::list<_Ty, _Ax>::const_iterator i = val.cbegin(), i_end = val.cend(); i != i_end; ++i)
            pack(cursor, *i);
    }


    template<class _Ty, class _Ax>
    inline size_t get_pk_size(const std::list<_Ty, _Ax> &val)
    {
        // Since we do not know wheter list elements are primitives or objects, iterate instead of sizeof().
        // For performance critical vectors of flat opaque data types write specialized template instantiation.
        size_t size = sizeof(std::list<_Ty, _Ax>::size_type);
        for (std::list<_Ty, _Ax>::const_iterator i = val.cbegin(), i_end = val.cend(); i != i_end; ++i)
            size += get_pk_size(*i);
        return size;
    }


    template<class _Ty, class _Ax>
    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ std::list<_Ty, _Ax> &val)
    {
        std::list<_Ty, _Ax>::size_type count = *(const std::list<_Ty, _Ax>::size_type*&)cursor;
        cursor += sizeof(std::list<_Ty, _Ax>::size_type);

        // Since we do not know wheter list elements are primitives or objects, iterate instead of assign().
        // For performance critical vectors of flat opaque data types write specialized template instantiation.
        val.clear();
        for (std::list<_Ty, _Ax>::size_type i = 0; i < count; i++) {
            _Ty el;
            unpack(cursor, el);
            val.push_back(el);
        }
    }


    inline void pack(_Inout_ unsigned char *&cursor, _In_ const winstd::cert_context &val)
    {
        *(DWORD*&)cursor = val->dwCertEncodingType;
        cursor += sizeof(DWORD);

        *(DWORD*&)cursor = val->cbCertEncoded;
        cursor += sizeof(DWORD);

        memcpy(cursor, val->pbCertEncoded, val->cbCertEncoded);
        cursor += val->cbCertEncoded;
    }


    inline size_t get_pk_size(const winstd::cert_context &val)
    {
        return sizeof(DWORD) + sizeof(DWORD) + val->cbCertEncoded;
    }


    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ winstd::cert_context &val)
    {
        DWORD dwCertEncodingType = *(DWORD*&)cursor;
        cursor += sizeof(DWORD);

        DWORD dwCertEncodedSize = *(DWORD*&)cursor;
        cursor += sizeof(DWORD);

        val.create(dwCertEncodingType, (BYTE*)cursor, dwCertEncodedSize);
        cursor += dwCertEncodedSize;
    }
}
