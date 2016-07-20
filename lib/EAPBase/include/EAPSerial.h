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
    /// Packs a boolean
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     Variable with data to pack
    ///
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const bool &val);

    ///
    /// Returns packed size of a boolean
    ///
    /// \param[in] val  Data to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    inline size_t get_pk_size(_In_ const bool &val);

    ///
    /// Unpacks a boolean
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[out]   val     Variable to receive unpacked value
    ///
    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ bool &val);

    ///
    /// Packs a byte
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     Variable with data to pack
    ///
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const unsigned char &val);

    ///
    /// Returns packed size of a byte
    ///
    /// \param[in] val  Data to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    inline size_t get_pk_size(_In_ const unsigned char &val);

    ///
    /// Unpacks a byte
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[out]   val     Variable to receive unpacked value
    ///
    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ unsigned char &val);

    ///
    /// Packs an unsigned int
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     Variable with data to pack
    ///
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const unsigned int &val);

    ///
    /// Returns packed size of an unsigned int
    ///
    /// \param[in] val  Data to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    inline size_t get_pk_size(_In_ const unsigned int &val);

    ///
    /// Unpacks an unsigned int
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[out]   val     Variable to receive unpacked value
    ///
    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ unsigned int &val);

#ifdef _WIN64
    ///
    /// Packs a size_t
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     Variable with data to pack
    ///
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const size_t &val);

    ///
    /// Returns packed size of a size_t
    ///
    /// \param[in] val  Data to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    inline size_t get_pk_size(_In_ const size_t &val);

    ///
    /// Unpacks a size_t
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[out]   val     Variable to receive unpacked value
    ///
    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ size_t &val);
#endif

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
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const bool &val)
    {
        *cursor = val ? 1 : 0;
        cursor++;
    }


    inline size_t get_pk_size(_In_ const bool &val)
    {
        UNREFERENCED_PARAMETER(val);
        return sizeof(unsigned char);
    }


    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ bool &val)
    {
        val = *cursor ? true : false;
        cursor++;
    }


    inline void pack(_Inout_ unsigned char *&cursor, _In_ const unsigned char &val)
    {
        *cursor = val;
        cursor++;
    }


    inline size_t get_pk_size(_In_ const unsigned char &val)
    {
        UNREFERENCED_PARAMETER(val);
        return sizeof(unsigned char);
    }


    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ unsigned char &val)
    {
        val = *cursor;
        cursor++;
    }


    inline void pack(_Inout_ unsigned char *&cursor, _In_ const unsigned int &val)
    {
        *(unsigned int*)cursor = val;
        cursor += sizeof(unsigned int);
    }


    inline size_t get_pk_size(_In_ const unsigned int &val)
    {
        UNREFERENCED_PARAMETER(val);
        return sizeof(unsigned int);
    }


    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ unsigned int &val)
    {
        val = *(unsigned int*)cursor;
        cursor += sizeof(unsigned int);
    }


#ifdef _WIN64
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const size_t &val)
    {
        *(size_t*)cursor = val;
        cursor += sizeof(size_t);
    }


    inline size_t get_pk_size(_In_ const size_t &val)
    {
        UNREFERENCED_PARAMETER(val);
        return sizeof(size_t);
    }


    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ size_t &val)
    {
        val = *(size_t*)cursor;
        cursor += sizeof(size_t);
    }
#endif


    template<class _Elem, class _Traits, class _Ax>
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const std::basic_string<_Elem, _Traits, _Ax> &val)
    {
        std::basic_string<_Elem, _Traits, _Ax>::size_type count = val.length();
        assert(strlen(val.c_str()) == count); // String should not contain null characters
        size_t nSize = sizeof(_Elem)*(count + 1);
        memcpy(cursor, (const _Elem*)val.c_str(), nSize);
        cursor += nSize;
    }


    template<class _Elem, class _Traits, class _Ax>
    inline size_t get_pk_size(const std::basic_string<_Elem, _Traits, _Ax> &val)
    {
        return sizeof(_Elem)*(val.length() + 1);
    }


    template<class _Elem, class _Traits, class _Ax>
    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ std::basic_string<_Elem, _Traits, _Ax> &val)
    {
        std::basic_string<_Elem, _Traits, _Ax>::size_type count = strlen((const _Elem*&)cursor);
        val.assign((const _Elem*&)cursor, count);
        cursor += sizeof(_Elem)*(count + 1);
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
        return sizeof(std::string::size_type) + WideCharToMultiByte(CP_UTF8, 0, val.c_str(), (int)val.length(), NULL, 0, NULL, NULL);
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
        pack(cursor, count);

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
        std::vector<_Ty, _Ax>::size_type count = val.size();
        size_t size = get_pk_size(count);
        for (std::vector<_Ty, _Ax>::size_type i = 0; i < count; i++)
            size += get_pk_size(val[i]);
        return size;
    }


    template<class _Ty, class _Ax>
    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ std::vector<_Ty, _Ax> &val)
    {
        std::vector<_Ty, _Ax>::size_type count;
        unpack(cursor, count);

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
        pack(cursor, count);

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
        std::list<_Ty, _Ax>::size_type count = val.size();
        size_t size = get_pk_size(count);
        for (std::list<_Ty, _Ax>::const_iterator i = val.cbegin(), i_end = val.cend(); i != i_end; ++i)
            size += get_pk_size(*i);
        return size;
    }


    template<class _Ty, class _Ax>
    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ std::list<_Ty, _Ax> &val)
    {
        std::list<_Ty, _Ax>::size_type count;
        unpack(cursor, count);

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
        if (val) {
            pack(cursor, (unsigned int)val->dwCertEncodingType);
            pack(cursor, (unsigned int)val->cbCertEncoded     );
            memcpy(cursor, val->pbCertEncoded, val->cbCertEncoded);
            cursor += val->cbCertEncoded;
        } else {
            pack(cursor, (unsigned int)0);
            pack(cursor, (unsigned int)0);
        }
    }


    inline size_t get_pk_size(const winstd::cert_context &val)
    {
        return
            val ?
                get_pk_size((unsigned int)val->dwCertEncodingType) +
                get_pk_size((unsigned int)val->cbCertEncoded     ) +
                val->cbCertEncoded :
                get_pk_size((unsigned int)0) +
                get_pk_size((unsigned int)0);
    }


    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ winstd::cert_context &val)
    {
        DWORD dwCertEncodingType;
        unpack(cursor, (unsigned int&)dwCertEncodingType);

        DWORD dwCertEncodedSize;
        unpack(cursor, (unsigned int&)dwCertEncodedSize);

        if (dwCertEncodedSize) {
            val.create(dwCertEncodingType, (BYTE*)cursor, dwCertEncodedSize);
            cursor += dwCertEncodedSize;
        } else
            val.free();
    }
}
