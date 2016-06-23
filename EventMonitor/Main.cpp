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

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "Ws2_32.lib")

using namespace std;
using namespace winstd;

static vector<TRACEHANDLE> g_traces;


static BOOL WINAPI ConsoleHandler(_In_ DWORD dwCtrlType)
{
    switch(dwCtrlType) {
    case CTRL_C_EVENT: 
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        for (vector<TRACEHANDLE>::const_iterator trace = g_traces.cbegin(), trace_end = g_traces.cend(); trace != trace_end; ++trace)
            CloseTrace(*trace);
    }
    return TRUE;
}


static tstring MapToString(_In_ const EVENT_MAP_INFO *pMapInfo, _In_ LPCBYTE pData)
{
    if ( (pMapInfo->Flag &  EVENTMAP_INFO_FLAG_MANIFEST_VALUEMAP) ||
        ((pMapInfo->Flag &  EVENTMAP_INFO_FLAG_WBEM_VALUEMAP    ) && (pMapInfo->Flag & ~EVENTMAP_INFO_FLAG_WBEM_VALUEMAP) != EVENTMAP_INFO_FLAG_WBEM_FLAG))
    {
        if ((pMapInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_NO_MAP) == EVENTMAP_INFO_FLAG_WBEM_NO_MAP)
            return tstring_printf(_T("%ls"), (PBYTE)pMapInfo + pMapInfo->MapEntryArray[*(PULONG)pData].OutputOffset);
        else {
            for (ULONG i = 0; ; i++) {
                if (i >= pMapInfo->EntryCount)
                    return tstring_printf(_T("%lu"), *(PULONG)pData);
                else if (pMapInfo->MapEntryArray[i].Value == *(PULONG)pData)
                    return tstring_printf(_T("%ls"), (PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset);
            }
        }
    } else if (
         (pMapInfo->Flag &  EVENTMAP_INFO_FLAG_MANIFEST_BITMAP) ||
         (pMapInfo->Flag &  EVENTMAP_INFO_FLAG_WBEM_BITMAP    ) ||
        ((pMapInfo->Flag &  EVENTMAP_INFO_FLAG_WBEM_VALUEMAP  ) && (pMapInfo->Flag & ~EVENTMAP_INFO_FLAG_WBEM_VALUEMAP) == EVENTMAP_INFO_FLAG_WBEM_FLAG))
    {
        tstring out;

        if (pMapInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_NO_MAP) {
            for (ULONG i = 0; i < pMapInfo->EntryCount; i++)
                if (*(PULONG)pData & (1 << i))
                    out.append(tstring_printf(out.empty() ? _T("%ls") : _T(" | %ls"), (PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset));
        } else {
            for (ULONG i = 0; i < pMapInfo->EntryCount; i++)
                if ((pMapInfo->MapEntryArray[i].Value & *(PULONG)pData) == pMapInfo->MapEntryArray[i].Value)
                    out.append(tstring_printf(out.empty() ? _T("%ls") : _T(" | %ls"), (PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset));
        }

        return out.empty() ? tstring_printf(_T("%lu"), *(PULONG)pData) : out;
    }

    return _T("<unknown map>");
}


static tstring DataToString(_In_ USHORT InType, _In_ USHORT OutType, _In_count_(nDataSize) LPCBYTE pData, _In_ SIZE_T nDataSize, _In_ const EVENT_MAP_INFO *pMapInfo, _In_ BYTE nPtrSize)
{
    assert(pData || !nDataSize);

    switch (InType) {
        case TDH_INTYPE_UNICODESTRING:
        case TDH_INTYPE_NONNULLTERMINATEDSTRING:
        case TDH_INTYPE_UNICODECHAR:
            return tstring_printf(_T("%.*ls"), nDataSize/sizeof(WCHAR), pData);

        case TDH_INTYPE_ANSISTRING:
        case TDH_INTYPE_NONNULLTERMINATEDANSISTRING:
        case TDH_INTYPE_ANSICHAR: {
            // Convert strings from ANSI code page, all others (JSON, XML etc.) from UTF-8
            wstring str;
            MultiByteToWideChar(OutType == TDH_OUTTYPE_STRING ? CP_ACP : CP_UTF8, 0, (LPCSTR)pData, (int)nDataSize, str);
            return tstring_printf(_T("%ls"), str.c_str());
        }

        case TDH_INTYPE_COUNTEDSTRING:
            return DataToString(TDH_INTYPE_NONNULLTERMINATEDSTRING, OutType, (LPCBYTE)((PUSHORT)pData + 1), *(PUSHORT)pData, pMapInfo, nPtrSize);

        case TDH_INTYPE_COUNTEDANSISTRING:
            return DataToString(TDH_INTYPE_NONNULLTERMINATEDANSISTRING, OutType, (LPCBYTE)((PUSHORT)pData + 1), *(PUSHORT)pData, pMapInfo, nPtrSize);

        case TDH_INTYPE_REVERSEDCOUNTEDSTRING:
            return DataToString(TDH_INTYPE_NONNULLTERMINATEDSTRING, OutType, (LPCBYTE)((PUSHORT)pData + 1), MAKEWORD(HIBYTE(*(PUSHORT)pData), LOBYTE(*(PUSHORT)pData)), pMapInfo, nPtrSize);

        case TDH_INTYPE_REVERSEDCOUNTEDANSISTRING:
            return DataToString(TDH_INTYPE_NONNULLTERMINATEDANSISTRING, OutType, (LPCBYTE)((PUSHORT)pData + 1), MAKEWORD(HIBYTE(*(PUSHORT)pData), LOBYTE(*(PUSHORT)pData)), pMapInfo, nPtrSize);

        case TDH_INTYPE_INT8:
            assert(nDataSize >= sizeof(CHAR));
            switch (OutType) {
            case TDH_OUTTYPE_STRING: return DataToString(TDH_INTYPE_ANSICHAR, TDH_OUTTYPE_NULL, pData, nDataSize, pMapInfo, nPtrSize);
            default                : return tstring_printf(_T("%hd"), *(PCHAR)pData);
            }

        case TDH_INTYPE_UINT8:
            assert(nDataSize >= sizeof(BYTE));
            switch (OutType) {
            case TDH_OUTTYPE_STRING : return DataToString(TDH_INTYPE_ANSICHAR, TDH_OUTTYPE_NULL, pData, nDataSize, pMapInfo, nPtrSize);
            case TDH_OUTTYPE_HEXINT8: return tstring_printf(_T("0x%x"), *(PBYTE)pData);
            default                 : return tstring_printf(_T("%hu" ), *(PBYTE)pData);
            }

        case TDH_INTYPE_INT16:
            assert(nDataSize >= sizeof(SHORT));
            return tstring_printf(_T("%hd"), *(PSHORT)pData);

        case TDH_INTYPE_UINT16:
            assert(nDataSize >= sizeof(USHORT));
            switch (OutType) {
            case TDH_OUTTYPE_PORT    : return tstring_printf(_T("%hu" ), ntohs(*(PUSHORT)pData));
            case TDH_OUTTYPE_HEXINT16: return tstring_printf(_T("0x%x"),       *(PUSHORT)pData );
            case TDH_OUTTYPE_STRING  : return tstring_printf(_T("%lc" ),       *(PUSHORT)pData );
            default                  : return tstring_printf(_T("%hu" ),       *(PUSHORT)pData );
            }

        case TDH_INTYPE_INT32:
            assert(nDataSize >= sizeof(LONG));
            switch (OutType) {
            case TDH_OUTTYPE_HRESULT: return tstring_printf(_T("0x%x"), *(PLONG)pData);
            default                 : return tstring_printf(_T("%ld" ), *(PLONG)pData);
            }

        case TDH_INTYPE_UINT32:
            assert(nDataSize >= sizeof(ULONG));
            switch (OutType) {
                case TDH_OUTTYPE_HRESULT   :
                case TDH_OUTTYPE_WIN32ERROR:
                case TDH_OUTTYPE_NTSTATUS  :
                case TDH_OUTTYPE_HEXINT32  : return tstring_printf(_T("0x%x"       ),  *(PULONG)pData);
                case TDH_OUTTYPE_IPV4      : return tstring_printf(_T("%d.%d.%d.%d"), (*(PULONG)pData >> 0) & 0xff, (*(PULONG)pData >> 8) & 0xff, (*(PULONG)pData >> 16) & 0xff, (*(PULONG)pData >> 24) & 0xff);
                default:                     return pMapInfo ? MapToString(pMapInfo, pData) : tstring_printf(_T("%lu"), *(PULONG)pData);
            }

        case TDH_INTYPE_HEXINT32:
            return DataToString(TDH_INTYPE_UINT32, TDH_OUTTYPE_HEXINT32, pData, nDataSize, pMapInfo, nPtrSize);

        case TDH_INTYPE_INT64:
            assert(nDataSize >= sizeof(LONGLONG));
            return tstring_printf(_T("%I64d"), *(PLONGLONG)pData);

        case TDH_INTYPE_UINT64:
            assert(nDataSize >= sizeof(ULONGLONG));
            switch (OutType) {
            case TDH_OUTTYPE_HEXINT64: return tstring_printf(_T("0x%I64x"), *(PULONGLONG)pData);
            default                  : return tstring_printf(_T("%I64u"  ), *(PULONGLONG)pData);
            }

        case TDH_INTYPE_HEXINT64:
            return DataToString(TDH_INTYPE_UINT64, TDH_OUTTYPE_HEXINT64, pData, nDataSize, pMapInfo, nPtrSize);

        case TDH_INTYPE_FLOAT:
            assert(nDataSize >= sizeof(FLOAT));
            return tstring_printf(_T("%f"), *(PFLOAT)pData);

        case TDH_INTYPE_DOUBLE:
            assert(nDataSize >= sizeof(DOUBLE));
            return tstring_printf(_T("%I64f"), *(DOUBLE*)pData);

        case TDH_INTYPE_BOOLEAN:
            assert(nDataSize >= sizeof(ULONG)); // Yes, boolean is really 32-bit.
            return *(PULONG)pData ? _T("true") : _T("false");

        case TDH_INTYPE_BINARY:
            switch (OutType) {
            case TDH_OUTTYPE_IPV6: {
                auto RtlIpv6AddressToString = (LPTSTR(NTAPI*)(const IN6_ADDR*, LPTSTR))GetProcAddress(GetModuleHandle(_T("ntdll.dll")),
#ifdef _UNICODE
                    "RtlIpv6AddressToStringW"
#else
                    "RtlIpv6AddressToStringA"
#endif
                    );
                if (RtlIpv6AddressToString) {
                    TCHAR szIPv6Addr[47];
                    RtlIpv6AddressToString((IN6_ADDR*)pData, szIPv6Addr);
                    return tstring_printf(_T("%s"), szIPv6Addr);
                } else
                    return _T("<IPv6 address>");
            }
            default: {
                tstring out;
                for (SIZE_T i = 0; i < nDataSize; i++)
                    out.append(tstring_printf(i ? _T(" %02x") : _T("%02x"), pData[i]));
                return out;
            }}

        case TDH_INTYPE_HEXDUMP:
            return DataToString(TDH_INTYPE_BINARY, TDH_OUTTYPE_NULL, pData, nDataSize, pMapInfo, nPtrSize);

        case TDH_INTYPE_GUID: {
            assert(nDataSize >= sizeof(GUID));
            WCHAR szGuid[39];
            StringFromGUID2(*(GUID*)pData, szGuid, _countof(szGuid));
            return tstring_printf(_T("%ls"), szGuid);
        }

        case TDH_INTYPE_POINTER:
            assert(nDataSize >= nPtrSize);
            switch (nPtrSize) {
            case sizeof(ULONG    ): return tstring_printf(_T("0x%08x"   ), *(PULONG    )pData);
            case sizeof(ULONGLONG): return tstring_printf(_T("0x%016I64x"), *(PULONGLONG)pData);
            default: // Unsupported pointer size.
                assert(0);
                return _T("<pointer>");
            }

        case TDH_INTYPE_SIZET:
            assert(nDataSize >= nPtrSize);
            switch (nPtrSize) {
            case sizeof(ULONG    ): return tstring_printf(_T("%u"   ), *(PULONG    )pData);
            case sizeof(ULONGLONG): return tstring_printf(_T("%I64u"), *(PULONGLONG)pData);
            default: // Unsupported size_t size.
                assert(0);
                return _T("<size_t>");
            }

        case TDH_INTYPE_FILETIME: {
            assert(nDataSize >= sizeof(FILETIME));
            SYSTEMTIME st, st_local;
            FileTimeToSystemTime((PFILETIME)pData, &st);
            SystemTimeToTzSpecificLocalTime(NULL, &st, &st_local);
            return DataToString(TDH_INTYPE_SYSTEMTIME, OutType, (LPCBYTE)&st_local, sizeof(st_local), pMapInfo, nPtrSize);
        }

        case TDH_INTYPE_SYSTEMTIME:
            assert(nDataSize >= sizeof(SYSTEMTIME));
            switch (OutType) {
            case TDH_OUTTYPE_CULTURE_INSENSITIVE_DATETIME: return tstring_printf(_T("%04d-%02d-%02d %02d:%02d:%02d.%03u"), ((PSYSTEMTIME)pData)->wYear, ((PSYSTEMTIME)pData)->wMonth, ((PSYSTEMTIME)pData)->wDay, ((PSYSTEMTIME)pData)->wHour, ((PSYSTEMTIME)pData)->wMinute, ((PSYSTEMTIME)pData)->wSecond, ((PSYSTEMTIME)pData)->wMilliseconds);
            default: {
                tstring out;
                return GetDateFormat(LOCALE_USER_DEFAULT, DATE_LONGDATE, (PSYSTEMTIME)pData, NULL, out) ? out : tstring(_T("<time>"));
            }}

        case TDH_INTYPE_WBEMSID:
            // A WBEM SID is actually a TOKEN_USER structure followed 
            // by the SID. The size of the TOKEN_USER structure differs 
            // depending on whether the events were generated on a 32-bit 
            // or 64-bit architecture. Also the structure is aligned
            // on an 8-byte boundary, so its size is 8 bytes on a
            // 32-bit computer and 16 bytes on a 64-bit computer.
            // Doubling the pointer size handles both cases.
            assert(nDataSize >= nPtrSize * 2);
            return (PULONG)pData > 0 ? DataToString(TDH_INTYPE_SID, OutType, pData + nPtrSize * 2, nDataSize - nPtrSize * 2, pMapInfo, nPtrSize) : _T("<WBEM SID>");

        case TDH_INTYPE_SID: {
            assert(nDataSize >= sizeof(SID));
            tstring user_name, domain_name;
            SID_NAME_USE eNameUse;
            if (LookupAccountSid(NULL, (PSID)pData, &user_name, &domain_name, &eNameUse))
                return tstring_printf(_T("%s\\%s"), domain_name.c_str(), user_name.c_str());
            else {
                unique_ptr<TCHAR[], LocalFree_delete<TCHAR[]> > sid;
                if (GetLastError() == ERROR_NONE_MAPPED &&
                    ConvertSidToStringSid((PSID)pData, (LPTSTR*)&sid))
                    return tstring_printf(_T("%s"), sid.get());
                else
                    return _T("<SID>");
            }
        }

    default:
        // It is not actually an error if we do not understand the given data type.
        assert(0);
        return _T("<unknown data type>");
    }
}


static ULONG GetArraySize(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, ULONG i, ULONG *pulArraySize)
{
    if (pInfo->EventPropertyInfoArray[i].Flags & PropertyParamCount) {
        ULONG ulResult;

        // Get array count property.
        PROPERTY_DATA_DESCRIPTOR data_desc = { (ULONGLONG)((LPBYTE)pInfo + pInfo->EventPropertyInfoArray[pInfo->EventPropertyInfoArray[i].countPropertyIndex].NameOffset), ULONG_MAX };
        vector<unsigned char> count;
        if ((ulResult = TdhGetProperty(pEvent, 0, NULL, 1, &data_desc, count)) != ERROR_SUCCESS)
            return ulResult;

        // Copy count value to output.
        switch (count.size()) {
        case sizeof(BYTE  ): *pulArraySize = *(const BYTE*  )count.data(); break;
        case sizeof(USHORT): *pulArraySize = *(const USHORT*)count.data(); break;
        case sizeof(ULONG ): *pulArraySize = *(const ULONG* )count.data(); break;
        default            : return ERROR_MORE_DATA;
        }
    } else
        *pulArraySize = pInfo->EventPropertyInfoArray[i].count;

    return ERROR_SUCCESS;
}


static tstring PropertyToString(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, ULONG ulPropIndex, LPWSTR pStructureName, ULONG ulStructIndex, BYTE nPtrSize)
{
    ULONG ulResult;

    // Get the size of the array if the property is an array.
    ULONG ulArraySize = 0;
    if ((ulResult = GetArraySize(pEvent, pInfo, ulPropIndex, &ulArraySize)) != ERROR_SUCCESS)
        return tstring_printf(_T("<Error getting array size (error %u)>"), ulResult);;

    tstring out;

    if (ulArraySize > 1)
        out += tstring_printf(_T("[%u]("), ulArraySize);

    for (ULONG k = 0; k < ulArraySize; k++) {
        if (pInfo->EventPropertyInfoArray[ulPropIndex].Flags & PropertyStruct) {
            // The property is a structure: print the members of the structure.
            tstring out;
            out += _T('(');
            for (USHORT j = pInfo->EventPropertyInfoArray[ulPropIndex].structType.StructStartIndex, usLastMember = pInfo->EventPropertyInfoArray[ulPropIndex].structType.StructStartIndex + pInfo->EventPropertyInfoArray[ulPropIndex].structType.NumOfStructMembers; j < usLastMember; j++) {
                out += tstring_printf(_T("%ls: "), (LPBYTE)pInfo + pInfo->EventPropertyInfoArray[j].NameOffset);
                out += PropertyToString(pEvent, pInfo, j, (LPWSTR)((LPBYTE)(pInfo) + pInfo->EventPropertyInfoArray[ulPropIndex].NameOffset), k, nPtrSize);
            }
            out += _T(')');
        } else {
            if (pInfo->EventPropertyInfoArray[ulPropIndex].nonStructType.InType  == TDH_INTYPE_BINARY &&
                pInfo->EventPropertyInfoArray[ulPropIndex].nonStructType.OutType == TDH_OUTTYPE_IPV6)
            {
                // The TDH API does not support IPv6 addresses. If the output type is TDH_OUTTYPE_IPV6,
                // you will not be able to consume the rest of the event. If you try to consume the
                // remainder of the event, you will get ERROR_EVT_INVALID_EVENT_DATA.
                return _T("<The event contains an IPv6 address. Skipping.>");
            } else {
                vector<BYTE> data;
                if (pStructureName) {
                    // To retrieve a member of a structure, you need to specify an array of descriptors. 
                    // The first descriptor in the array identifies the name of the structure and the second 
                    // descriptor defines the member of the structure whose data you want to retrieve. 
                    PROPERTY_DATA_DESCRIPTOR data_desc[2] = {
                        { (ULONGLONG)pStructureName                                                         , ulStructIndex },
                        { (ULONGLONG)((LPBYTE)pInfo + pInfo->EventPropertyInfoArray[ulPropIndex].NameOffset), k             }
                    };
                    ulResult = TdhGetProperty(pEvent, 0, NULL, _countof(data_desc), data_desc, data);
                } else {
                    PROPERTY_DATA_DESCRIPTOR data_desc = { (ULONGLONG)((LPBYTE)pInfo + pInfo->EventPropertyInfoArray[ulPropIndex].NameOffset), k };
                    ulResult = TdhGetProperty(pEvent, 0, NULL, 1, &data_desc, data);
                }
                if (ulResult == ERROR_EVT_INVALID_EVENT_DATA) {
                    // This happens with empty/NULL data. Not an error actually.
                    assert(data.empty());
                } else if (ulResult != ERROR_SUCCESS)
                    return tstring_printf(_T("<Error getting property (error %u)>"), ulResult);

                // Get the name/value mapping if the property specifies a value map.
                unique_ptr<EVENT_MAP_INFO> map_info;
                ulResult = TdhGetEventMapInformation(pEvent, (LPWSTR)((LPBYTE)pInfo + pInfo->EventPropertyInfoArray[ulPropIndex].nonStructType.MapNameOffset), map_info);
                if (ulResult == ERROR_NOT_FOUND) {
                    // name/value mapping not found. Not an error actually.
                    assert(!map_info);
                } else if (ulResult != ERROR_SUCCESS)
                    return tstring_printf(_T("<Error getting map information (error %u)>"), ulResult);
                else if (pInfo->DecodingSource == DecodingSourceXMLFile) {
                    // The mapped string values defined in a manifest will contain a trailing space
                    // in the EVENT_MAP_ENTRY structure. Replace the trailing space with a null-
                    // terminating character, so that the bit mapped strings are correctly formatted.
                    for (ULONG i = 0; i < map_info->EntryCount; i++) {
                        SIZE_T len = _tcslen((LPCTSTR)((PBYTE)map_info.get() + map_info->MapEntryArray[i].OutputOffset)) - 1;
                        ((LPWSTR)((PBYTE)map_info.get() + map_info->MapEntryArray[i].OutputOffset))[len] = 0;
                    }
                }

                if (!out.empty()) out += _T(", ");
                out += !data.empty() ? DataToString(
                    pInfo->EventPropertyInfoArray[ulPropIndex].nonStructType.InType,
                    pInfo->EventPropertyInfoArray[ulPropIndex].nonStructType.OutType,
                    data.data(),
                    data.size(),
                    map_info.get(),
                    nPtrSize) : _T("<null>");
            }
        }
    }

    if (ulArraySize > 1)
        out += _T(')');

    return out;
}


static VOID WINAPI EventRecordCallback(_In_ PEVENT_RECORD pEvent)
{
    {
        // Calculate and print event time-stamp.
        FILETIME ft;
        ft.dwHighDateTime = pEvent->EventHeader.TimeStamp.HighPart;
        ft.dwLowDateTime = pEvent->EventHeader.TimeStamp.LowPart;

        SYSTEMTIME st, st_local;
        FileTimeToSystemTime(&ft, &st);
        SystemTimeToTzSpecificLocalTime(NULL, &st, &st_local);

        ULONGLONG
            ts = pEvent->EventHeader.TimeStamp.QuadPart,
            nanosec = (ts % 10000000) * 100;

        _ftprintf(stdout, _T("%04d-%02d-%02d %02d:%02d:%02d.%09I64u"),
            st_local.wYear, st_local.wMonth, st_local.wDay, st_local.wHour, st_local.wMinute, st_local.wSecond, nanosec);
    }

    {
        // Get event meta-info.
        unique_ptr<TRACE_EVENT_INFO> info;
        ULONG ulResult;
        if ((ulResult = TdhGetEventInformation(pEvent, 0, NULL, info)) == ERROR_SUCCESS) {
            if (info->DecodingSource != DecodingSourceWPP) {
                if (pEvent->EventHeader.Flags & EVENT_HEADER_FLAG_STRING_ONLY) {
                    // This is a string-only event. Print it.
                    _ftprintf(stdout, _T(" %ls"), pEvent->UserData);
                } else {
                    // This is not a string-only event. Prepare parameters.

                    BYTE nPtrSize = (pEvent->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;
                    vector<tstring> props;
                    vector<DWORD_PTR> props_msg;
                    props.reserve(info->TopLevelPropertyCount);
                    props_msg.reserve(info->TopLevelPropertyCount);
                    for (ULONG i = 0; i < info->TopLevelPropertyCount; i++) {
                        props.push_back(std::move(PropertyToString(pEvent, info.get(), i, NULL, 0, nPtrSize)));
                        props_msg.push_back((DWORD_PTR)props[i].c_str());
                    }

                    if (info->EventMessageOffset) {
                        // Format the message.
                        _ftprintf(stdout, _T(" %ls"), wstring_msg(0, (LPCTSTR)((LPCBYTE)info.get() + info->EventMessageOffset), props_msg.data()).c_str());
                    }
                }
            } else if (info->EventMessageOffset) {
                // This is a WPP event.
                _ftprintf(stdout, _T(" %ls"), (LPCBYTE)info.get() + info->EventMessageOffset);
            }
        }
    }

    _ftprintf(stdout, _T("\n"));
}


#ifdef _UNICODE
int wmain(int argc, const wchar_t *argv[])
#else
int  main(int argc, const char    *argv[])
#endif
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    setlocale(LC_ALL, ".OCP");

    // Initialize COM.
    com_initializer com_init(NULL);

    // Start a new session.
    ULONG ulResult;
    event_session session;
    for (unsigned int i = 0; ; i++) {
        //tstring log_file(tstring_printf(i ? _T("test.etl") : _T("test %u.etl"), i));
        tstring name(tstring_printf(i ? _T(PRODUCT_NAME_STR) _T(" Event Monitor Session %u") : _T(PRODUCT_NAME_STR) _T(" Event Monitor Session"), i));

        // Allocate session properties.
        ULONG
            ulSizeName    = (ULONG)((name    .length() + 1)*sizeof(TCHAR)),
            //ulSizeLogFile = (ULONG)((log_file.length() + 1)*sizeof(TCHAR)),
            ulSize        = sizeof(EVENT_TRACE_PROPERTIES) + ulSizeName /*+ ulSizeLogFile*/;
        unique_ptr<EVENT_TRACE_PROPERTIES> properties((EVENT_TRACE_PROPERTIES*)new char[ulSize]);
        if (!properties) {
            _ftprintf(stderr, _T("Error allocating session properties memory.\n"));
            return 1;
        }

        // Initialize properties.
        memset(properties.get(), 0, sizeof(EVENT_TRACE_PROPERTIES));
        properties->Wnode.BufferSize    = ulSize;
        properties->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
        properties->Wnode.ClientContext = 1; //QPC clock resolution
        CoCreateGuid(&(properties->Wnode.Guid));
        properties->LogFileMode         = /*EVENT_TRACE_FILE_MODE_SEQUENTIAL |*/ EVENT_TRACE_REAL_TIME_MODE;
        properties->MaximumFileSize     = 1;  // 1 MB
        properties->LoggerNameOffset    = sizeof(EVENT_TRACE_PROPERTIES);
        //properties->LogFileNameOffset   = sizeof(EVENT_TRACE_PROPERTIES) + ulSizeName;
        //memcpy((LPTSTR)((char*)properties.get() + properties->LogFileNameOffset), log_file.c_str(), ulSizeLogFile);

        if ((ulResult = session.create(name.c_str(), properties.get())) == ERROR_SUCCESS) {
            break;
        } else if (ulResult == ERROR_ACCESS_DENIED) {
            _ftprintf(stderr, _T("Access denied creating event session: you need administrative privileges (Run As Administrator) or be a member of Performance Log Users group to start event tracing session.\n"), ulResult);
            return 1;
        } else if (ulResult == ERROR_ALREADY_EXISTS) {
            _ftprintf(stderr, _T("The %s event session already exists.\n"), name.c_str());
            // Do not despair... Retry with a new session name and ID.
            continue;
        } else {
            _ftprintf(stderr, _T("Error creating event session (error %u).\n"), ulResult);
            return 1;
        }
    }

    // Enable event provider we are interested in to log events to our session.
    event_trace_enabler trace_enabler_event(session, &EAPMETHOD_TRACE_EVENT_PROVIDER, TRACE_LEVEL_VERBOSE);
    if ((ulResult = trace_enabler_event.status()) != ERROR_SUCCESS) {
        _ftprintf(stderr, _T("Error enabling event provider (error %u).\n"), ulResult);
        return 1;
    }

    // {6EB8DB94-FE96-443F-A366-5FE0CEE7FB1C}
    static const GUID s_provider_eaphost = { 0X6EB8DB94, 0XFE96, 0X443F, { 0XA3, 0X66, 0X5F, 0XE0, 0XCE, 0XE7, 0XFB, 0X1C } };
    event_trace_enabler trace_enabler_eaphost(session, &s_provider_eaphost, TRACE_LEVEL_INFORMATION);
    if ((ulResult = trace_enabler_eaphost.status()) != ERROR_SUCCESS) {
        // If the EAPHost trace provider failed to enable, do not despair.
        _ftprintf(stderr, _T("Error enabling EAPHost event provider (error %u).\n"), ulResult);
    }

    // Open trace.
    EVENT_TRACE_LOGFILE tlf = {};
    tlf.LoggerName = (LPTSTR)session.name();
    tlf.ProcessTraceMode    = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    tlf.EventRecordCallback = EventRecordCallback;
    event_trace trace;
    if (!trace.create(&tlf)) {
        _ftprintf(stderr, _T("Error opening event trace (error %u).\n"), GetLastError());
        return 1;
    }

    // Process events.
    g_traces.push_back(trace.detach());
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);
    ProcessTrace(g_traces.data(), (ULONG)g_traces.size(), NULL, NULL);

    return 0;
}
