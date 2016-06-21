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

using namespace std;
using namespace winstd;

// {B963A9BE-2D21-4A4C-BE47-10490AD63AB9}
static const GUID g_session_id = 
{ 0xb963a9be, 0x2d21, 0x4a4c, { 0xbe, 0x47, 0x10, 0x49, 0xa, 0xd6, 0x3a, 0xb9 } };


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


static VOID WINAPI EventRecordCallback(_In_ PEVENT_RECORD EventRecord)
{
    UNREFERENCED_PARAMETER(EventRecord);
}


#ifdef _UNICODE
int wmain(int argc, const wchar_t *argv[])
#else
int  main(int argc, const char    *argv[])
#endif
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

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
        properties->Wnode.Guid          = g_session_id;
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
            continue;
        } else {
            _ftprintf(stderr, _T("Error creating event session (error %u).\n"), ulResult);
            return 1;
        }
    }

    // Enable event provider we are interested in to log events to our session.
    event_trace_enabler trace_enabler(session, &EAPMETHOD_TRACE_EVENT_PROVIDER, TRACE_LEVEL_VERBOSE);
    if ((ulResult = trace_enabler.status()) != ERROR_SUCCESS) {
        _ftprintf(stderr, _T("Error enabling event provider (error %u).\n"), ulResult);
        return 1;
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
