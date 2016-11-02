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


//////////////////////////////////////////////////////////////////////////
// Local helper functions declarations
//////////////////////////////////////////////////////////////////////////

static tstring MapToString(_In_ const EVENT_MAP_INFO *pMapInfo, _In_ ULONG ulData);
static tstring DataToString(_In_ USHORT InType, _In_ USHORT OutType, _In_count_(nDataSize) LPCBYTE pData, _In_ SIZE_T nDataSize, _In_ const EVENT_MAP_INFO *pMapInfo, _In_ BYTE nPtrSize);
static ULONG GetArraySize(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, ULONG i, ULONG *pulArraySize);
static tstring PropertyToString(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, ULONG ulPropIndex, LPWSTR pStructureName, ULONG ulStructIndex, BYTE nPtrSize);


//////////////////////////////////////////////////////////////////////////
// wxETWEvent
//////////////////////////////////////////////////////////////////////////

const EVENT_RECORD wxETWEvent::s_record_null = {};


wxETWEvent::wxETWEvent(wxEventType type, const EVENT_RECORD &record) :
    m_record(record),
    wxEvent(0, type)
{
}


wxETWEvent::wxETWEvent(const wxETWEvent& event) :
    m_record(event.m_record),
    wxEvent(event)
{
}


IMPLEMENT_DYNAMIC_CLASS(wxETWEvent, wxEvent)
wxDEFINE_EVENT(wxEVT_ETW_EVENT, wxETWEvent);


//////////////////////////////////////////////////////////////////////////
// wxEventTraceProcessorThread
//////////////////////////////////////////////////////////////////////////

wxEventTraceProcessorThread::wxEventTraceProcessorThread(wxEvtHandler *parent, const wxArrayString &sessions) :
    m_parent(parent),
    wxThread(wxTHREAD_JOINABLE)
{
    EVENT_TRACE_LOGFILE tlf = {};
    tlf.ProcessTraceMode    = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    tlf.EventRecordCallback = EventRecordCallback;
    tlf.Context             = this;

    for (size_t i = 0, i_end = sessions.GetCount(); i < i_end; i++) {
        // Open trace.
        tlf.LoggerName = const_cast<LPTSTR>((LPCTSTR)(sessions[i]));
        event_trace trace;
        if (!trace.create(&tlf)) {
            wxLogError(_("Error opening event trace (error %u)."), GetLastError());
            continue;
        }

        // Save trace to the table.
        m_traces.push_back(trace.detach());
    }
}


wxEventTraceProcessorThread::~wxEventTraceProcessorThread()
{
    for (auto trace = m_traces.begin(), trace_end = m_traces.end(); trace != trace_end; ++trace) {
        TRACEHANDLE &h = *trace;
        if (h) {
            // Close trace.
            CloseTrace(h);
        }
    }
}


void wxEventTraceProcessorThread::Abort()
{
    for (auto trace = m_traces.begin(), trace_end = m_traces.end(); trace != trace_end; ++trace) {
        TRACEHANDLE &h = *trace;
        if (h) {
            // Close trace.
            CloseTrace(h);
            h = NULL;
        }
    }
}


wxThread::ExitCode wxEventTraceProcessorThread::Entry()
{
    // Process events.
    ProcessTrace(m_traces.data(), (ULONG)m_traces.size(), NULL, NULL);

    return 0;
}


VOID WINAPI wxEventTraceProcessorThread::EventRecordCallback(_In_ PEVENT_RECORD pEvent)
{
    wxASSERT_MSG(pEvent, wxT("event is NULL"));
    wxASSERT_MSG(pEvent->UserContext, wxT("thread is NULL"));

    wxEventTraceProcessorThread *_this = ((wxEventTraceProcessorThread*)pEvent->UserContext);

    if (_this->TestDestroy()) {
        // Event processing is pending destruction.
        return;
    }

    _this->m_parent->QueueEvent(new wxETWEvent(wxEVT_ETW_EVENT, *pEvent));
}


//////////////////////////////////////////////////////////////////////////
// wxETWListCtrl
//////////////////////////////////////////////////////////////////////////

BEGIN_EVENT_TABLE(wxETWListCtrl, wxListCtrl)
    EVT_ETW_EVENT(wxETWListCtrl::OnETWEvent)
END_EVENT_TABLE()


// {6EB8DB94-FE96-443F-A366-5FE0CEE7FB1C}
const GUID wxETWListCtrl::s_provider_eaphost = { 0x6EB8DB94, 0xFE96, 0x443F, { 0xA3, 0x66, 0x5F, 0xE0, 0xCE, 0xE7, 0xFB, 0x1C } };

// {1F678132-5938-4686-9FDC-C8FF68F15C85}
const GUID wxETWListCtrl::s_provider_schannel = { 0x1F678132, 0x5938, 0x4686, { 0x9F, 0xDC, 0xC8, 0xFF, 0x68, 0xF1, 0x5C, 0x85 } };


wxETWListCtrl::wxETWListCtrl(wxWindow *parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style, const wxValidator& validator, const wxString& name) :
    m_proc(NULL),
    m_scroll_auto(true),
    m_level(TRACE_LEVEL_INFORMATION),
    m_rec_db(wxETWEVENT_RECORDS_MAX),
    m_rec_idx(wxETWEVENT_RECORDS_MAX),
    wxListCtrl(parent, id, pos, size, style, validator, name)
{
    this->AppendColumn(_("Time"  ), wxLIST_FORMAT_LEFT, 160);
    this->AppendColumn(_("PID"   ), wxLIST_FORMAT_LEFT,  50);
    this->AppendColumn(_("TID"   ), wxLIST_FORMAT_LEFT,  50);
    this->AppendColumn(_("Source"), wxLIST_FORMAT_LEFT,  80);
    this->AppendColumn(_("Event" ), wxLIST_FORMAT_LEFT, 350);

    // Maximum expected column widths for pre-formatted row display
    m_col_format_width[0] = 26;
    m_col_format_width[1] = 5;
    m_col_format_width[2] = 5;
    m_col_format_width[3] = std::max<int>(std::max<int>(_countof("EapHost"), _countof("Schannel")), _countof(PRODUCT_NAME_STR)) - 1;
    m_col_format_width[4] = 0;

    // Prepare all possible item attributes.
    wxColour col_bg((unsigned long)0xffffff);
    m_item_attr[0][0].SetBackgroundColour(col_bg                 );
    m_item_attr[0][0].SetTextColour      ((unsigned long)0x666666);
    m_item_attr[0][1].SetBackgroundColour(col_bg                 );
    m_item_attr[0][1].SetTextColour      ((unsigned long)0x000000);
    m_item_attr[0][2].SetBackgroundColour(col_bg                 );
    m_item_attr[0][2].SetTextColour      ((unsigned long)0x00aacc);
    m_item_attr[0][3].SetBackgroundColour(col_bg                 );
    m_item_attr[0][3].SetTextColour      ((unsigned long)0x0000ff);
    m_item_attr[1][0].SetBackgroundColour(col_bg                 );
    m_item_attr[1][0].SetTextColour      ((unsigned long)0xcccccc);
    m_item_attr[1][1].SetBackgroundColour(col_bg                 );
    m_item_attr[1][1].SetTextColour      ((unsigned long)0xaaaaaa);
    m_item_attr[1][2].SetBackgroundColour(col_bg                 );
    m_item_attr[1][2].SetTextColour      ((unsigned long)0xaaeeee);
    m_item_attr[1][3].SetBackgroundColour(col_bg                 );
    m_item_attr[1][3].SetTextColour      ((unsigned long)0xaaaaff);

    // Start a new session.
    ULONG ulResult;
    for (unsigned int i = 0; ; i++) {
        //tstring log_file(tstring_printf(i ? _T("test.etl") : _T("test %u.etl"), i));
        tstring name(tstring_printf(i ? _T(PRODUCT_NAME_STR) _T(" Event Monitor Session %u") : _T(PRODUCT_NAME_STR) _T(" Event Monitor Session"), i));

        // Allocate session properties.
        ULONG
            ulSizeName    = (ULONG)((name    .length() + 1)*sizeof(TCHAR)),
            //ulSizeLogFile = (ULONG)((log_file.length() + 1)*sizeof(TCHAR)),
            ulSize        = sizeof(EVENT_TRACE_PROPERTIES) + ulSizeName /*+ ulSizeLogFile*/;
        unique_ptr<EVENT_TRACE_PROPERTIES> properties(reinterpret_cast<EVENT_TRACE_PROPERTIES*>(new char[ulSize]));
        wxASSERT_MSG(properties, wxT("error allocating session properties memory"));

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
        //memcpy(reinterpret_cast<char*>(properties.get()) + properties->LogFileNameOffset, log_file.c_str(), ulSizeLogFile);

        if ((ulResult = m_session.create(name.c_str(), properties.get())) == ERROR_SUCCESS) {
            break;
        } else if (ulResult == ERROR_ACCESS_DENIED) {
            wxLogError(_("Access denied creating event session: you need administrative privileges (Run As Administrator) or be a member of Performance Log Users group to start event tracing session."));
            return;
        } else if (ulResult == ERROR_ALREADY_EXISTS) {
            wxLogDebug(_("The %s event session already exists."), name);
            // Do not despair... Retry with a new session name and ID.
            continue;
        } else {
            wxLogError(_("Error creating event session (error %u)."), ulResult);
            return;
        }
    }

    // Enable event providers we are interested in to log events to our session.
    if ((ulResult = EnableTraceEx(
        &EAPMETHOD_TRACE_EVENT_PROVIDER,
        &((const EVENT_TRACE_PROPERTIES*)m_session)->Wnode.Guid,
        m_session,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        0, 0,
        0,
        NULL)) != ERROR_SUCCESS)
    {
        wxLogDebug(wxString::Format(_("Error enabling %s event provider (error %u)."), wxT(PRODUCT_NAME_STR)), ulResult);
        return;
    }
    m_sources.insert(EAPMETHOD_TRACE_EVENT_PROVIDER);

    if ((ulResult = EnableTraceEx(
        &s_provider_eaphost,
        &((const EVENT_TRACE_PROPERTIES*)m_session)->Wnode.Guid,
        m_session,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        0, 0,
        0,
        NULL)) != ERROR_SUCCESS)
    {
        // If the EapHost trace provider failed to enable, do not despair.
        wxLogDebug(wxString::Format(_("Error enabling %s event provider (error %u)."), wxT("EapHost")), ulResult);
    }

    if ((ulResult = EnableTraceEx(
        &s_provider_schannel,
        &((const EVENT_TRACE_PROPERTIES*)m_session)->Wnode.Guid,
        m_session,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        0, 0,
        0,
        NULL)) != ERROR_SUCCESS)
    {
        // If the Schannel trace provider failed to enable, do not despair.
        wxLogDebug(wxString::Format(_("Error enabling %s event provider (error %u)."), wxT("Schannel")), ulResult);
    }

    // Process events in separate thread, not to block wxWidgets' message pump.
    wxArrayString sessions;
    sessions.Add(m_session.name());
    m_proc = new wxEventTraceProcessorThread(GetEventHandler(), sessions);
    wxASSERT_MSG(m_proc, wxT("error allocating thread memory"));
    if (m_proc->Run() != wxTHREAD_NO_ERROR) {
        wxFAIL_MSG("Can't create the thread!");
        delete m_proc;
        m_proc = NULL;
    }
}


wxETWListCtrl::~wxETWListCtrl()
{
    if (m_session) {
        if (m_proc) {
            m_proc->Abort();
            m_proc->Delete();
            delete m_proc;
        }

        // Disable event providers.
        EnableTraceEx(
                &s_provider_schannel,
                &((const EVENT_TRACE_PROPERTIES*)m_session)->Wnode.Guid,
                m_session,
                EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                TRACE_LEVEL_VERBOSE,
                0, 0,
                0,
                NULL);

        EnableTraceEx(
                &s_provider_eaphost,
                &((const EVENT_TRACE_PROPERTIES*)m_session)->Wnode.Guid,
                m_session,
                EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                TRACE_LEVEL_VERBOSE,
                0, 0,
                0,
                NULL);

        EnableTraceEx(
                &EAPMETHOD_TRACE_EVENT_PROVIDER,
                &((const EVENT_TRACE_PROPERTIES*)m_session)->Wnode.Guid,
                m_session,
                EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                TRACE_LEVEL_VERBOSE,
                0, 0,
                0,
                NULL);
    }
}


void wxETWListCtrl::CopySelected() const
{
    // Prepare text in ANSI and Unicode flavours.
    string dataA, rowA;
    wstring dataW, rowW;
    for (long item = -1; (item = GetNextItem(item, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED)) != -1;) {
        FormatRow(m_rec_db.at_abs(m_rec_idx.at(item)), rowA, rowW);
        rowA +=  "\r\n"; dataA += rowA;
        rowW += L"\r\n"; dataW += rowW;
    }

    // Put text to clipboard.
    CopyToClipboard(dataA, dataW);
}


void wxETWListCtrl::CopyAll() const
{
    // Prepare text in ANSI and Unicode flavours.
    string dataA, rowA;
    wstring dataW, rowW;
    for (size_t i = 0, n = m_rec_db.size(); i < n; i++) {
        FormatRow(m_rec_db[i], rowA, rowW);
        rowA +=  "\r\n"; dataA += rowA;
        rowW += L"\r\n"; dataW += rowW;
    }

    // Put text to clipboard.
    CopyToClipboard(dataA, dataW);

}


void wxETWListCtrl::ClearAll()
{
    m_rec_idx.clear();
    m_rec_db.clear();
    if (GetItemCount())
        SetItemCount(0);
}


void wxETWListCtrl::SelectAll()
{
    for (long item = 0, count = GetItemCount(); item < count; item++)
        SetItemState(item, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
}


void wxETWListCtrl::SelectNone()
{
    for (long item = -1; (item = GetNextItem(item, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED)) != -1;)
        SetItemState(item, 0, wxLIST_STATE_SELECTED);
}


void wxETWListCtrl::RebuildItems()
{
    ChildrenRepositioningGuard child_reposition(this);

    // Get current focus and selection.
    set<size_t> focus, selection;
    for (long item = -1; (item = GetNextItem(item, wxLIST_NEXT_ALL, wxLIST_STATE_FOCUSED)) != -1;)
        focus.insert(m_rec_idx[item]);
    for (long item = -1; (item = GetNextItem(item, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED)) != -1;)
        selection.insert(m_rec_idx[item]);

    // Get current view position (scrolling).
    long
        item_top        = GetTopItem(),
        item_page_count = GetCountPerPage(),
        item_center     = std::min<long>(
            item_top + item_page_count / 2,     // Index of item in the centre of the view
            (item_top + m_rec_idx.size()) / 2); // Index of the item in the centre between top viewed item and the last (when list is not overflowed)
    size_t center = (size_t)item_center < m_rec_idx.size() ? m_rec_idx[item_center] : -1;

    // Rebuild the index.
    m_rec_idx.clear();
    auto selection_end = selection.cend(), focus_end = focus.cend();
    vector<long> selection_out, focus_out;
    long center_out = -1;
    for (size_t i = 0, n = m_rec_db.size(); i < n; i++) {
        size_t i_abs = m_rec_db.abs(i);
        if (i_abs == center)
            center_out = m_rec_idx.size();
        if (IsVisible(m_rec_db[i])) {
            if (selection.find(i_abs) != selection_end)
                selection_out.push_back(m_rec_idx.size());
            if (focus.find(i_abs) != focus_end)
                focus_out.push_back(m_rec_idx.size());
            m_rec_idx.push_back(i_abs);
        }
    }

    // Set new item count.
    long item_count = (long)m_rec_idx.size();
    if (GetItemCount() != item_count)
        SetItemCount(item_count);

    if (item_count) {
        // Restore focus and selection.
        for (size_t i = 0, n = focus_out.size(); i < n; i++)
            SetItemState(focus_out[i], wxLIST_STATE_FOCUSED, wxLIST_STATE_FOCUSED);
        SelectNone();
        for (size_t i = 0, n = selection_out.size(); i < n; i++)
            SetItemState(selection_out[i], wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);

        // Restore scrolling.
        if (center_out != -1) {
            wxRect pos1, pos2;
            GetItemRect(GetTopItem(), pos1);
            GetItemRect(std::max<long>(std::min<long>(center_out, item_count - 1) - item_page_count / 2, 0), pos2);
            ScrollList(pos2.x - pos1.x, pos2.y - pos1.y);
        } else
            EnsureVisible(item_count - 1);

        // Refresh items.
        item_top = GetTopItem();
        RefreshItems(item_top, std::min<long>(item_top + item_page_count, item_count));
    }
}


bool wxETWListCtrl::IsVisible(const EVENT_RECORD &rec) const
{
    return
        m_sources.find(rec.EventHeader.ProviderId) != m_sources.end() &&
        rec.EventHeader.EventDescriptor.Level <= m_level;
}


void wxETWListCtrl::FormatRow(const event_rec &rec, std::string &rowA, std::wstring &rowW) const
{
    rowA.clear();
    rowW.clear();

    // Merge columns.
    string colA;
    wxString colW;
    for (size_t i = 0; i < _countof(m_col_format_width); i++) {
        // Get column text.
        colW = OnGetItemText(rec, i);
        size_t len = colW.Length();
        if (len < m_col_format_width[i]) {
            // Pad it to required length.
            colW.Append(wxT(' '), m_col_format_width[i] - len);
        } else if (m_col_format_width[i] && len > m_col_format_width[i]) {
            // Truncate it and add horizontal ellipsis.
            colW.Truncate(m_col_format_width[i] - 3);
            colW.Append(wxT("..."));
        }

        // Convert to ACP.
        WideCharToMultiByte(CP_ACP, 0, colW.c_str(), -1, colA, NULL, NULL);

        // Append to output.
        if (i) {
            rowA +=  "  ";
            rowW += L"  ";
        }
        rowA += colA;
        rowW += colW;
    }
}


bool wxETWListCtrl::CopyToClipboard(const std::string &dataA, const std::wstring &dataW) const
{
    if (OpenClipboard(GetHWND())) {
        EmptyClipboard();

        HGLOBAL h;
        size_t size;

        size = (dataA.length() + 1) * sizeof(CHAR);
        h = GlobalAlloc(GMEM_MOVEABLE, size);
        if (h) {
            LPVOID d = GlobalLock(h);
            if (d) {
                memcpy(d, dataA.data(), size);
                GlobalUnlock(h);
                SetClipboardData(CF_TEXT, h);
            }
        }

        size = (dataW.length() + 1) * sizeof(WCHAR);
        h = GlobalAlloc(GMEM_MOVEABLE, size);
        if (h) {
            LPVOID d = GlobalLock(h);
            if (d) {
                memcpy(d, dataW.data(), size);
                GlobalUnlock(h);
                SetClipboardData(CF_UNICODETEXT, h);
            }
        }

        CloseClipboard();

        return true;
    } else
        return false;
}


wxListItemAttr *wxETWListCtrl::OnGetItemAttr(long item) const
{
    const event_rec &rec = m_rec_db.at_abs(m_rec_idx.at(item));
    bool is_ours = IsEqualGUID(rec.EventHeader.ProviderId, EAPMETHOD_TRACE_EVENT_PROVIDER) ? true : false;

    // Select appropriate attributes acording to race, colour, or creed...
    return (wxListItemAttr*)(
        ((const EVENT_RECORD&)rec).EventHeader.EventDescriptor.Level >= TRACE_LEVEL_VERBOSE     ? (is_ours ? &(m_item_attr[0][0]) : &(m_item_attr[1][0])) :
        ((const EVENT_RECORD&)rec).EventHeader.EventDescriptor.Level >= TRACE_LEVEL_INFORMATION ? (is_ours ? &(m_item_attr[0][1]) : &(m_item_attr[1][1])) :
        ((const EVENT_RECORD&)rec).EventHeader.EventDescriptor.Level >= TRACE_LEVEL_WARNING     ? (is_ours ? &(m_item_attr[0][2]) : &(m_item_attr[1][2])) :
                                                                                                  (is_ours ? &(m_item_attr[0][3]) : &(m_item_attr[1][3])));
}


wxString wxETWListCtrl::OnGetItemText(long item, long column) const
{
    return OnGetItemText(m_rec_db.at_abs(m_rec_idx.at(item)), column);
}


wxString wxETWListCtrl::OnGetItemText(const winstd::event_rec &rec, long column) const
{
    switch (column) {
    case 0: {
        // Get event time-stamp.
        FILETIME ft;
        ft.dwHighDateTime = rec.EventHeader.TimeStamp.HighPart;
        ft.dwLowDateTime  = rec.EventHeader.TimeStamp.LowPart;

        SYSTEMTIME st, st_local;
        FileTimeToSystemTime(&ft, &st);
        SystemTimeToTzSpecificLocalTime(NULL, &st, &st_local);

        ULONGLONG
            ts = rec.EventHeader.TimeStamp.QuadPart,
            microsec = (ts % 10000000) / 10;

        return tstring_printf(_T("%04d-%02d-%02d %02d:%02d:%02d.%06I64u"),
            st_local.wYear, st_local.wMonth, st_local.wDay, st_local.wHour, st_local.wMinute, st_local.wSecond, microsec);
    }

    case 1:
        // Get process ID.
        return wxString::Format(wxT("%u"), rec.EventHeader.ProcessId);

    case 2:
        // Get thread ID.
        return wxString::Format(wxT("%u"), rec.EventHeader.ThreadId);

    case 3:
        // Get event source.
        return
            IsEqualGUID(rec.EventHeader.ProviderId, EAPMETHOD_TRACE_EVENT_PROVIDER) ? wxT(PRODUCT_NAME_STR) :
            IsEqualGUID(rec.EventHeader.ProviderId, s_provider_eaphost            ) ? wxT("EapHost"       ) :
            IsEqualGUID(rec.EventHeader.ProviderId, s_provider_schannel           ) ? wxT("Schannel"      ) : wxEmptyString;

    case 4: {
        // Get event meta-info.
        unique_ptr<TRACE_EVENT_INFO> info;
        ULONG ulResult;
        if ((ulResult = TdhGetEventInformation((PEVENT_RECORD)&rec, 0, NULL, info)) == ERROR_SUCCESS) {
            if (info->DecodingSource != DecodingSourceWPP) {
                if (rec.EventHeader.Flags & EVENT_HEADER_FLAG_STRING_ONLY) {
                    // This is a string-only event. Print it.
                    return reinterpret_cast<LPCWSTR>(rec.UserData);
                } else {
                    // This is not a string-only event. Prepare parameters.

                    BYTE nPtrSize = (rec.EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;
                    vector<tstring> props;
                    vector<DWORD_PTR> props_msg;
                    props.reserve(info->TopLevelPropertyCount);
                    props_msg.reserve(info->TopLevelPropertyCount);
                    for (ULONG i = 0; i < info->TopLevelPropertyCount; i++) {
                        props.push_back(std::move(PropertyToString((PEVENT_RECORD)&rec, info.get(), i, NULL, 0, nPtrSize)));
                        props_msg.push_back((DWORD_PTR)props[i].c_str());
                    }

                    if (info->EventMessageOffset) {
                        // Format the message.
                        return wstring_msg(0, reinterpret_cast<LPCTSTR>(reinterpret_cast<LPCBYTE>(info.get()) + info->EventMessageOffset), props_msg.data()).c_str();
                    }
                }
            } else if (info->EventMessageOffset) {
                // This is a WPP event.
                return reinterpret_cast<LPCWSTR>(reinterpret_cast<LPCBYTE>(info.get()) + info->EventMessageOffset);
            }
        }
    }
    }

    return wxEmptyString;
}


void wxETWListCtrl::OnETWEvent(wxETWEvent& event)
{
    // Move event, since event handlers will have no use of it and destroy it in the end.
    // This way we save memory allocation and copying.
    event_rec rec(std::move(event.GetRecord()));

    // Is event visible according to current view settings?
    bool is_visible = IsVisible(rec);

    // Move event to the end of the queue.
    size_t pos = m_rec_db.push_back(std::move(rec));

    bool has_moved;
    if (!m_rec_idx.empty() && m_rec_idx.front() == pos) {
        // This event overwrote previous head element in index.
        m_rec_idx.pop_front();
        has_moved = true;
    } else
        has_moved = false;

    if (is_visible) {
        // Push event absolute subscript to the index too.
        m_rec_idx.push_back(pos);
    }

    long item_count = (long)m_rec_idx.size();
    if (GetItemCount() != item_count)
        SetItemCount(item_count);

    if (item_count) {
        if (m_scroll_auto) {
            // Bring the record into view.
            EnsureVisible(item_count - 1);
        }

        if (has_moved) {
            long item_top  = GetTopItem();
            RefreshItems(item_top, std::min<long>(item_top + GetCountPerPage(), item_count));
        }
    }
}


//////////////////////////////////////////////////////////////////////////
// wxPersistentETWListCtrl
//////////////////////////////////////////////////////////////////////////

wxPersistentETWListCtrl::wxPersistentETWListCtrl(wxETWListCtrl *wnd) : wxPersistentWindow<wxETWListCtrl>(wnd)
{
}


wxString wxPersistentETWListCtrl::GetKind() const
{
    return wxT(wxPERSIST_TLW_KIND);
}


void wxPersistentETWListCtrl::Save() const
{
    const wxETWListCtrl * const wnd = static_cast<const wxETWListCtrl*>(GetWindow());

    // Save log's column widths.
    wxListItem col;
    col.SetMask(wxLIST_MASK_TEXT | wxLIST_MASK_WIDTH);
    for (int i = 0, n = wnd->GetColumnCount(); i < n; i++) {
        wnd->GetColumn(i, col);
        SaveValue(wxString::Format(wxT("Column%sWidth"), col.GetText()), col.GetWidth());
    }

    SaveValue(wxT("ScrollAuto"), wnd->m_scroll_auto);

    wxString data_str;
    for (auto src = wnd->m_sources.cbegin(), src_end = wnd->m_sources.cend(); src != src_end; ++src)
        data_str += tstring_guid(*src);
    SaveValue(wxT("Sources"), data_str);

    SaveValue(wxT("Level"), (int)wnd->m_level);
}


bool wxPersistentETWListCtrl::Restore()
{
    wxETWListCtrl * const wnd = static_cast<wxETWListCtrl*>(GetWindow());

    // Restore log's column widths.
    wxListItem col;
    col.SetMask(wxLIST_MASK_TEXT);
    for (int i = 0, n = wnd->GetColumnCount(); i < n; i++) {
        wnd->GetColumn(i, col);

        int width;
        if (RestoreValue(wxString::Format(wxT("Column%sWidth"), col.GetText()), &width))
            wnd->SetColumnWidth(i, width);
    }

    RestoreValue(wxT("ScrollAuto"), &(wnd->m_scroll_auto));

    wnd->m_sources.clear();
    wxString data_str;
    if (RestoreValue(wxT("Sources"), &data_str)) {
        for (size_t i = 0; (i = data_str.find(wxT('{'), i)) != std::string::npos;) {
            GUID guid;
            if (StringToGuid(data_str.data() + i, &guid)) {
                wnd->m_sources.insert(guid);
                i += 38;
            } else
                i++;
        }
    } else {
        // Insert our provider by default.
        wnd->m_sources.insert(EAPMETHOD_TRACE_EVENT_PROVIDER);
    }

    int data_int;
    if (RestoreValue(wxT("Level"), &data_int))
        wnd->m_level = (UCHAR)std::min<int>(std::max<int>(data_int, TRACE_LEVEL_ERROR), TRACE_LEVEL_VERBOSE);

    return true;
}


//////////////////////////////////////////////////////////////////////////
// Local helper functions
//////////////////////////////////////////////////////////////////////////

static tstring MapToString(_In_ const EVENT_MAP_INFO *pMapInfo, _In_ ULONG ulData)
{
    if ( (pMapInfo->Flag &  EVENTMAP_INFO_FLAG_MANIFEST_VALUEMAP) ||
        ((pMapInfo->Flag &  EVENTMAP_INFO_FLAG_WBEM_VALUEMAP    ) && (pMapInfo->Flag & ~EVENTMAP_INFO_FLAG_WBEM_VALUEMAP) != EVENTMAP_INFO_FLAG_WBEM_FLAG))
    {
        if ((pMapInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_NO_MAP) == EVENTMAP_INFO_FLAG_WBEM_NO_MAP)
            return tstring_printf(_T("%ls"), (PBYTE)pMapInfo + pMapInfo->MapEntryArray[ulData].OutputOffset);
        else {
            for (ULONG i = 0; ; i++) {
                if (i >= pMapInfo->EntryCount)
                    return tstring_printf(_T("%lu"), ulData);
                else if (pMapInfo->MapEntryArray[i].Value == ulData)
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
                if (ulData & (1 << i))
                    out.append(tstring_printf(out.empty() ? _T("%ls") : _T(" | %ls"), (PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset));
        } else {
            for (ULONG i = 0; i < pMapInfo->EntryCount; i++)
                if ((pMapInfo->MapEntryArray[i].Value & ulData) == pMapInfo->MapEntryArray[i].Value)
                    out.append(tstring_printf(out.empty() ? _T("%ls") : _T(" | %ls"), (PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset));
        }

        return out.empty() ? tstring_printf(_T("%lu"), ulData) : out;
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
            MultiByteToWideChar(OutType == TDH_OUTTYPE_STRING ? CP_ACP : CP_UTF8, 0, reinterpret_cast<LPCSTR>(pData), (int)nDataSize, str);
            return tstring_printf(_T("%ls"), str.c_str());
        }

        case TDH_INTYPE_COUNTEDSTRING:
            return DataToString(TDH_INTYPE_NONNULLTERMINATEDSTRING, OutType, reinterpret_cast<LPCBYTE>((PUSHORT)pData + 1), *(PUSHORT)pData, pMapInfo, nPtrSize);

        case TDH_INTYPE_COUNTEDANSISTRING:
            return DataToString(TDH_INTYPE_NONNULLTERMINATEDANSISTRING, OutType, reinterpret_cast<LPCBYTE>((PUSHORT)pData + 1), *(PUSHORT)pData, pMapInfo, nPtrSize);

        case TDH_INTYPE_REVERSEDCOUNTEDSTRING:
            return DataToString(TDH_INTYPE_NONNULLTERMINATEDSTRING, OutType, reinterpret_cast<LPCBYTE>((PUSHORT)pData + 1), MAKEWORD(HIBYTE(*(PUSHORT)pData), LOBYTE(*(PUSHORT)pData)), pMapInfo, nPtrSize);

        case TDH_INTYPE_REVERSEDCOUNTEDANSISTRING:
            return DataToString(TDH_INTYPE_NONNULLTERMINATEDANSISTRING, OutType, reinterpret_cast<LPCBYTE>((PUSHORT)pData + 1), MAKEWORD(HIBYTE(*(PUSHORT)pData), LOBYTE(*(PUSHORT)pData)), pMapInfo, nPtrSize);

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
                default:                     return pMapInfo ? MapToString(pMapInfo, *(PULONG)pData) : tstring_printf(_T("%lu"), *(PULONG)pData);
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
            return DataToString(TDH_INTYPE_SYSTEMTIME, OutType, reinterpret_cast<LPCBYTE>(&st_local), sizeof(st_local), pMapInfo, nPtrSize);
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
            assert(nDataSize >= (SIZE_T)nPtrSize * 2);
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
        PROPERTY_DATA_DESCRIPTOR data_desc = { (ULONGLONG)(reinterpret_cast<LPBYTE>(pInfo) + pInfo->EventPropertyInfoArray[pInfo->EventPropertyInfoArray[i].countPropertyIndex].NameOffset), ULONG_MAX };
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
    bool out_nonfirst = false;

    if (pInfo->EventPropertyInfoArray[ulPropIndex].Flags & PropertyParamCount)
        out += tstring_printf(_T("[%u]("), ulArraySize);

    for (ULONG k = 0; k < ulArraySize; k++) {
        if (pInfo->EventPropertyInfoArray[ulPropIndex].Flags & PropertyStruct) {
            // The property is a structure: print the members of the structure.
            if (out_nonfirst) out += _T(", "); else out_nonfirst = true;
            out += _T('(');
            for (USHORT j = pInfo->EventPropertyInfoArray[ulPropIndex].structType.StructStartIndex, usLastMember = pInfo->EventPropertyInfoArray[ulPropIndex].structType.StructStartIndex + pInfo->EventPropertyInfoArray[ulPropIndex].structType.NumOfStructMembers; j < usLastMember; j++) {
                out += tstring_printf(_T("%ls: "), reinterpret_cast<LPBYTE>(pInfo) + pInfo->EventPropertyInfoArray[j].NameOffset);
                out += PropertyToString(pEvent, pInfo, j, reinterpret_cast<LPWSTR>(reinterpret_cast<LPBYTE>(pInfo) + pInfo->EventPropertyInfoArray[ulPropIndex].NameOffset), k, nPtrSize);
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
                        { (ULONGLONG)pStructureName                                                                           , ulStructIndex },
                        { (ULONGLONG)(reinterpret_cast<LPBYTE>(pInfo) + pInfo->EventPropertyInfoArray[ulPropIndex].NameOffset), k             }
                    };
                    ulResult = TdhGetProperty(pEvent, 0, NULL, _countof(data_desc), data_desc, data);
                } else {
                    PROPERTY_DATA_DESCRIPTOR data_desc = { (ULONGLONG)(reinterpret_cast<LPBYTE>(pInfo) + pInfo->EventPropertyInfoArray[ulPropIndex].NameOffset), k };
                    ulResult = TdhGetProperty(pEvent, 0, NULL, 1, &data_desc, data);
                }
                if (ulResult == ERROR_EVT_INVALID_EVENT_DATA) {
                    // This happens with empty/NULL data. Not an error actually.
                    assert(data.empty());
                } else if (ulResult != ERROR_SUCCESS)
                    return tstring_printf(_T("<Error getting property (error %u)>"), ulResult);

                // Get the name/value mapping if the property specifies a value map.
                unique_ptr<EVENT_MAP_INFO> map_info;
                ulResult = TdhGetEventMapInformation(pEvent, reinterpret_cast<LPWSTR>(reinterpret_cast<LPBYTE>(pInfo) + pInfo->EventPropertyInfoArray[ulPropIndex].nonStructType.MapNameOffset), map_info);
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
                        LPWSTR str = reinterpret_cast<LPWSTR>((PBYTE)map_info.get() + map_info->MapEntryArray[i].OutputOffset);
                        SIZE_T len = wcslen(str);
                        if (len) str[len - 1] = 0;
                    }
                }

                if (out_nonfirst) out += _T(", "); else out_nonfirst = true;
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

    if (pInfo->EventPropertyInfoArray[ulPropIndex].Flags & PropertyParamCount)
        out += _T(')');

    return out;
}
