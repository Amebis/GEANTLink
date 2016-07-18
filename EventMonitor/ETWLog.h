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

#include <wx/event.h>

///
/// ETW event
///
class wxETWEvent;
wxDECLARE_EVENT(wxEVT_ETW_EVENT, wxETWEvent);
#define wxETWEventHandler(func) wxEVENT_HANDLER_CAST(wxETWEventFunction, func)
#define EVT_ETW_EVENT(func) wx__DECLARE_EVT0(wxEVT_ETW_EVENT, wxETWEventHandler(func))

///
/// Event list control
///
class wxETWListCtrl;

///
/// Event trace processor
///
class wxEventTraceProcessorThread;

#pragma once

#include <wx/listctrl.h>
#include <wx/thread.h>

#include <WinStd/ETW.h>

#include <vector>


class wxETWEvent : public wxEvent
{
public:
    wxETWEvent(wxEventType type = wxEVT_NULL, const EVENT_RECORD &record = s_record_null);
    wxETWEvent(const wxETWEvent& event);
    virtual ~wxETWEvent();
    virtual wxEvent *Clone() const { return new wxETWEvent(*this); }

    inline const EVENT_RECORD& GetRecord() const { return m_record; }
    inline       EVENT_RECORD& GetRecord()       { return m_record; }

    inline const EVENT_HEADER& GetHeader() const { return m_record.EventHeader; }

    inline const ETW_BUFFER_CONTEXT& GetBufferContext() const { return m_record.BufferContext; }

    bool SetExtendedData(size_t extended_data_count, const EVENT_HEADER_EXTENDED_DATA_ITEM *extended_data);
    inline size_t GetExtendedDataCount() const { return m_record.ExtendedDataCount; }
    inline const EVENT_HEADER_EXTENDED_DATA_ITEM& GetExtendedData(size_t index) const { wxASSERT(index < m_record.ExtendedDataCount); return m_record.ExtendedData[index]; }

    bool SetUserData(size_t user_data_length, const void *user_data);
    inline size_t GetUserDataLength() const { return m_record.UserDataLength; }
    inline void *GetUserData() const { return m_record.UserData; }

protected:
    bool DoSetExtendedData(size_t extended_data_count, const EVENT_HEADER_EXTENDED_DATA_ITEM *extended_data);
    bool DoSetUserData(size_t user_data_length, const void *user_data);

private:
    DECLARE_DYNAMIC_CLASS_NO_ASSIGN(wxETWEvent)

public:
    static const EVENT_RECORD s_record_null;

protected:
    EVENT_RECORD m_record;  ///< ETW event record
};


typedef void (wxEvtHandler::*wxETWEventFunction)(wxETWEvent&);


class wxEventTraceProcessorThread : public wxThread
{
public:
    wxEventTraceProcessorThread(wxEvtHandler *parent, const wxArrayString &sessions);
    virtual ~wxEventTraceProcessorThread();

    void Abort();

protected:
    virtual ExitCode Entry();

private:
    static VOID WINAPI EventRecordCallback(PEVENT_RECORD pEvent);

protected:
    std::vector<TRACEHANDLE> m_traces;  ///< An array of tracing sessions this thread is monitoring
    wxEvtHandler *m_parent;             ///< Pointer to the event handler this thread is sending record notifications
};


class wxETWListCtrl : public wxListCtrl
{
public:
    wxETWListCtrl(
              wxWindow    *parent,
              wxWindowID  id         = wxID_ANY,
        const wxPoint     &pos       = wxDefaultPosition,
        const wxSize      &size      = wxDefaultSize,
              long        style      = wxLC_NO_SORT_HEADER|wxLC_REPORT|wxLC_SINGLE_SEL|wxNO_BORDER,
        const wxValidator &validator = wxDefaultValidator,
        const wxString    &name      = wxListCtrlNameStr);
    virtual ~wxETWListCtrl();

protected:
    void OnETWEvent(wxETWEvent& event);
    DECLARE_EVENT_TABLE()

public:
    static const GUID s_provider_eaphost;   ///< EAPHost event provider ID

protected:
    winstd::event_session m_session;        ///< Event session
    wxEventTraceProcessorThread *m_proc;    ///< Processor thread
    long m_item_id;                         ///< Next free list item ID
};
