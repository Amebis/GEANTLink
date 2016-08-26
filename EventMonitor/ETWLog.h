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
/// Maximum number of event records kept
///
#define wxETWEVENT_RECORDS_MAX  1000000

///
/// ETW event
///
class wxETWEvent;
wxDECLARE_EVENT(wxEVT_ETW_EVENT, wxETWEvent);
#define wxETWEventHandler(func) wxEVENT_HANDLER_CAST(wxETWEventFunction, func)
#define EVT_ETW_EVENT(func) wx__DECLARE_EVT0(wxEVT_ETW_EVENT, wxETWEventHandler(func))

///
/// Event trace processor
///
class wxEventTraceProcessorThread;

///
/// Event list control
///
class wxETWListCtrl;

///
/// Supports saving/restoring wxETWListCtrl state
///
class wxPersistentETWListCtrl;

#pragma once

#include <wx/listctrl.h>
#include <wx/persist/window.h>
#include <wx/thread.h>

#include <WinStd/ETW.h>

#include <memory>
#include <vector>


class wxETWEvent : public wxEvent
{
public:
    wxETWEvent(wxEventType type = wxEVT_NULL, const EVENT_RECORD &record = s_record_null);
    wxETWEvent(const wxETWEvent& event);
    virtual wxEvent *Clone() const { return new wxETWEvent(*this); }

    inline const winstd::event_rec&  GetRecord() const { return m_record; }
    inline       winstd::event_rec&  GetRecord()       { return m_record; }

protected:
    bool DoSetExtendedData(size_t extended_data_count, const EVENT_HEADER_EXTENDED_DATA_ITEM *extended_data);
    bool DoSetUserData(size_t user_data_length, const void *user_data);

private:
    DECLARE_DYNAMIC_CLASS_NO_ASSIGN(wxETWEvent)

public:
    static const EVENT_RECORD s_record_null;

protected:
    winstd::event_rec m_record; ///< ETW event record
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
              long        style      = wxLC_NO_SORT_HEADER|wxLC_REPORT|wxLC_VIRTUAL|wxNO_BORDER,
        const wxValidator &validator = wxDefaultValidator,
        const wxString    &name      = wxListCtrlNameStr);
    virtual ~wxETWListCtrl();

    bool IsEmpty() const { return m_rec_db.empty(); }
    void CopySelected() const;
    void CopyAll() const;
    void ClearAll();
    void SelectAll();
    void SelectNone();
    void RebuildItems();

    friend class wxPersistentETWListCtrl;   // Allow saving/restoring window state.

protected:
    bool IsVisible(const EVENT_RECORD &rec) const;
    void FormatRow(const winstd::event_rec &rec, std::string &rowA, std::wstring &rowW) const;
    bool CopyToClipboard(const std::string &dataA, const std::wstring &dataW) const;

    virtual wxListItemAttr *OnGetItemAttr(long item) const;
    virtual wxString OnGetItemText(long item, long column) const;
    virtual wxString OnGetItemText(const winstd::event_rec &rec, long column) const;
    void OnETWEvent(wxETWEvent& event);
    DECLARE_EVENT_TABLE()

public:
    bool m_scroll_auto;                                 ///< Is autoscrolling enabled?
    bool m_source_eaphost;                              ///< Shows EAPHost messages
    bool m_source_schannel;                             ///< Shows Schannel messages
    bool m_source_product;                              ///< Shows native messages
    UCHAR m_level;                                      ///< Shows messages up to this level of verboseness

    static const GUID s_provider_eaphost;               ///< EAPHost event provider ID
    static const GUID s_provider_schannel;              ///< Schannel event provider ID

protected:
    winstd::event_session m_session;                    ///< Event session
    wxEventTraceProcessorThread *m_proc;                ///< Processor thread
    long m_item_id;                                     ///< Next free list item ID

    wxListItemAttr m_item_attr[2][4];                   ///< Current item attributes
    winstd::vector_queue<winstd::event_rec> m_rec_db;   ///< Event record database
    winstd::vector_queue<size_t> m_rec_idx;             ///< Event record database indices of shown records

    size_t m_col_format_width[5];                       ///< Column widths for pre-formatted row display (0 = unlimited)
};


class wxPersistentETWListCtrl : public wxPersistentWindow<wxETWListCtrl>
{
public:
    wxPersistentETWListCtrl(wxETWListCtrl *wnd);

    virtual wxString GetKind() const;
    virtual void Save() const;
    virtual bool Restore();
};


inline wxPersistentObject *wxCreatePersistentObject(wxETWListCtrl *wnd)
{
    return new wxPersistentETWListCtrl(wnd);
}
