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

/// \addtogroup EventMonitor
/// @{

///
/// Maximum number of event records kept
///
#define wxETWEVENT_RECORDS_MAX  1000000

/// @}

class wxETWEvent;
wxDECLARE_EVENT(wxEVT_ETW_EVENT, wxETWEvent);
#define wxETWEventHandler(func) wxEVENT_HANDLER_CAST(wxETWEventFunction, func)
#define EVT_ETW_EVENT(func) wx__DECLARE_EVT0(wxEVT_ETW_EVENT, wxETWEventHandler(func))

class wxEventTraceProcessorThread;
class wxETWListCtrl;
class wxPersistentETWListCtrl;

#pragma once

#include <wx/listctrl.h>
#include <wx/persist/window.h>
#include <wx/thread.h>

#include <WinStd/ETW.h>

#include <memory>
#include <vector>
#include <set>


/// \addtogroup EventMonitor
/// @{

///
/// ETW event
///
class wxETWEvent : public wxEvent
{
public:
    ///
    /// Creates ETW event
    ///
    /// \param[in] type    The unique type of event
    /// \param[in] record  ETW event record
    ///
    wxETWEvent(wxEventType type = wxEVT_NULL, const EVENT_RECORD &record = s_record_null);

    ///
    /// Copies an ETW event
    ///
    /// \param[in] event  ETW event to copy from
    ///
    wxETWEvent(const wxETWEvent& event);

    ///
    /// Clones the ETW event
    ///
    /// \returns Event copy
    ///
    virtual wxEvent *Clone() const
    {
        return new wxETWEvent(*this);
    }

    ///
    /// Returns ETW event record assosiated with event
    ///
    inline const winstd::event_rec& GetRecord() const
    {
        return m_record;
    }

    ///
    /// Returns ETW event record assosiated with event
    ///
    inline winstd::event_rec& GetRecord()
    {
        return m_record;
    }

private:
    DECLARE_DYNAMIC_CLASS_NO_ASSIGN(wxETWEvent)

public:
    static const EVENT_RECORD s_record_null; ///< Blank ETW event record

protected:
    winstd::event_rec m_record; ///< ETW event record
};


///
/// Prototype of the function consuming `wxETWEvent` events
///
typedef void (wxEvtHandler::*wxETWEventFunction)(wxETWEvent&);


///
/// Monitors ETW events and forwards them as `wxETWEvent` event
///
class wxEventTraceProcessorThread : public wxThread
{
public:
    ///
    /// A thread to process ETW events
    ///
    /// \param[in] parent    Event handler this thread will send record notifications
    /// \param[in] sessions  An array of sessions to monitor
    ///
    wxEventTraceProcessorThread(wxEvtHandler *parent, const wxArrayString &sessions);

    ///
    /// Destructor
    ///
    virtual ~wxEventTraceProcessorThread();

    ///
    /// Closes all session handles to allow graceful thread termination
    ///
    void Abort();

protected:
    /// \cond internal
    virtual ExitCode Entry();
    /// \endcond

private:
    /// \cond internal
    static VOID WINAPI EventRecordCallback(PEVENT_RECORD pEvent);
    /// \endcond

protected:
    std::vector<TRACEHANDLE> m_traces;  ///< An array of tracing sessions this thread is monitoring
    wxEvtHandler *m_parent;             ///< Pointer to the event handler this thread is sending record notifications
};


///
/// Event list control
///
class wxETWListCtrl : public wxListCtrl
{
protected:
    ///
    /// Functor for GUID comparison
    ///
    struct less_guid : public std::binary_function<GUID, GUID, bool>
    {
        ///
        /// Compares two GUIDs
        ///
        bool operator()(const GUID &a, const GUID &b) const
        {
            if (a.Data1 < b.Data1) return true;
            if (a.Data1 > b.Data1) return false;
            if (a.Data2 < b.Data2) return true;
            if (a.Data2 > b.Data2) return false;
            if (a.Data3 < b.Data3) return true;
            if (a.Data3 > b.Data3) return false;
            if (memcmp(a.Data4, b.Data4, sizeof(a.Data4)) < 0) return true;
            return false;
        }
    };

    ///
    /// A set of GUIDs
    ///
    typedef std::set<GUID, less_guid> guidset;

public:
    ///
    /// Creates a list control for ETW log display
    ///
    /// \param[in] parent     Parent window. Must not be \c NULL.
    /// \param[in] id         Window identifier. The value \c wxID_ANY indicates a default value.
    /// \param[in] pos        Window position. If \c wxDefaultPosition is specified then a default position is chosen.
    /// \param[in] size       Window size. If \c wxDefaultSize is specified then the window is sized appropriately.
    /// \param[in] style      Window style. See \c wxListCtrl.
    /// \param[in] validator  Window validator
    /// \param[in] name       Window name
    ///
    wxETWListCtrl(
              wxWindow    *parent,
              wxWindowID  id         = wxID_ANY,
        const wxPoint     &pos       = wxDefaultPosition,
        const wxSize      &size      = wxDefaultSize,
              long        style      = wxLC_NO_SORT_HEADER|wxLC_REPORT|wxLC_VIRTUAL|wxNO_BORDER,
        const wxValidator &validator = wxDefaultValidator,
        const wxString    &name      = wxListCtrlNameStr);

    ///
    /// Destructor
    ///
    virtual ~wxETWListCtrl();

    ///
    /// Returns true if the list is empty
    ///
    inline bool IsEmpty() const
    {
        return m_rec_db.empty();
    }

    ///
    /// Copies selected rows to clipboard
    ///
    void CopySelected() const;

    ///
    /// Copies all rows (including hidden ones) to clipboard
    ///
    void CopyAll() const;

    ///
    /// Empties the list
    ///
    void ClearAll();

    ///
    /// Selects all rows
    ///
    void SelectAll();

    ///
    /// Clears row selection
    ///
    void SelectNone();

    ///
    /// Rebuilds the list
    ///
    void RebuildItems();

    ///
    /// Checks if given ETW source is enabled
    ///
    /// \param[in] guid  GUID of ETW source
    ///
    /// \returns
    /// - \c true if ETW source with \p guid GUID is enabled;
    /// - \c false otherwise.
    ///
    inline bool IsSourceEnabled(const GUID &guid) const
    {
        return m_sources.find(guid) != m_sources.end();
    }

    ///
    /// Enables/Disables ETW source
    ///
    /// \param[in] guid    GUID of ETW source
    /// \param[in] enable  \c true to enable, \c false to disable
    ///
    inline void EnableSource(const GUID &guid, bool enable = true)
    {
        auto s = m_sources.find(guid);
        if (enable) {
            if (s == m_sources.end()) {
                m_sources.insert(guid);
                RebuildItems();
            }
        } else {
            if (s != m_sources.end()) {
                m_sources.erase(s);
                RebuildItems();
            }
        }
    }

    friend class wxPersistentETWListCtrl;   // Allow saving/restoring window state.

protected:
    /// \cond internal
    bool IsVisible(const EVENT_RECORD &rec) const;
    void FormatRow(const winstd::event_rec &rec, std::string &rowA, std::wstring &rowW) const;
    bool CopyToClipboard(const std::string &dataA, const std::wstring &dataW) const;

    virtual wxListItemAttr *OnGetItemAttr(long item) const;
    virtual wxString OnGetItemText(long item, long column) const;
    virtual wxString OnGetItemText(const winstd::event_rec &rec, long column) const;
    void OnETWEvent(wxETWEvent& event);
    /// \endcond

    DECLARE_EVENT_TABLE()

public:
    bool m_scroll_auto;                                 ///< Is autoscrolling enabled?
    UCHAR m_level;                                      ///< Shows messages up to this level of verboseness

    static const GUID s_provider_eaphost;               ///< EapHost event provider ID
    static const GUID s_provider_schannel;              ///< Schannel event provider ID

protected:
    winstd::event_session m_session;                    ///< Event session
    wxEventTraceProcessorThread *m_proc;                ///< Processor thread

    guidset m_sources;                                  ///< Set of enabled sources

    wxListItemAttr m_item_attr[2][4];                   ///< Current item attributes
    winstd::vector_queue<winstd::event_rec> m_rec_db;   ///< Event record database
    winstd::vector_queue<size_t> m_rec_idx;             ///< Event record database indices of shown records

    size_t m_col_format_width[5];                       ///< Column widths for pre-formatted row display (0 = unlimited)
};


///
/// Supports saving/restoring `wxETWListCtrl` state
///
class wxPersistentETWListCtrl : public wxPersistentWindow<wxETWListCtrl>
{
public:
    ///
    /// Constructor for a persistent window object
    ///
    /// \param[in] wnd  Window this object will save/restore
    ///
    wxPersistentETWListCtrl(wxETWListCtrl *wnd);

    ///
    /// Returns the string uniquely identifying the objects supported by this adapter.
    ///
    /// \returns This implementation always returns `wxT(wxPERSIST_TLW_KIND)`
    ///
    virtual wxString GetKind() const;

    ///
    /// Saves the object properties
    ///
    virtual void Save() const;

    ///
    /// Restores the object properties
    ///
    /// \returns
    /// - \c true if the properties were successfully restored;
    /// - \c false otherwise.
    ///
    virtual bool Restore();
};


///
/// Creates persistent window object for `wxETWListCtrl` class window
///
inline wxPersistentObject *wxCreatePersistentObject(wxETWListCtrl *wnd)
{
    return new wxPersistentETWListCtrl(wnd);
}

/// @}
