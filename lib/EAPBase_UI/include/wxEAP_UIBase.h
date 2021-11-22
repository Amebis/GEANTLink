/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2021 Amebis
    Copyright © 2016 GÉANT
*/

class wxEAPCredentialsPanelBase;

#pragma once

#include <wx/panel.h>


///
/// \defgroup EAPBaseGUI  GUI
/// Graphical User Interface
///
/// @{

///
/// Base class for all credential entry panel that must provide "Remember" credentials checkbox
///
class wxEAPCredentialsPanelBase : public wxPanel
{
public:
    ///
    /// Constructs a wxPanel with "Remember" credentials checkbox
    ///
    /// \param[in] parent  The parent window
    /// \param[in] winid   An identifier for the panel. \c wxID_ANY is taken to mean a default.
    /// \param[in] pos     The panel position. The value \c wxDefaultPosition indicates a default position, chosen by either the windowing system or wxWidgets, depending on platform.
    /// \param[in] size    The panel size. The value \c wxDefaultSize indicates a default size, chosen by either the windowing system or wxWidgets, depending on platform.
    /// \param[in] style   The window style. See `wxPanel`.
    /// \param[in] name    Window name
    ///
    wxEAPCredentialsPanelBase(wxWindow *parent,
            wxWindowID winid = wxID_ANY,
            const wxPoint& pos = wxDefaultPosition,
            const wxSize& size = wxDefaultSize,
            long style = wxTAB_TRAVERSAL | wxNO_BORDER,
            const wxString& name = wxPanelNameStr) : wxPanel(parent, winid, pos, size, style, name)
    {
    }

    ///
    /// (Un)checks "Remember credentials" checkbox
    ///
    /// \param[in] val  If \c true, checkbox is checked; otherwise cleared
    ///
    virtual void SetRemember(bool val) = 0;

    ///
    /// Returns \c true if "Remember credentials" checkbox is checked
    ///
    virtual bool GetRemember() const = 0;
};

/// @}
