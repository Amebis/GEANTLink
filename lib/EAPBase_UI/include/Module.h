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

namespace eap
{
    class peer_ui;
    class monitor_ui;
}

#pragma once

#include "../../EAPBase/include/Module.h"


namespace eap
{
    /// \addtogroup EAPBaseModule
    /// @{

    ///
    /// EAP UI peer base abstract class
    ///
    /// A group of methods all EAP UI peers must or should implement.
    ///
    class peer_ui : public module
    {
    public:
        ///
        /// Constructs a EAP UI peer module for the given EAP type
        ///
        /// \param[in] eap_method  EAP method type ID
        ///
        peer_ui(_In_ winstd::eap_type_t eap_method);

        ///
        /// Converts XML into the configuration BLOB.
        ///
        /// \sa [EapPeerConfigXml2Blob function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363602.aspx)
        ///
        /// \param[in ] dwFlags                   A combination of EAP flags that describe the EAP authentication session behavior.
        /// \param[in ] pConfigRoot               Pointer to the XML configuration to be converted.
        /// \param[out] pConnectionDataOut        A pointer to a pointer to a byte buffer that contains the configuration data converted from XML. The configuration data is created inside the EapHostConfig Schema element. The buffer is of size \p pdwConnectionDataOutSize. After consuming the data, this memory must be freed by calling \p EapPeerFreeMemory().
        /// \param[out] pdwConnectionDataOutSize  A pointer to the size, in bytes, of the configuration BLOB in \p pConnectionDataOut.
        ///
        virtual void config_xml2blob(
            _In_  DWORD       dwFlags,
            _In_  IXMLDOMNode *pConfigRoot,
            _Out_ BYTE        **pConnectionDataOut,
            _Out_ DWORD       *pdwConnectionDataOutSize) = 0;

        ///
        /// Converts the configuration BLOB to XML.
        ///
        /// The configuration BLOB is returned in the `ppConnectionDataOut` parameter of the `EapPeerInvokeConfigUI` function.
        ///
        /// \sa [EapPeerConfigBlob2Xml function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363601.aspx)
        ///
        /// \param[in] dwFlags               A combination of EAP flags that describe the EAP authentication session behavior.
        /// \param[in] pConnectionData       A pointer to a buffer that contains the configuration BLOB to convert. The buffer is of size \p dwConnectionDataSize.
        /// \param[in] dwConnectionDataSize  The size, in bytes, of the configuration BLOB in \p pConnectionData.
        /// \param[in] pDoc                  A pointer to a pointer to an XML document that contains the converted configuration. If the EAP method does not support the \p EapPeerConfigBlob2Xml() function, the XML document will contain the \p ConfigBlob node with the BLOB in string form. The EAP method should create configuration inside the EapHostConfig Schema configuration element.
        /// \param[in] pConfigRoot           Configuration root XML node
        ///
        virtual void config_blob2xml(
            _In_                                   DWORD           dwFlags,
            _In_count_(dwConnectionDataSize) const BYTE            *pConnectionData,
            _In_                                   DWORD           dwConnectionDataSize,
            _In_                                   IXMLDOMDocument *pDoc,
            _In_                                   IXMLDOMNode     *pConfigRoot) = 0;

        ///
        /// Raises the EAP method's specific connection configuration user interface dialog on the client.
        ///
        /// \sa [EapPeerInvokeConfigUI function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363614.aspx)
        ///
        /// \param[in ] hwndParent                A handle to the parent window which will spawn the connection configuration user interface dialog.
        /// \param[in ] pConnectionDataIn         A pointer to a buffer that contains the configuration BLOB to convert. The buffer is of size \p dwConnectionDataInSize.
        /// \param[in ] dwConnectionDataInSize    The size, in bytes, of the configuration BLOB in \p pConnectionDataIn.
        /// \param[out] ppConnectionDataOut       Receives a pointer to a pointer that contains a byte buffer with the user-configured connection data.
        /// \param[out] pdwConnectionDataOutSize  Receives a pointer to the size, in bytes, of the \p ppConnectionDataOut parameter.
        ///
        virtual void invoke_config_ui(
            _In_                                     HWND  hwndParent,
            _In_count_(dwConnectionDataInSize) const BYTE  *pConnectionDataIn,
            _In_                                     DWORD dwConnectionDataInSize,
            _Out_                                    BYTE  **ppConnectionDataOut,
            _Out_                                    DWORD *pdwConnectionDataOutSize) = 0;

        ///
        /// Raises a custom interactive user interface dialog to obtain user identity information for the EAP method on the client.
        ///
        /// \sa [EapPeerInvokeIdentityUI function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363615.aspx)
        ///
        /// \param[in ] hwndParent            A handle to the parent window which will spawn the interactive user interface dialog to obtain the identity data. Can be \c NULL.
        /// \param[in ] dwFlags               A combination of EAP flags that describe the EAP authentication session behavior.
        /// \param[in ] pConnectionData       A pointer to a buffer that contains the configuration BLOB to convert. The buffer is of size \p dwConnectionDataSize.
        /// \param[in ] dwConnectionDataSize  The size, in bytes, of the configuration BLOB in \p pConnectionData.
        /// \param[in ] pUserData             A pointer to the user data specific to this authentication used to pre-populate the user data. When this API is called for the first time, or when a new authentication session starts, this parameter is \c NULL. Otherwise, set this parameter to the `pUserData` member of the structure pointed to by the \p pResult parameter received by `EapPeerGetResult()`.
        /// \param[in ] dwUserDataSize        Specifies the size, in bytes, of the user identity data returned in \p pUserData.
        /// \param[out] ppUserDataOut         A pointer to the pointer of the returned user data. The data is passed to `EapPeerBeginSession()` as input \p pUserData.
        /// \param[out] pdwUserDataOutSize    Specifies the size, in bytes, of the \p ppUserDataOut buffer.
        /// \param[out] ppwszIdentity         A pointer to the returned user identity. The pointer will be included in the identity response packet and returned to the server.
        ///
        virtual void invoke_identity_ui(
            _In_                                   HWND   hwndParent,
            _In_                                   DWORD  dwFlags,
            _In_count_(dwConnectionDataSize) const BYTE   *pConnectionData,
            _In_                                   DWORD  dwConnectionDataSize,
            _In_count_(dwUserDataSize)       const BYTE   *pUserData,
            _In_                                   DWORD  dwUserDataSize,
            _Out_                                  BYTE   **ppUserDataOut,
            _Out_                                  DWORD  *pdwUserDataOutSize,
            _Out_                                  LPWSTR *ppwszIdentity) = 0;

        ///
        /// Raises a custom interactive user interface dialog for the EAP method on the client.
        ///
        /// \sa [EapPeerInvokeInteractiveUI function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363616.aspx)
        ///
        /// \param[in ] hwndParent                    A handle to the parent window which will spawn the interactive user interface dialog.
        /// \param[in ] pUIContextData                A pointer to an opaque byte buffer that contains the context data used to create the user interface dialog.
        /// \param[in ] dwUIContextDataSize           The size, in bytes, of the user interface context data specified by \p pUIContextData.
        /// \param[out] ppDataFromInteractiveUI       A pointer to the address of an opaque byte buffer that contains data obtained from the interactive user interface dialog.
        /// \param[out] pdwDataFromInteractiveUISize  A pointer to the size, in bytes, of the data returned in \p ppDataFromInteractiveUI.
        ///
        virtual void invoke_interactive_ui(
            _In_                                  HWND  hwndParent,
            _In_count_(dwUIContextDataSize) const BYTE  *pUIContextData,
            _In_                                  DWORD dwUIContextDataSize,
            _Inout_                               BYTE  **ppDataFromInteractiveUI,
            _Inout_                               DWORD *pdwDataFromInteractiveUISize) = 0;
    };

    /// @}

    /// \addtogroup EAPBaseGUI
    /// @{

    ///
    /// Base class to enable single instance of the same dialog (master) return result to multiple threads (slaves)
    ///
    class monitor_ui
    {
    public:
        ///
        /// Constructs a UI monitor
        ///
        monitor_ui(_In_ HINSTANCE module, _In_ const GUID &guid);

        ///
        /// Destructs the UI monitor
        ///
        virtual ~monitor_ui();

        ///
        /// Sets pop-up window handle
        ///
        /// \param[in] hwnd  Handle of window to set as a new pop-up
        ///
        void set_popup(_In_ HWND hwnd);

        ///
        /// Notifies all slaves waiting for this master and send them result data
        ///
        /// \param[in] data  Pointer to result data
        /// \param[in] size  \p data size in bytes
        ///
        void release_slaves(_In_bytecount_(size) const void *data, _In_ size_t size) const;

        ///
        /// Returns true if this is a master
        ///
        inline bool is_master() const
        {
            return m_is_master;
        }

        ///
        /// Returns true if this is a slave
        ///
        inline bool is_slave() const
        {
            return !is_master();
        }

        ///
        /// Returns the data master send
        ///
        inline const std::vector<unsigned char>& master_data() const
        {
            return m_data;
        }

    protected:
        /// \cond internal

        virtual LRESULT winproc(
            _In_ UINT   msg,
            _In_ WPARAM wparam,
            _In_ LPARAM lparam);

        static LRESULT CALLBACK winproc(
            _In_ HWND   hwnd,
            _In_ UINT   msg,
            _In_ WPARAM wparam,
            _In_ LPARAM lparam);

        /// \endcond

    protected:
        bool m_is_master;                   ///< Is this monitor master?
        HWND m_hwnd;                        ///< Message window handle
        std::list<HWND> m_slaves;           ///< List of slaves to notify on finish
        volatile HWND m_hwnd_popup;         ///< Pop-up window handle
        std::vector<unsigned char> m_data;  ///< Data master sent

        // Custom window messages
        static const UINT s_msg_attach;     ///< Slave sends this message to attach to master
        static const UINT s_msg_finish;     ///< Master sends this message to slaves to notify them it has finished (wparam has size, lparam has data)
    };

    /// @}
}
