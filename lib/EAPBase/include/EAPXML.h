/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2020 Amebis
    Copyright © 2016 GÉANT
*/

#include <WinStd/COM.h>

#include <MsXml.h>
#include <msxml6.h>
#include <sal.h>

#include <string>
#include <vector>

namespace eapxml
{
    ///
    /// \defgroup EAPBaseXML  XML DOM
    /// Easy interaction with MSXML
    ///
    /// @{

    ///
    /// Returns owner document object for a given node
    ///
    /// \param[in ] pXmlNode  XML node
    /// \param[out] ppXmlDoc  XML document
    ///
    /// \returns
    /// - >0 if succeeded with warnings;
    /// - =0 (\c S_OK) if successful;
    /// - <0 if failed.
    /// Use `SUCCEEDED()` macro to test for first two cases (>=0) or `FAILED()` to test for failure.
    ///
    inline HRESULT get_document(_In_ IXMLDOMNode *pXmlNode, _Out_ winstd::com_obj<IXMLDOMDocument2> &ppXmlDoc);

    ///
    /// Selects single child node by name
    ///
    /// \param[in ] pXmlParent    Parent XML node
    /// \param[in ] bstrNodeName  XML node selection name
    /// \param[out] ppXmlNode     Child XML node found
    ///
    /// \returns
    /// - >0 if succeeded with warnings;
    /// - =0 (\c S_OK) if successful;
    /// - <0 if failed.
    /// Use `SUCCEEDED()` macro to test for first two cases (>=0) or `FAILED()` to test for failure.
    ///
    inline HRESULT select_node(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrNodeName, _Out_ winstd::com_obj<IXMLDOMNode> &ppXmlNode);

    ///
    /// Selects child nodes by name
    ///
    /// \param[in ] pXmlParent    Parent XML node
    /// \param[in ] bstrNodeName  XML node selection name
    /// \param[out] ppXmlNodes    List of child XML nodes found
    ///
    /// \returns
    /// - >0 if succeeded with warnings;
    /// - =0 (\c S_OK) if successful;
    /// - <0 if failed.
    /// Use `SUCCEEDED()` macro to test for first two cases (>=0) or `FAILED()` to test for failure.
    ///
    inline HRESULT select_nodes(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrNodeName, _Out_ winstd::com_obj<IXMLDOMNodeList> &ppXmlNodes);

    ///
    /// Selects single child element by name
    ///
    /// \param[in ] pXmlParent       Parent XML node
    /// \param[in ] bstrElementName  XML element selection name
    /// \param[out] ppXmlElement     Child XML element found
    ///
    /// \returns
    /// - >0 if succeeded with warnings;
    /// - =0 (\c S_OK) if successful;
    /// - <0 if failed.
    /// Use `SUCCEEDED()` macro to test for first two cases (>=0) or `FAILED()` to test for failure.
    ///
    inline HRESULT select_element(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ winstd::com_obj<IXMLDOMElement> &ppXmlElement);

    ///
    /// Creates a new element
    ///
    /// \param[in ] pDoc             Owner XML document
    /// \param[in ] bstrElementName  XML element name
    /// \param[in ] bstrNamespace    XML element namespace
    /// \param[out] ppXmlElement     XML element created
    ///
    /// \returns
    /// - >0 if succeeded with warnings;
    /// - =0 (\c S_OK) if successful;
    /// - <0 if failed.
    /// Use `SUCCEEDED()` macro to test for first two cases (>=0) or `FAILED()` to test for failure.
    ///
    inline HRESULT create_element(_In_ IXMLDOMDocument *pDoc, _In_z_ const BSTR bstrElementName, _In_z_ const BSTR bstrNamespace, _Out_ winstd::com_obj<IXMLDOMElement> &ppXmlElement);

    ///
    /// Creates a new child element if not already present
    ///
    /// \param[in ] pDoc                   Owner XML document
    /// \param[in ] pXmlParent             Parent XML node
    /// \param[in ] bstrElementNameSelect  XML element selection name
    /// \param[in ] bstrElementNameCreate  XML element name
    /// \param[in ] bstrNamespace          XML element namespace
    /// \param[out] ppXmlElement           XML element found or created
    ///
    /// \returns
    /// - >0 if succeeded with warnings;
    /// - =0 (\c S_OK) if successful;
    /// - <0 if failed.
    /// Use `SUCCEEDED()` macro to test for first two cases (>=0) or `FAILED()` to test for failure.
    ///
    inline HRESULT create_element(_In_ IXMLDOMDocument *pDoc, IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementNameSelect, _In_z_ const BSTR bstrElementNameCreate, _In_z_ const BSTR bstrNamespace, _Out_ winstd::com_obj<IXMLDOMElement> &ppXmlElement);

    ///
    /// Tests if node has a parent set
    ///
    /// \param[in] pXmlNode  XML node
    ///
    /// \returns
    /// - Non zero when \p pXmlNode has a parent set;
    /// - Zero otherwise.
    ///
    inline bool has_parent(_In_ IXMLDOMNode *pXmlNode);

    ///
    /// Returns child element text
    ///
    /// \param[in ] pXmlParent       Parent XML node
    /// \param[in ] bstrElementName  XML element selection name
    /// \param[out] pbstrValue       XML element text
    /// \param[out] ppXmlElement     Child XML element found
    ///
    /// \returns
    /// - >0 if succeeded with warnings;
    /// - =0 (\c S_OK) if successful;
    /// - <0 if failed.
    /// Use `SUCCEEDED()` macro to test for first two cases (>=0) or `FAILED()` to test for failure.
    ///
    inline HRESULT get_element_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ winstd::bstr &pbstrValue, _Out_opt_ winstd::com_obj<IXMLDOMElement> *ppXmlElement = NULL);

    ///
    /// Returns child element text
    ///
    /// \param[in ] pXmlParent       Parent XML node
    /// \param[in ] bstrElementName  XML element selection name
    /// \param[out] sValue           XML element text
    /// \param[out] ppXmlElement     Child XML element found
    ///
    /// \returns
    /// - >0 if succeeded with warnings;
    /// - =0 (\c S_OK) if successful;
    /// - <0 if failed.
    /// Use `SUCCEEDED()` macro to test for first two cases (>=0) or `FAILED()` to test for failure.
    ///
    template<class _Traits, class _Ax> inline HRESULT get_element_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ std::basic_string<wchar_t, _Traits, _Ax> &sValue, _Out_opt_ winstd::com_obj<IXMLDOMElement> *ppXmlElement = NULL);

    ///
    /// Returns child element text converted to number
    ///
    /// \param[in ] pXmlParent       Parent XML node
    /// \param[in ] bstrElementName  XML element selection name
    /// \param[out] pdwValue         XML element text converted to number
    /// \param[out] ppXmlElement     Child XML element found
    ///
    /// \returns
    /// - >0 if succeeded with warnings;
    /// - =0 (\c S_OK) if successful;
    /// - <0 if failed.
    /// Use `SUCCEEDED()` macro to test for first two cases (>=0) or `FAILED()` to test for failure.
    ///
    inline HRESULT get_element_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ DWORD &pdwValue, _Out_opt_ winstd::com_obj<IXMLDOMElement> *ppXmlElement = NULL);

    ///
    /// Returns child element text converted to boolean
    ///
    /// \param[in ] pXmlParent       Parent XML node
    /// \param[in ] bstrElementName  XML element selection name
    /// \param[out] pbValue          XML element text converted to boolean
    /// \param[out] ppXmlElement     Child XML element found
    ///
    /// \returns
    /// - >0 if succeeded with warnings;
    /// - =0 (\c S_OK) if successful;
    /// - <0 if failed.
    /// Use `SUCCEEDED()` macro to test for first two cases (>=0) or `FAILED()` to test for failure.
    ///
    inline HRESULT get_element_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ bool &pbValue, _Out_opt_ winstd::com_obj<IXMLDOMElement> *ppXmlElement = NULL);

    ///
    /// Returns child element BLOB encoded as Base64 text
    ///
    /// \param[in ] pXmlParent       Parent XML node
    /// \param[in ] bstrElementName  XML element selection name
    /// \param[out] aValue           XML element BLOB
    /// \param[out] ppXmlElement     Child XML element found
    ///
    /// \returns
    /// - >0 if succeeded with warnings;
    /// - =0 (\c S_OK) if successful;
    /// - <0 if failed.
    /// Use `SUCCEEDED()` macro to test for first two cases (>=0) or `FAILED()` to test for failure.
    ///
    template<class _Ty, class _Ax> inline HRESULT get_element_base64(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ std::vector<_Ty, _Ax> &aValue, _Out_opt_ winstd::com_obj<IXMLDOMElement> *ppXmlElement = NULL);

    ///
    /// Returns child element BLOB encoded as hexadecimal text
    ///
    /// \param[in ] pXmlParent       Parent XML node
    /// \param[in ] bstrElementName  XML element selection name
    /// \param[out] aValue           XML element BLOB
    /// \param[out] ppXmlElement     Child XML element found
    ///
    /// \returns
    /// - >0 if succeeded with warnings;
    /// - =0 (\c S_OK) if successful;
    /// - <0 if failed.
    /// Use `SUCCEEDED()` macro to test for first two cases (>=0) or `FAILED()` to test for failure.
    ///
    template<class _Ty, class _Ax> inline HRESULT get_element_hex(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ std::vector<_Ty, _Ax> &aValue, _Out_opt_ winstd::com_obj<IXMLDOMElement> *ppXmlElement = NULL);

    ///
    /// Returns child element localizable text
    ///
    /// \param[in ] pXmlParent       Parent XML node
    /// \param[in ] bstrElementName  XML element selection name
    /// \param[in ] pszLang          Desired localization
    /// \param[out] pbstrValue       XML element text
    /// \param[out] ppXmlElement     Child XML element found
    ///
    /// \returns
    /// - >0 if succeeded with warnings;
    /// - =0 (\c S_OK) if successful;
    /// - <0 if failed.
    /// Use `SUCCEEDED()` macro to test for first two cases (>=0) or `FAILED()` to test for failure.
    ///
    inline HRESULT get_element_localized(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _In_z_ LPCWSTR pszLang, _Out_ winstd::bstr &pbstrValue, _Out_opt_ winstd::com_obj<IXMLDOMElement> *ppXmlElement = NULL);

    ///
    /// Returns child element localizable text
    ///
    /// \param[in ] pXmlParent       Parent XML node
    /// \param[in ] bstrElementName  XML element selection name
    /// \param[in ] pszLang          Desired localization
    /// \param[out] sValue           XML element text
    /// \param[out] ppXmlElement     Child XML element found
    ///
    /// \returns
    /// - >0 if succeeded with warnings;
    /// - =0 (\c S_OK) if successful;
    /// - <0 if failed.
    /// Use `SUCCEEDED()` macro to test for first two cases (>=0) or `FAILED()` to test for failure.
    ///
    template<class _Traits, class _Ax> inline HRESULT get_element_localized(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _In_z_ LPCWSTR pszLang, _Out_ std::basic_string<wchar_t, _Traits, _Ax> &sValue, _Out_opt_ winstd::com_obj<IXMLDOMElement> *ppXmlElement = NULL);

    ///
    /// Creates a new child element
    ///
    /// \param[in ] pDoc             Owner XML document
    /// \param[in ] pCurrentDOMNode  Parent XML node
    /// \param[in ] bstrElementName  XML element name
    /// \param[in ] bstrNamespace    XML element namespace
    /// \param[out] ppXmlElement     XML element created
    ///
    /// \returns
    /// - >0 if succeeded with warnings;
    /// - =0 (\c S_OK) if successful;
    /// - <0 if failed.
    /// Use `SUCCEEDED()` macro to test for first two cases (>=0) or `FAILED()` to test for failure.
    ///
    inline HRESULT put_element(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _Out_ winstd::com_obj<IXMLDOMElement> &ppXmlElement);

    ///
    /// Creates a new child element with text
    ///
    /// \param[in ] pDoc             Owner XML document
    /// \param[in ] pCurrentDOMNode  Parent XML node
    /// \param[in ] bstrElementName  XML element name
    /// \param[in ] bstrNamespace    XML element namespace
    /// \param[in ] bstrValue        XML element text
    /// \param[out] ppXmlElement     XML element created
    ///
    /// \returns
    /// - >0 if succeeded with warnings;
    /// - =0 (\c S_OK) if successful;
    /// - <0 if failed.
    /// Use `SUCCEEDED()` macro to test for first two cases (>=0) or `FAILED()` to test for failure.
    ///
    inline HRESULT put_element_value(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_z_ const BSTR bstrValue, _Out_opt_ winstd::com_obj<IXMLDOMElement> *ppXmlElement = NULL);

    ///
    /// Creates a new child element with text converted from number
    ///
    /// \param[in ] pDoc             Owner XML document
    /// \param[in ] pCurrentDOMNode  Parent XML node
    /// \param[in ] bstrElementName  XML element name
    /// \param[in ] bstrNamespace    XML element namespace
    /// \param[in ] dwValue          XML element number
    /// \param[out] ppXmlElement     XML element created
    ///
    /// \returns
    /// - >0 if succeeded with warnings;
    /// - =0 (\c S_OK) if successful;
    /// - <0 if failed.
    /// Use `SUCCEEDED()` macro to test for first two cases (>=0) or `FAILED()` to test for failure.
    ///
    inline HRESULT put_element_value(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_ DWORD dwValue, _Out_opt_ winstd::com_obj<IXMLDOMElement> *ppXmlElement = NULL);

    ///
    /// Creates a new child element with text converted from boolean
    ///
    /// \param[in ] pDoc             Owner XML document
    /// \param[in ] pCurrentDOMNode  Parent XML node
    /// \param[in ] bstrElementName  XML element name
    /// \param[in ] bstrNamespace    XML element namespace
    /// \param[in ] bValue           XML element boolean
    /// \param[out] ppXmlElement     XML element created
    ///
    /// \returns
    /// - >0 if succeeded with warnings;
    /// - =0 (\c S_OK) if successful;
    /// - <0 if failed.
    /// Use `SUCCEEDED()` macro to test for first two cases (>=0) or `FAILED()` to test for failure.
    ///
    inline HRESULT put_element_value(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_ bool bValue, _Out_opt_ winstd::com_obj<IXMLDOMElement> *ppXmlElement = NULL);

    ///
    /// Creates a new child element with Base64 encoded text from BLOB
    ///
    /// \param[in ] pDoc             Owner XML document
    /// \param[in ] pCurrentDOMNode  Parent XML node
    /// \param[in ] bstrElementName  XML element name
    /// \param[in ] bstrNamespace    XML element namespace
    /// \param[in ] pValue           Pointer to BLOB data
    /// \param[in ] nValueLen        Size of \p pValue in bytes
    /// \param[out] ppXmlElement     XML element created
    ///
    /// \returns
    /// - >0 if succeeded with warnings;
    /// - =0 (\c S_OK) if successful;
    /// - <0 if failed.
    /// Use `SUCCEEDED()` macro to test for first two cases (>=0) or `FAILED()` to test for failure.
    ///
    inline HRESULT put_element_base64(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_bytecount_(nValueLen) LPCVOID pValue, _In_ SIZE_T nValueLen, _Out_opt_ winstd::com_obj<IXMLDOMElement> *ppXmlElement = NULL);

    ///
    /// Creates a new child element with hexadecimal encoded text from BLOB
    ///
    /// \param[in ] pDoc             Owner XML document
    /// \param[in ] pCurrentDOMNode  Parent XML node
    /// \param[in ] bstrElementName  XML element name
    /// \param[in ] bstrNamespace    XML element namespace
    /// \param[in ] pValue           Pointer to BLOB data
    /// \param[in ] nValueLen        Size of \p pValue in bytes
    /// \param[out] ppXmlElement     XML element created
    ///
    /// \returns
    /// - >0 if succeeded with warnings;
    /// - =0 (\c S_OK) if successful;
    /// - <0 if failed.
    /// Use `SUCCEEDED()` macro to test for first two cases (>=0) or `FAILED()` to test for failure.
    ///
    inline HRESULT put_element_hex(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_bytecount_(nValueLen) LPCVOID pValue, _In_ SIZE_T nValueLen, _Out_opt_ winstd::com_obj<IXMLDOMElement> *ppXmlElement = NULL);

    ///
    /// Returns attribute text
    ///
    /// \param[in ] pXmlParent         Parent XML node
    /// \param[in ] bstrAttributeName  XML attribute selection name
    /// \param[out] pbstrValue         XML atribute value
    ///
    /// \returns
    /// - >0 if succeeded with warnings;
    /// - =0 (\c S_OK) if successful;
    /// - <0 if failed.
    /// Use `SUCCEEDED()` macro to test for first two cases (>=0) or `FAILED()` to test for failure.
    ///
    inline HRESULT get_attrib_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrAttributeName, _Out_ winstd::bstr &pbstrValue);

    ///
    /// Returns attribute text
    ///
    /// \param[in ] pXmlParent         Parent XML node
    /// \param[in ] bstrAttributeName  XML attribute selection name
    /// \param[out] sValue             XML atribute value
    ///
    /// \returns
    /// - >0 if succeeded with warnings;
    /// - =0 (\c S_OK) if successful;
    /// - <0 if failed.
    /// Use `SUCCEEDED()` macro to test for first two cases (>=0) or `FAILED()` to test for failure.
    ///
    template<class _Traits, class _Ax> inline HRESULT get_attrib_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrAttributeName, _Out_ std::basic_string<wchar_t, _Traits, _Ax> &sValue);

    ///
    /// Returns attribute text converted to number
    ///
    /// \param[in ] pXmlParent         Parent XML node
    /// \param[in ] bstrAttributeName  XML attribute selection name
    /// \param[out] pdwValue           XML atribute value
    ///
    /// \returns
    /// - >0 if succeeded with warnings;
    /// - =0 (\c S_OK) if successful;
    /// - <0 if failed.
    /// Use `SUCCEEDED()` macro to test for first two cases (>=0) or `FAILED()` to test for failure.
    ///
    inline HRESULT get_attrib_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrAttributeName, _Out_ DWORD &pdwValue);

    ///
    /// Returns attribute text converted to boolean
    ///
    /// \param[in ] pXmlParent         Parent XML node
    /// \param[in ] bstrAttributeName  XML attribute selection name
    /// \param[out] pbValue            XML atribute value
    ///
    /// \returns
    /// - >0 if succeeded with warnings;
    /// - =0 (\c S_OK) if successful;
    /// - <0 if failed.
    /// Use `SUCCEEDED()` macro to test for first two cases (>=0) or `FAILED()` to test for failure.
    ///
    inline HRESULT get_attrib_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrAttributeName, _Out_ bool &pbValue);

    ///
    /// Returns attribute BLOB converted from Base64 encoded text
    ///
    /// \param[in ] pXmlParent         Parent XML node
    /// \param[in ] bstrAttributeName  XML attribute selection name
    /// \param[out] aValue             XML atribute value
    ///
    /// \returns
    /// - >0 if succeeded with warnings;
    /// - =0 (\c S_OK) if successful;
    /// - <0 if failed.
    /// Use `SUCCEEDED()` macro to test for first two cases (>=0) or `FAILED()` to test for failure.
    ///
    template<class _Ty, class _Ax> inline HRESULT get_attrib_base64(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrAttributeName, _Out_ std::vector<_Ty, _Ax> &aValue);

    ///
    /// Returns attribute BLOB converted from hexadecimal encoded text
    ///
    /// \param[in ] pXmlParent         Parent XML node
    /// \param[in ] bstrAttributeName  XML attribute selection name
    /// \param[out] aValue             XML atribute value
    ///
    /// \returns
    /// - >0 if succeeded with warnings;
    /// - =0 (\c S_OK) if successful;
    /// - <0 if failed.
    /// Use `SUCCEEDED()` macro to test for first two cases (>=0) or `FAILED()` to test for failure.
    ///
    template<class _Ty, class _Ax> inline HRESULT get_attrib_hex(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrAttributeName, _Out_ std::vector<_Ty, _Ax> &aValue);

    ///
    /// Sets node attribute
    ///
    /// \param[in ] pCurrentDOMNode    Parent XML node
    /// \param[in ] bstrAttributeName  XML attribute name
    /// \param[out] bstrValue          XML atribute value
    ///
    /// \returns
    /// - >0 if succeeded with warnings;
    /// - =0 (\c S_OK) if successful;
    /// - <0 if failed.
    /// Use `SUCCEEDED()` macro to test for first two cases (>=0) or `FAILED()` to test for failure.
    ///
    inline HRESULT put_attrib_value(_In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrAttributeName, _In_z_ const BSTR bstrValue);

    ///
    /// Sets node attribute converted from number
    ///
    /// \param[in ] pCurrentDOMNode    Parent XML node
    /// \param[in ] bstrAttributeName  XML attribute name
    /// \param[out] dwValue            XML atribute value
    ///
    /// \returns
    /// - >0 if succeeded with warnings;
    /// - =0 (\c S_OK) if successful;
    /// - <0 if failed.
    /// Use `SUCCEEDED()` macro to test for first two cases (>=0) or `FAILED()` to test for failure.
    ///
    inline HRESULT put_attrib_value(_In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrAttributeName, _In_ DWORD dwValue);

    ///
    /// Sets node attribute converted from boolean
    ///
    /// \param[in ] pCurrentDOMNode    Parent XML node
    /// \param[in ] bstrAttributeName  XML attribute name
    /// \param[out] bValue             XML atribute value
    ///
    /// \returns
    /// - >0 if succeeded with warnings;
    /// - =0 (\c S_OK) if successful;
    /// - <0 if failed.
    /// Use `SUCCEEDED()` macro to test for first two cases (>=0) or `FAILED()` to test for failure.
    ///
    inline HRESULT put_attrib_value(_In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrAttributeName, _In_ bool bValue);

    ///
    /// Sets node attribute to Base64 encoded text from BLOB
    ///
    /// \param[in ] pCurrentDOMNode    Parent XML node
    /// \param[in ] bstrAttributeName  XML attribute name
    /// \param[in ] pValue             Pointer to BLOB data
    /// \param[in ] nValueLen          Size of \p pValue in bytes
    ///
    /// \returns
    /// - >0 if succeeded with warnings;
    /// - =0 (\c S_OK) if successful;
    /// - <0 if failed.
    /// Use `SUCCEEDED()` macro to test for first two cases (>=0) or `FAILED()` to test for failure.
    ///
    inline HRESULT put_attrib_base64(_In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrAttributeName, _In_bytecount_(nValueLen) LPCVOID pValue, _In_ SIZE_T nValueLen);
    ///
    /// Sets node attribute to hexadecimal encoded text from BLOB
    ///
    /// \param[in ] pCurrentDOMNode    Parent XML node
    /// \param[in ] bstrAttributeName  XML attribute name
    /// \param[in ] pValue             Pointer to BLOB data
    /// \param[in ] nValueLen          Size of \p pValue in bytes
    ///
    /// \returns
    /// - >0 if succeeded with warnings;
    /// - =0 (\c S_OK) if successful;
    /// - <0 if failed.
    /// Use `SUCCEEDED()` macro to test for first two cases (>=0) or `FAILED()` to test for failure.
    ///
    inline HRESULT put_attrib_hex(_In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrAttributeName, _In_bytecount_(nValueLen) LPCVOID pValue, _In_ SIZE_T nValueLen);

    ///
    /// Builds XPath for a given node
    ///
    /// \param[in] pXmlNode  XML node
    ///
    /// \returns String with XPath for a given node up to node terminal parent
    ///
    inline std::wstring get_xpath(_In_ IXMLDOMNode *pXmlNode);

    /// @}
}

#pragma once

#include <WinStd/Base64.h>
#include <WinStd/Hex.h>

#include <assert.h>


namespace eapxml
{
    inline HRESULT get_document(_In_ IXMLDOMNode *pXmlNode, _Out_ winstd::com_obj<IXMLDOMDocument2> &ppXmlDoc)
    {
        assert(pXmlNode);

        HRESULT hr;
        winstd::com_obj<IXMLDOMDocument> doc;

        return
            SUCCEEDED(hr = pXmlNode->get_ownerDocument(&doc)) &&
            SUCCEEDED(hr = doc.query_interface(ppXmlDoc)) ? S_OK : hr;
    }


    inline HRESULT select_node(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrNodeName, _Out_ winstd::com_obj<IXMLDOMNode> &ppXmlNode)
    {
        assert(pXmlParent);

        HRESULT hr;
        IXMLDOMNode *pXmlNode;

        if (SUCCEEDED(hr = pXmlParent->selectSingleNode(bstrNodeName, &pXmlNode))) {
            ppXmlNode.attach(pXmlNode);
            return pXmlNode ? S_OK : E_NOT_SET;
        } else
            return hr;
    }


    inline HRESULT select_nodes(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrNodeName, _Out_ winstd::com_obj<IXMLDOMNodeList> &ppXmlNodes)
    {
        assert(pXmlParent);

        HRESULT hr;
        IXMLDOMNodeList *pXmlNodes;

        if (SUCCEEDED(hr = pXmlParent->selectNodes(bstrNodeName, &pXmlNodes))) {
            ppXmlNodes.attach(pXmlNodes);
            return pXmlNodes ? S_OK : E_NOT_SET;
        } else
            return hr;
    }


    inline HRESULT select_element(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ winstd::com_obj<IXMLDOMElement> &ppXmlElement)
    {
        HRESULT hr;
        winstd::com_obj<IXMLDOMNode> pXmlNode;

        return
            SUCCEEDED(hr = select_node(pXmlParent, bstrElementName, pXmlNode)) ?
            SUCCEEDED(hr = pXmlNode.query_interface(ppXmlElement)) ?
            ppXmlElement ? S_OK : E_NOT_SET : hr : hr;
    }


    inline HRESULT create_element(_In_ IXMLDOMDocument *pDoc, _In_z_ const BSTR bstrElementName, _In_z_ const BSTR bstrNamespace, _Out_ winstd::com_obj<IXMLDOMElement> &ppXmlElement)
    {
        assert(pDoc);

        static const winstd::variant varNodeTypeEl(NODE_ELEMENT);
        HRESULT hr;
        winstd::com_obj<IXMLDOMNode> pXmlNode;

        return
            SUCCEEDED(hr = pDoc->createNode(varNodeTypeEl, bstrElementName, bstrNamespace, &pXmlNode)) ?
            SUCCEEDED(hr = pXmlNode.query_interface(ppXmlElement)) ?
            ppXmlElement ? S_OK : E_NOT_SET : hr : hr;
    }


    inline HRESULT create_element(_In_ IXMLDOMDocument *pDoc, IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementNameSelect, _In_z_ const BSTR bstrElementNameCreate, _In_z_ const BSTR bstrNamespace, _Out_ winstd::com_obj<IXMLDOMElement> &ppXmlElement)
    {
        assert(pDoc);
        assert(pXmlParent);

        HRESULT hr;

        return
            SUCCEEDED(hr = select_element(pXmlParent, bstrElementNameSelect, ppXmlElement)) ? S_OK :
            SUCCEEDED(hr = create_element(pDoc, bstrElementNameCreate, bstrNamespace, ppXmlElement)) ?
            SUCCEEDED(hr = pXmlParent->appendChild(ppXmlElement, NULL)) ? S_OK : hr : hr;
    }


    inline bool has_parent(_In_ IXMLDOMNode *pXmlNode)
    {
        assert(pXmlNode);

        winstd::com_obj<IXMLDOMNode> pXmlNodeParent;

        return SUCCEEDED(pXmlNode->get_parentNode(&pXmlNodeParent)) && pXmlNodeParent;
    }


    inline HRESULT get_element_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ winstd::bstr &pbstrValue, _Out_opt_ winstd::com_obj<IXMLDOMElement> *ppXmlElement)
    {
        HRESULT hr;
        winstd::com_obj<IXMLDOMElement> pXmlElement;
        BSTR bstrValue;

        if (SUCCEEDED(hr = select_element(pXmlParent, bstrElementName, pXmlElement)) &&
            SUCCEEDED(hr = pXmlElement->get_text(&bstrValue)))
        {
            pbstrValue.attach(bstrValue);
            if (ppXmlElement)
                *ppXmlElement = std::move(pXmlElement);
            return bstrValue ? S_OK : E_NOT_SET;
        } else
            return hr;
    }


    template<class _Traits, class _Ax>
    inline HRESULT get_element_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ std::basic_string<wchar_t, _Traits, _Ax> &sValue, _Out_opt_ winstd::com_obj<IXMLDOMElement> *ppXmlElement)
    {
        winstd::bstr bstr;
        HRESULT hr = get_element_value(pXmlParent, bstrElementName, bstr, ppXmlElement);
        if (SUCCEEDED(hr))
            sValue.assign(bstr, bstr.length());
        return hr;
    }


    inline HRESULT get_element_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ DWORD &pdwValue, _Out_opt_ winstd::com_obj<IXMLDOMElement> *ppXmlElement)
    {
        winstd::bstr bstr;
        HRESULT hr = get_element_value(pXmlParent, bstrElementName, bstr, ppXmlElement);
        if (SUCCEEDED(hr))
            pdwValue = wcstoul(bstr, NULL, 10);
        return hr;
    }


    inline HRESULT get_element_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ bool &pbValue, _Out_opt_ winstd::com_obj<IXMLDOMElement> *ppXmlElement)
    {
        winstd::bstr bstr;
        HRESULT hr = get_element_value(pXmlParent, bstrElementName, bstr, ppXmlElement);
        if (SUCCEEDED(hr)) {
            if (CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstr, bstr.length(), L"true" , -1, NULL, NULL, 0) == CSTR_EQUAL ||
                CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstr, bstr.length(), L"1"    , -1, NULL, NULL, 0) == CSTR_EQUAL)
                pbValue = true;
            else if (
                CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstr, bstr.length(), L"false", -1, NULL, NULL, 0) == CSTR_EQUAL ||
                CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstr, bstr.length(), L"0"    , -1, NULL, NULL, 0) == CSTR_EQUAL)
                pbValue = false;
            else
                hr = E_NOT_VALID_STATE;
        }

        return hr;
    }


    template<class _Ty, class _Ax>
    inline HRESULT get_element_base64(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ std::vector<_Ty, _Ax> &aValue, _Out_opt_ winstd::com_obj<IXMLDOMElement> *ppXmlElement)
    {
        winstd::bstr bstr;
        HRESULT hr = get_element_value(pXmlParent, bstrElementName, bstr, ppXmlElement);
        if (SUCCEEDED(hr)) {
            winstd::base64_dec dec;
            bool is_last;
            dec.decode(aValue, is_last, (BSTR)bstr, bstr.length());
        }

        return hr;
    }


    template<class _Ty, class _Ax>
    inline HRESULT get_element_hex(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ std::vector<_Ty, _Ax> &aValue, _Out_opt_ winstd::com_obj<IXMLDOMElement> *ppXmlElement)
    {
        winstd::bstr bstr;
        HRESULT hr = get_element_value(pXmlParent, bstrElementName, bstr, ppXmlElement);
        if (SUCCEEDED(hr)) {
            winstd::hex_dec dec;
            bool is_last;
            dec.decode(aValue, is_last, (BSTR)bstr, bstr.length());
        }

        return hr;
    }


    inline HRESULT get_element_localized(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _In_z_ LPCWSTR pszLang, _Out_ winstd::bstr &pbstrValue, _Out_opt_ winstd::com_obj<IXMLDOMElement> *ppXmlElement)
    {
        HRESULT hr;
        winstd::com_obj<IXMLDOMElement> pXmlElement;

        if (FAILED(hr = select_element(pXmlParent, bstrElementName, pXmlElement)))
            return hr;

        if (ppXmlElement)
            *ppXmlElement = pXmlElement;

        winstd::com_obj<IXMLDOMNodeList> pXmlListLocalizedText;
        long lCount = 0;
        if (FAILED(select_nodes(pXmlElement, winstd::bstr(L"eap-metadata:localized-text"), pXmlListLocalizedText)) ||
            FAILED(pXmlListLocalizedText->get_length(&lCount)) ||
            lCount <= 0)
        {
            BSTR bstr;
            if (SUCCEEDED(hr = pXmlElement->get_text(&bstr))) {
                pbstrValue.attach(bstr);
                return bstr ? S_OK : E_NOT_SET;
            } else
                return hr;
        }

        winstd::bstr bstrDefault, bstrEn;
        for (long i = 0; ; i++) {
            if (i >= lCount) {
                if (bstrDefault != NULL) {
                    // Return "C" localization.
                    pbstrValue = std::move(bstrDefault);
                    return S_OK;
                } else if (bstrEn != NULL) {
                    // Return "en" localization.
                    pbstrValue = std::move(bstrEn);
                    return S_OK;
                } else
                    return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
            }

            winstd::com_obj<IXMLDOMNode> pXmlElLocalizedText;
            pXmlListLocalizedText->get_item(i, &pXmlElLocalizedText);

            {
                // Read <lang>.
                winstd::bstr bstrLang;
                if (FAILED(get_element_value(pXmlElLocalizedText, winstd::bstr(L"eap-metadata:lang"), bstrLang)) ||
                    CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstrLang, bstrLang.length(), L"C" , -1, NULL, NULL, 0) == CSTR_EQUAL)
                {
                    // <lang> is missing or "C" language found.
                    winstd::bstr bstr;
                    if (SUCCEEDED(hr = get_element_value(pXmlElLocalizedText, winstd::bstr(L"eap-metadata:text"), bstr)))
                        bstrDefault = std::move(bstr);
                } else if (CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstrLang, bstrLang.length(), pszLang, -1, NULL, NULL, 0) == CSTR_EQUAL) {
                    // Found an exact match.
                    return get_element_value(pXmlElLocalizedText, winstd::bstr(L"eap-metadata:text"), pbstrValue);
                } else if (CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstrLang, bstrLang.length(), L"en", -1, NULL, NULL, 0) == CSTR_EQUAL) {
                    // "en" language found.
                    winstd::bstr bstr;
                    if (SUCCEEDED(hr = get_element_value(pXmlElLocalizedText, winstd::bstr(L"eap-metadata:text"), bstr)))
                        bstrEn = std::move(bstr);
                }
            }
        }
    }


    template<class _Traits, class _Ax>
    inline HRESULT get_element_localized(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _In_z_ LPCWSTR pszLang, _Out_ std::basic_string<wchar_t, _Traits, _Ax> &sValue, _Out_opt_ winstd::com_obj<IXMLDOMElement> *ppXmlElement)
    {
        winstd::bstr bstr;
        HRESULT hr = get_element_localized(pXmlParent, bstrElementName, pszLang, bstr, ppXmlElement);
        if (SUCCEEDED(hr))
            sValue.assign(bstr, bstr.length());
        return hr;
    }


    inline HRESULT put_element(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _Out_ winstd::com_obj<IXMLDOMElement> &ppXmlElement)
    {
        assert(pDoc);
        assert(pCurrentDOMNode);

        static const VARIANT varNodeTypeEl = { VT_I4, 0, 0, 0, { NODE_ELEMENT } };
        HRESULT hr;
        winstd::com_obj<IXMLDOMNode> pXmlEl;

        return 
            SUCCEEDED(hr = pDoc->createNode(varNodeTypeEl, bstrElementName, bstrNamespace, &pXmlEl)) &&
            SUCCEEDED(hr = pCurrentDOMNode->appendChild(pXmlEl, NULL)) &&
            SUCCEEDED(hr = pXmlEl.query_interface(ppXmlElement)) ? S_OK : hr;
    }


    inline HRESULT put_element_value(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_z_ const BSTR bstrValue, _Out_opt_ winstd::com_obj<IXMLDOMElement> *ppXmlElement)
    {
        assert(pDoc);

        static const VARIANT varNodeTypeEl = { VT_I4, 0, 0, 0, { NODE_ELEMENT } };
        HRESULT hr;
        winstd::com_obj<IXMLDOMNode> pXmlEl;
        winstd::com_obj<IXMLDOMText> pXmlElText;

        if (SUCCEEDED(hr = pDoc->createNode(varNodeTypeEl, bstrElementName, bstrNamespace, &pXmlEl)) &&
            SUCCEEDED(hr = pDoc->createTextNode(bstrValue, &pXmlElText)) &&
            SUCCEEDED(hr = pXmlEl->appendChild(pXmlElText, NULL)) &&
            SUCCEEDED(hr = pCurrentDOMNode->appendChild(pXmlEl, NULL)))
        {
            if (ppXmlElement)
                pXmlEl.query_interface(*ppXmlElement);
            return S_OK;
        } else
            return hr;
    }


    inline HRESULT put_element_value(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_ DWORD dwValue, _Out_opt_ winstd::com_obj<IXMLDOMElement> *ppXmlElement)
    {
        return put_element_value(pDoc, pCurrentDOMNode, bstrElementName, bstrNamespace, winstd::bstr(winstd::wstring_printf(L"%d", dwValue)), ppXmlElement);
    }


    inline HRESULT put_element_value(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_ bool bValue, _Out_opt_ winstd::com_obj<IXMLDOMElement> *ppXmlElement)
    {
        return put_element_value(pDoc, pCurrentDOMNode, bstrElementName, bstrNamespace, winstd::bstr(bValue ? L"true": L"false"), ppXmlElement);
    }


    inline HRESULT put_element_base64(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_bytecount_(nValueLen) LPCVOID pValue, _In_ SIZE_T nValueLen, _Out_opt_ winstd::com_obj<IXMLDOMElement> *ppXmlElement)
    {
        std::wstring sBase64;
        winstd::base64_enc enc;
        enc.encode(sBase64, pValue, nValueLen);
        return put_element_value(pDoc, pCurrentDOMNode, bstrElementName, bstrNamespace, winstd::bstr(sBase64), ppXmlElement);
    }


    inline HRESULT put_element_hex(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_bytecount_(nValueLen) LPCVOID pValue, _In_ SIZE_T nValueLen, _Out_opt_ winstd::com_obj<IXMLDOMElement> *ppXmlElement)
    {
        std::wstring sHex;
        winstd::hex_enc enc;
        enc.encode(sHex, pValue, nValueLen);
        return put_element_value(pDoc, pCurrentDOMNode, bstrElementName, bstrNamespace, winstd::bstr(sHex), ppXmlElement);
    }


    inline HRESULT get_attrib_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrAttributeName, _Out_ winstd::bstr &pbstrValue)
    {
        HRESULT hr;
        winstd::com_obj<IXMLDOMNamedNodeMap> pXmlAttributes;
        winstd::com_obj<IXMLDOMNode> pXmlAt;
        VARIANT varValue;
        V_VT(&varValue) = VT_EMPTY;

        return
            SUCCEEDED(hr = pXmlParent->get_attributes(&pXmlAttributes)) &&
            SUCCEEDED(hr = pXmlAttributes->getNamedItem(bstrAttributeName, &pXmlAt)) ?
            pXmlAt ?
            SUCCEEDED(hr = pXmlAt->get_nodeValue(&varValue)) ?
            V_VT(&varValue) == VT_BSTR ? pbstrValue.attach(V_BSTR(&varValue)), V_VT(&varValue) = VT_EMPTY, S_OK : E_UNEXPECTED : hr : E_NOT_SET : hr;
    }


    template<class _Traits, class _Ax>
    inline HRESULT get_attrib_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrAttributeName, _Out_ std::basic_string<wchar_t, _Traits, _Ax> &sValue)
    {
        winstd::bstr bstr;
        HRESULT hr = get_attrib_value(pXmlParent, bstrAttributeName, bstr);
        if (SUCCEEDED(hr))
            sValue.assign(bstr, bstr.length());
        return hr;
    }


    inline HRESULT get_attrib_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrAttributeName, _Out_ DWORD &pdwValue)
    {
        winstd::bstr bstr;
        HRESULT hr = get_attrib_value(pXmlParent, bstrAttributeName, bstr);
        if (SUCCEEDED(hr))
            pdwValue = wcstoul(bstr, NULL, 10);
        return hr;
    }


    inline HRESULT get_attrib_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrAttributeName, _Out_ bool &pbValue)
    {
        winstd::bstr bstr;
        HRESULT hr = get_attrib_value(pXmlParent, bstrAttributeName, bstr);
        if (SUCCEEDED(hr)) {
            if (CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstr, bstr.length(), L"true" , -1, NULL, NULL, 0) == CSTR_EQUAL ||
                CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstr, bstr.length(), L"1"    , -1, NULL, NULL, 0) == CSTR_EQUAL)
                pbValue = true;
            else if (
                CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstr, bstr.length(), L"false", -1, NULL, NULL, 0) == CSTR_EQUAL ||
                CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstr, bstr.length(), L"0"    , -1, NULL, NULL, 0) == CSTR_EQUAL)
                pbValue = false;
            else
                hr = E_NOT_VALID_STATE;
        }

        return hr;
    }


    template<class _Ty, class _Ax>
    inline HRESULT get_attrib_base64(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrAttributeName, _Out_ std::vector<_Ty, _Ax> &aValue)
    {
        winstd::bstr bstr;
        HRESULT hr = get_attrib_value(pXmlParent, bstrAttributeName, &bstr);
        if (SUCCEEDED(hr)) {
            winstd::base64_dec dec;
            bool is_last;
            dec.decode(aValue, is_last, (BSTR)bstr, bstr.length());
        }

        return hr;
    }


    template<class _Ty, class _Ax>
    inline HRESULT get_attrib_hex(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrAttributeName, _Out_ std::vector<_Ty, _Ax> &aValue)
    {
        winstd::bstr bstr;
        HRESULT hr = get_attrib_value(pXmlParent, bstrAttributeName, &bstr);
        if (SUCCEEDED(hr)) {
            winstd::hex_dec dec;
            bool is_last;
            dec.decode(aValue, is_last, (BSTR)bstr, bstr.length());
        }

        return hr;
    }


    inline HRESULT put_attrib_value(_In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrAttributeName, _In_z_ const BSTR bstrValue)
    {
        HRESULT hr;
        winstd::com_obj<IXMLDOMElement> pXmlEl;
        VARIANT varValue;
        V_VT(&varValue) = VT_BSTR;
        V_BSTR(&varValue) = bstrValue;

        return
            SUCCEEDED(hr = pCurrentDOMNode->QueryInterface(__uuidof(IXMLDOMElement), (void**)&pXmlEl)) &&
            SUCCEEDED(hr = pXmlEl->setAttribute(bstrAttributeName, varValue)) ? S_OK : hr;
    }


    inline HRESULT put_attrib_value(_In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrAttributeName, _In_ DWORD dwValue)
    {
        return put_attrib_value(pCurrentDOMNode, bstrAttributeName, winstd::bstr(winstd::wstring_printf(L"%d", dwValue)));
    }


    inline HRESULT put_attrib_value(_In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrAttributeName, _In_ bool bValue)
    {
        return put_attrib_value(pCurrentDOMNode, bstrAttributeName, winstd::bstr(bValue ? L"true": L"false"));
    }


    inline HRESULT put_attrib_base64(_In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrAttributeName, _In_bytecount_(nValueLen) LPCVOID pValue, _In_ SIZE_T nValueLen)
    {
        std::wstring sBase64;
        winstd::base64_enc enc;
        enc.encode(sBase64, pValue, nValueLen);
        return put_attrib_value(pCurrentDOMNode, bstrAttributeName, winstd::bstr(sBase64));
    }


    inline HRESULT put_attrib_hex(_In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrAttributeName, _In_bytecount_(nValueLen) LPCVOID pValue, _In_ SIZE_T nValueLen)
    {
        std::wstring sHex;
        winstd::hex_enc enc;
        enc.encode(sHex, pValue, nValueLen);
        return put_attrib_value(pCurrentDOMNode, bstrAttributeName, winstd::bstr(sHex));
    }


    inline std::wstring get_xpath(_In_ IXMLDOMNode *pXmlNode)
    {
        if (pXmlNode) {
            winstd::bstr bstr;
            winstd::com_obj<IXMLDOMNode> pXmlNodeParent;

            return
                SUCCEEDED(pXmlNode->get_nodeName(&bstr)) ?
                SUCCEEDED(pXmlNode->get_parentNode(&pXmlNodeParent)) ? get_xpath(pXmlNodeParent) + L"/" + (LPCWSTR)bstr : (LPCWSTR)bstr : L"?";
        } else
            return L"";
    }
}
