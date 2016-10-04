# GÉANTLink

Suite of EAP supplicants for Windows - IEEE 802.1X plug-ins for enterprise network authentication

## Building

### Building Environment Requirements
- Microsoft Windows Vista or later
- Microsoft Visual Studio 2010 SP1
- _msgfmt.exe_ from [gettext](https://www.gnu.org/software/gettext/);
  Hint: [Poedit](https://poedit.net/) contains up-to-date binary Win32 compiled gettext-utilities. Install it and add _GettextTools\bin_ folder to path.
- _sed.exe_ and _grep.exe_
- _MsiDb.Exe_ and other command line utilities for MSI packaging distributed as a part of Microsoft Windows SDK (installed with Visual Studio). Add SDK's _Bin_ folder to path.

### wxWidgets
GÉANTLink is using wxWidgets v3.0.2 static libraries. Unfortunately, only dynamic libraries (DLL) variant is available as a binary download. Therefore static libraries needs to be compiled from [source](https://github.com/wxWidgets/wxWidgets).

#### Compiling wxWidgets Win32 static libraries
1. Start _Visual Studio Command Prompt (2010)_
2. Change working directory to _build\msw_
3. Run: `nmake /f makefile.vc /ls RUNTIME_LIBS=static SHARED=0`
4. Run: `nmake /f makefile.vc /ls RUNTIME_LIBS=static SHARED=0 BUILD=release`

#### Compiling wxWidgets x64 static libraries
1. Start _Visual Studio x64 Cross Tools Command Prompt (2010)_
2. Change working directory to _build\msw_
3. Run: `nmake /f makefile.vc /ls RUNTIME_LIBS=static SHARED=0 TARGET_CPU=X64`
4. Run: `nmake /f makefile.vc /ls RUNTIME_LIBS=static SHARED=0 TARGET_CPU=X64 BUILD=release`

#### Specifying wxWidgets path
GÉANTLink compilation references wxWidgets libraries using `WXWIN` environment variable. Please set it to wxWidgets folder (i.e. `C:\SDK\wxWidgets\3.0.2`).

### Digital Signing of Build Outputs
In order to have the build process digitally sign output files, one should provide the following:

1. A signing certificate installed in the current user’s certificate store.
2. The following variables in the environment:
  - `ManifestCertificateThumbprint` - set the value to certificate’s SHA1 thumbprint (hexadecimal, without spaces, i.e. `bc0d8da45f9eeefcbe4e334e1fc262804df88d7e`).
  - `ManifestTimestampUrl` - set the value to URL used to perform timestamp signature (i.e. `http://timestamp.verisign.com/scripts/timstamp.dll`). In order to perform timestamp signing successfully, the computer running the build should be online and able to access this URL.

Please note that only Release builds are configured for timestamp signing. Debug configurations do not attempt to timestamp sign the resulting DLL and EXE files in order to speed up the building process and enable offline building.

### Building

#### Building in Visual Studio IDE
GÉANTLink can be build and debugged opening _VS10Solution.sln_ in Visual C++ 2010 IDE.

Before one can attempt to debug EAP DLLs, you should run `nmake register` from an elevated command prompt. See _Building in command line_ chapter below.

Next, one must configure a network profile actually using GÉANTLink for the authentication.

GÉANTLink EAP modules are divided into two DLLs: backend (i.e. _EAPTTLS.dll_) and GUI (i.e. _EAPTTLSUI.dll_).

##### Backend DLL
The backend DLL is loaded by _Eap3Host.exe_ process when connecting to the network. One approach to debug the module is to start Visual C++ elevated, open _VS10Solution.sln_, and attach to the running _Eap3Host.exe_ process.

On initial connection attempt _Eap3Host.exe_ will load the DLL and will not release it until _EapHost_ service is restarted. To release our DLL (i.e. for rebuild) you have to restart _EapHost_ service manually or run `nmake register` again.

To debug early life of our backend DLL, uncomment `Sleep(10000)` in `DllMain()` of the module, and set breakpoints. This should give you plenty of time to catch emerging _Eap3Host.exe_ process and attach the debugger to it before our DLL starts servicing authentication.

##### GUI DLL
The GUI DLL is loaded by _DllHost.exe_ process on XML profile configuration import/export and when interactive user interface is required.

A few seconds after desired function call has finished, _DllHost.exe_ terminates and releases the DLL.

To debug early life of our GUI DLL, uncomment `Sleep(10000)` in `DllMain()` of the module, and set breakpoints. This should give you plenty of time to attach the debugger to _DllHost.exe_ process before our DLL starts.

#### Building in command line
Use of standard command prompt is recommended, providing that Microsoft Visual Studio 2010 folders containing _nmake.exe_ and _devenv.com_ are added to the path.

Use Microsoft NMAKE to build the project.

Command            | Explanation
-------------------|------------------------------------------
`nmake Clean`      | Deletes all intermediate and output files.
`nmake Register`   | Builds a debug version of project, registers DLLs, and adds Start Menu shortcuts. For testing and development purposes only! Requires elevated command prompt.
`nmake Unregister` | Removes Start Menu shortcuts, unregisters DLLs. For testing development purposes only! Requires elevated command prompt.
`nmake Setup`      | Builds a release version of project and release MSI setup files. The resulting files can be found in _output\Setup_ folder.
`nmake SetupDebug` | Builds a debug version of project and debug MSI setup files. The resulting files can be found in _output\Setup_ folder.

The `/ls` flag can be appended to the commands above to reduce NMAKE’s verbosity. You can combine multiple targets (i.e. nmake Unregister Clean). Please, see NMAKE reference for further reading.
