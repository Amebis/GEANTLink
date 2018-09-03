# GÉANTLink

Suite of EAP supplicants for Microsoft Windows - IEEE 802.1X clients for enterprise network authentication

## Features
- Integrates into Windows seamlessly
- Wired and wireless network support

### Authentication methods
- EAP-TTLS with the following inner methods:
    - PAP
    - MSCHAPv2

### Security
- Microsoft Windows Credential Manager stored user credentials
- User credentials can be shared between different network profiles, regardless of their connection: wired or wireless
- Encrypted EapHost inter-process communication
- TLS:
   - Separate trusted root CA list
   - Configurable list of accepted server names

### Diagnostics
- Reporting to Event Log channels: Operational and Analytic verbosity
- Real-time event monitoring utility

### User interface
- Customizable helpdesk contact information
- Lockable network profile configuration

### Deployment
- Released as multi-lingual 32 and 64-bit MSI packages; Group Policy deployment supported
- [MsiUseFeature utility](https://github.com/Amebis/GEANTLink/tree/ver1.0/MsiUseFeature) for GÉANTLink install state testing (for embedding GÉANTLink into other setup packages)
- [CredWrite utility](https://github.com/Amebis/GEANTLink/tree/ver1.0/CredWrite) for automated user credential import to Credential Manager
- [WLANManager utility](https://github.com/Amebis/GEANTLink/tree/ver1.0/WLANManager) to allow network profile configuration dialog shortcuts

### Supported operating systems
- Windows Vista, Windows Server 2008
- Windows 7, Windows Server 2008 R2

## Download
Binaries are available for download [here](https://github.com/Amebis/GEANTLink/releases).

## Building

### Building Environment Requirements
- Microsoft Windows Vista or later
- Microsoft Visual Studio 2010 SP1
- _msgfmt.exe_ from [gettext](https://www.gnu.org/software/gettext/);
  Hint: [Poedit](https://poedit.net/) contains up-to-date binary Win32 compiled gettext-utilities. Install it and add `GettextTools\bin` folder to the system path.
- _sed.exe_ and _grep.exe_
- _MsiDb.Exe_ and other command line utilities for MSI packaging distributed as a part of Microsoft Windows SDK (installed with Visual Studio). Add SDK's `Bin` folder to the system path.

### wxWidgets
GÉANTLink is using wxWidgets v3.1.1 static libraries. Unfortunately, only dynamic libraries (DLL) variant is available as a binary download. Therefore static libraries needs to be compiled from [source](https://github.com/wxWidgets/wxWidgets).

#### Compiling wxWidgets Win32 static libraries
1. Start _Visual Studio Command Prompt (2010)_
2. Change working folder to `build\msw`
3. Run: `nmake /f makefile.vc /ls RUNTIME_LIBS=static SHARED=0 COMPILER_VERSION=100`
4. Run: `nmake /f makefile.vc /ls RUNTIME_LIBS=static SHARED=0 COMPILER_VERSION=100 BUILD=release`

#### Compiling wxWidgets x64 static libraries
1. Start _Visual Studio x64 Cross Tools Command Prompt (2010)_
2. Change working folder to `build\msw`
3. Run: `nmake /f makefile.vc /ls RUNTIME_LIBS=static SHARED=0 COMPILER_VERSION=100 TARGET_CPU=X64`
4. Run: `nmake /f makefile.vc /ls RUNTIME_LIBS=static SHARED=0 COMPILER_VERSION=100 TARGET_CPU=X64 BUILD=release`

#### Specifying wxWidgets path
GÉANTLink compilation references wxWidgets libraries using `WXWIN` environment variable. Please set it to wxWidgets folder (i.e. `C:\SDK\wxWidgets\3.1.1`).

### Digital Signing of Build Outputs
In order to have the build process digitally sign output files, one should provide the following:

1. A signing certificate installed in the current user’s certificate store.
2. The following variables in the environment:
  - `ManifestCertificateThumbprint` - set the value to certificate’s SHA1 thumbprint (hexadecimal, without spaces, i.e. `bc0d8da45f9eeefcbe4e334e1fc262804df88d7e`).
  - `ManifestTimestampRFC3161Url` - set the value to URL used to perform RFC3161 timestamp signature (i.e. `http://sha256timestamp.ws.symantec.com/sha256/timestamp`). In order to perform timestamp signing successfully, the computer running the build should be online and able to access this URL.

Please note that only Release builds are configured for timestamp signing. Debug configurations do not attempt to timestamp sign the resulting DLL and EXE files in order to speed up the building process and enable offline building.

### Building

#### Building in Visual Studio IDE
GÉANTLink has some submodules. When cloning Git repository, make sure to use `--recursive` Git switch to clone submodules too. Example:
`git clone --recursive "https://github.com/Amebis/GEANTLink.git" "C:\Projects\GEANTLink"`

After clone is complete, grant _Users_ local group read and execute permissions to `output` subfolder (when working folder is private). This allows _EapHost_ service to load GÉANTLink's DLL, and Event Viewer to display GÉANTLink events.

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
Use of standard command prompt is recommended, providing that Microsoft Visual Studio 2010 folders containing _nmake.exe_ and _devenv.com_ are added to the system path.

Use Microsoft NMAKE to build the project.

Command            | Explanation
-------------------|------------------------------------------
`nmake Clean`      | Deletes all intermediate and output files.
`nmake Register`   | Builds a debug version of project, registers DLLs, and adds Start Menu shortcuts. For testing and development purposes only! Requires elevated command prompt.
`nmake Unregister` | Removes Start Menu shortcuts, unregisters DLLs. For testing development purposes only! Requires elevated command prompt.
`nmake Setup`      | Builds a release version of project and release MSI setup files. The resulting files can be found in `output\Setup` folder.
`nmake SetupDebug` | Builds a debug version of project and debug MSI setup files. The resulting files can be found in `output\Setup` folder.

The `/ls` flag can be appended to the commands above to reduce NMAKE’s verbosity. You can combine multiple targets (i.e. nmake Unregister Clean). Please, see NMAKE reference for further reading.

### Translating into your language
GÉANTLink is fully localizable. We kindly invite you to help [translating it on Transifex](https://www.transifex.com/eduroam_devel/geantlink/).
