# GÉANTLink

Suite of EAP supplicants for Microsoft Windows - IEEE 802.1X clients for enterprise network authentication

## Features

- Integrates into Windows seamlessly
- Wired and wireless network support

### Authentication methods

- EAP-TTLS with the following inner methods:
    - PAP
    - MSCHAPv2
    - EAP-MSCHAPv2
    - EAP-GTC: Challenge/Response and Password authentication modes
    - System-installed EAP method chaining (experimental)

### Security

- Microsoft Windows Credential Manager stored user credentials
- User credentials can be shared between different network profiles, regardless of their connection: wired or wireless
- Encrypted EapHost inter-process communication
- TLS:
   - Separate trusted root CA list
   - Configurable list of accepted server names
   - Post-authentication CRL check

### Diagnostics

- Reporting to Event Log channels: Operational and Analytic verbosity
- Real-time event monitoring utility

### User interface

- Customizable helpdesk contact information
- Lockable network profile configuration

### Deployment

- Released as multi-lingual x86, x64, and ARM64 MSI packages; Group Policy deployment supported
- [MsiUseFeature utility](https://github.com/Amebis/GEANTLink/tree/master/MsiUseFeature) for the product install state testing (for embedding this product into other setup packages)
- [CredWrite utility](https://github.com/Amebis/GEANTLink/tree/master/CredWrite) for automated user credential import to Credential Manager
- [WLANManager utility](https://github.com/Amebis/GEANTLink/tree/master/WLANManager) to allow network profile configuration dialog shortcuts

### Supported operating systems

- Windows Vista, Windows Server 2008
- Windows 7, Windows Server 2008 R2
- Windows 8 Desktop, Windows Server 2012
- Windows 8.1 Desktop, Windows Server 2012 R2
- Windows 10 Desktop, Windows Server 2016

## Download

Binaries are available for download [here](https://github.com/Amebis/GEANTLink/releases).

## Building

### Building Environment Requirements

- Microsoft Windows Vista or later
- Microsoft Visual Studio 2019
- _msgfmt.exe_ from [gettext](https://www.gnu.org/software/gettext/);
  Hint: [Poedit](https://poedit.net/) contains up-to-date binary Win32 compiled gettext-utilities. Install it and add `GettextTools\bin` folder to the system path.
- _sed.exe_ and _grep.exe_
  Hint: [Git for Windows](https://gitforwindows.org/) contains up-to-date set of GNU utilities.
- _MsiDb.Exe_ and other command line utilities for MSI packaging distributed as a part of Microsoft Windows SDK (installed with Visual Studio). Add SDK's `Bin` folder to the system path.

### wxWidgets

This product is using wxWidgets static libraries. Since upstream wxWidgets libraries don't support ARM64 yet, a clone with ARM64 support was prepared at [GitHub](https://github.com/Amebis/wxWidgets.git).

#### Compiling wxWidgets x86 static libraries

1. Start command prompt
2. Change working folder to `build\msw`
3. Run: `"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsamd64_x86.bat"`
4. Run: `nmake /f makefile.vc /ls RUNTIME_LIBS=static SHARED=0 COMPILER_VERSION=142`
5. Run: `nmake /f makefile.vc /ls RUNTIME_LIBS=static SHARED=0 COMPILER_VERSION=142 BUILD=release`

#### Compiling wxWidgets x64 static libraries

1. Start command prompt
2. Change working folder to `build\msw`
3. Run: `"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"`
4. Run: `nmake /f makefile.vc /ls RUNTIME_LIBS=static SHARED=0 COMPILER_VERSION=142 TARGET_CPU=X64`
5. Run: `nmake /f makefile.vc /ls RUNTIME_LIBS=static SHARED=0 COMPILER_VERSION=142 TARGET_CPU=X64 BUILD=release`

#### Compiling wxWidgets ARM64 static libraries

1. Start command prompt
2. Change working folder to `build\msw`
3. Run: `"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsamd64_arm64.bat"`
4. Run: `nmake /f makefile.vc /ls RUNTIME_LIBS=static SHARED=0 COMPILER_VERSION=142 TARGET_CPU=ARM64 USE_OPENGL=0`
5. Run: `nmake /f makefile.vc /ls RUNTIME_LIBS=static SHARED=0 COMPILER_VERSION=142 TARGET_CPU=ARM64 USE_OPENGL=0 BUILD=release`

#### Specifying wxWidgets path

The product compilation references wxWidgets libraries using `WXWIN` environment variable. Please set it to wxWidgets folder (i.e. `C:\SDK\wxWidgets`).

### Digital Signing of Build Outputs

In order to have the build process digitally sign the Release output files, one should setup either:

- Local signing:
   1. A signing certificate/hardware key
   2. The following variables in the environment:
      - `ManifestCertificateThumbprint` - set the value to certificate’s SHA1 thumbprint (hexadecimal, without spaces, e.g. `bc0d8da45f9eeefcbe4e334e1fc262804df88d7e`).
      - `ManifestTimestampRFC3161Url` - set the value to URL used to perform timestamp signature (e.g. `http://sha256timestamp.ws.symantec.com/sha256/timestamp`, `http://timestamp.digicert.com` etc.). In order to perform the timestamp signing successfully, the computer running the build should be online and able to access this URL.

- Microsoft Trusted Signing:
   1. Install [Trusted Signing dlib package](https://www.nuget.org/packages/Microsoft.Trusted.Signing.Client):
      ```cmd
      nuget install Microsoft.Trusted.Signing.Client -Version 1.0.53 -x`
      ```
   2. Provide a [`manifest.json`](https://learn.microsoft.com/en-us/azure/trusted-signing/how-to-signing-integrations#create-a-json-file) file and place it at `%APPDATA%\Microsoft.Trusted.Signing.Client.json`:
      ```cmd
      notepad "%APPDATA%\Microsoft.Trusted.Signing.Client.json"
      ```

Debug configurations are not digitally signed by design.

### Building

#### Building in Visual Studio IDE

This product has some submodules. When cloning Git repository, make sure to use `--recursive` Git switch to clone submodules too. Example:
`git clone --recursive "https://github.com/Amebis/GEANTLink.git" "C:\Projects\GEANTLink"`

After clone is complete, grant _Users_ local group read and execute permissions to `output` subfolder (when working folder is private). This allows _EapHost_ service to load DLL, and Event Viewer to display events.

The product can be build and debugged opening _GEANTLink.sln_ in Visual C++ IDE.

Before one can attempt to debug EAP DLLs, you should run `nmake register` from an elevated command prompt. See _Building in command line_ chapter below.

Next, one must configure a network profile to actually use one of this product's EAP modules for the authentication.

EAP modules are divided into two DLLs: backend (i.e. _EAP-TTLS.dll_) and GUI (i.e. _EAP-TTLS_UI.dll_).

##### Backend DLL

The backend DLL is loaded by _Eap3Host.exe_ process when connecting to the network. One approach to debug the module is to start Visual C++ elevated, open _GEANTLink.sln_, and attach to the running _Eap3Host.exe_ process.

On initial connection attempt _Eap3Host.exe_ will load the DLL and will not release it until _EapHost_ service is restarted. To release our DLL (i.e. for rebuild) you have to restart _EapHost_ service manually or run `nmake register` again.

To debug early life of our backend DLL, uncomment `Sleep(10000)` in `DllMain()` of the module, and set breakpoints. This should give you plenty of time to catch emerging _Eap3Host.exe_ process and attach the debugger to it before our DLL starts servicing authentication.

##### GUI DLL

The GUI DLL is loaded by _DllHost.exe_ process on XML profile configuration import/export and when interactive user interface is required.

A few seconds after desired function call has finished, _DllHost.exe_ terminates and releases the DLL.

To debug early life of our GUI DLL, uncomment `Sleep(10000)` in `DllMain()` of the module, and set breakpoints. This should give you plenty of time to attach the debugger to _DllHost.exe_ process before our DLL starts.

#### Building in command line

Open _Developer Command Prompt for VS 2019_ for building.

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

This product is fully localizable. We kindly invite you to help [translating it on Transifex](https://www.transifex.com/eduroam_devel/geantlink/).
