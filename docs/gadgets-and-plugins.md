# Gadgets and Plugins

The catalog of what YSoNet can generate. The lists below are a snapshot; the live, authoritative list comes from `ysonet.exe --fullhelp`.

Back to [documentation index](README.md).

## Gadgets

Each gadget lists the formatters it supports. A number in parentheses means several variants exist.

```text
ActivitySurrogateDisableTypeCheck (BinaryFormatter, LosFormatter, NetDataContractSerializer, SoapFormatter)
ActivitySurrogateSelector (BinaryFormatter (2), LosFormatter, SoapFormatter)
ActivitySurrogateSelectorFromFile (BinaryFormatter (2), LosFormatter, SoapFormatter)
AxHostState (BinaryFormatter, LosFormatter, NetDataContractSerializer, SoapFormatter)
BaseActivationFactory (Json.NET)
ClaimsIdentity (BinaryFormatter, LosFormatter, SoapFormatter)
ClaimsPrincipal (BinaryFormatter, LosFormatter, SoapFormatter)
DataSet (BinaryFormatter, LosFormatter, SoapFormatter)
DataSetOldBehaviour (BinaryFormatter, LosFormatter)
DataSetOldBehaviourFromFile (BinaryFormatter, LosFormatter)
DataSetTypeSpoof (BinaryFormatter, LosFormatter, SoapFormatter)
GenericPrincipal (BinaryFormatter, LosFormatter)
GetterCompilerResults (Json.NET)
GetterSecurityException (Json.NET)
GetterSettingsPropertyValue (Json.NET, MessagePackTypeless, MessagePackTypelessLz4, Xaml)
ObjectDataProvider (DataContractSerializer (2), FastJson, FsPickler, JavaScriptSerializer, Json.NET, MessagePackTypeless, MessagePackTypelessLz4, SharpSerializerBinary, SharpSerializerXml, Xaml (4), XmlSerializer (2), YamlDotNet < 5.0.0)
ObjRef (BinaryFormatter, LosFormatter, ObjectStateFormatter, SoapFormatter)
PSObject (BinaryFormatter, LosFormatter, NetDataContractSerializer, SoapFormatter)
RolePrincipal (BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter)
SessionSecurityToken (BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter)
SessionViewStateHistoryItem (BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter)
TextFormattingRunProperties (BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter)
ToolboxItemContainer (BinaryFormatter, LosFormatter, SoapFormatter)
TypeConfuseDelegate (BinaryFormatter, LosFormatter, NetDataContractSerializer)
TypeConfuseDelegateMono (BinaryFormatter, LosFormatter, NetDataContractSerializer)
WindowsClaimsIdentity (BinaryFormatter (3), DataContractSerializer (2), Json.NET (2), LosFormatter (3), NetDataContractSerializer (3), SoapFormatter (2))
WindowsIdentity (BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter)
WindowsPrincipal (BinaryFormatter, DataContractJsonSerializer, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter)
XamlAssemblyLoadFromFile (BinaryFormatter, LosFormatter, NetDataContractSerializer, SoapFormatter)
XamlImageInfo (Json.NET)
```

## Plugins

YSoNet can generate raw payloads or more complex ones using a plugin architecture. To use a plugin, pass `-p <plugin name>` followed by the plugin options (the rest of the ysonet options are ignored). Example:

```bash
./ysonet.exe -p DotNetNuke -m read_file -f win.ini
```

Available plugins:

```text
ActivatorUrl (Sends a generated payload to an activated, presumably remote, object)
Altserialization (Generates payload for HttpStaticObjectsCollection or SessionStateItemCollection)
ApplicationTrust (Generates XML payload for the ApplicationTrust class)
Clipboard (Generates payload for DataObject and copies it into the clipboard - ready to be pasted in affected apps)
DotNetNuke (Generates payload for DotNetNuke CVE-2017-9822)
GetterCallGadgets (Implements arbitrary getter call gadgets for .NET Framework and .NET 5/6/7 with WPF enabled, run with -l for more help)
MachineKeySessionSecurityTokenHandler (Generates XML payload for the MachineKeySessionSecurityTokenHandler class)
NetNonRceGadgets (Implements Non-RCE gadgets for .NET Framework)
Resx (Generates RESX and .RESOURCES files)
SessionSecurityTokenHandler (Generates XML payload for the SessionSecurityTokenHandler class)
SharePoint (Generates payloads for the following SharePoint CVEs: CVE-2025-49704, CVE-2024-38018, CVE-2020-1147, CVE-2019-0604, CVE-2018-8421)
ThirdPartyGadgets (Implements gadgets for 3rd Party Libraries)
TransactionManagerReenlist (Generates payload for the TransactionManager.Reenlist method)
ViewState (Generates a ViewState using known MachineKey parameters)
```

### Plugin options

For help on a specific plugin's options, use `-h` with `-p <plugin name>`. Example:

```text
./ysonet.exe -h -p DotNetNuke

ysonet generates deserialization payloads for a variety of .NET formatters.

Plugin:

DotNetNuke (Generates payload for DotNetNuke CVE-2017-9822)

Options:

  -m, --mode=VALUE           the payload mode: read_file, write_file, run_command.
  -c, --command=VALUE        the command to be executed in run_command mode.
  -u, --url=VALUE            the url to fetch the file from in write_file mode.
  -f, --file=VALUE           the file to read in read_file mode or the file to write to in write_file mode.
      --minify               Whether to minify the payloads where applicable (experimental). Default: false
      --ust, --usesimpletype This is to remove additional info only when minifying and FormatterAssemblyStyle=Simple. Default: true
```
