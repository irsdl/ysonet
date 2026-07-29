# Gadgets and Plugins

The catalog of what YSoNet can generate. The lists below are a snapshot; the live, authoritative list comes from `ysonet.exe --fullhelp`. A few gadgets are marked hidden and are left out of this snapshot, so `--fullhelp` can show more than you see here.

> [!CAUTION]
> Do not use this catalog as a deserialization blocklist. It cannot include private,
> future, application-specific, or differently composed gadget chains. Blocking these
> entries does not make an unsafe deserializer safe. Read the
> [security guidance](../SECURITY.md) before using this catalog in a product review.

Back to [documentation index](README.md).

## Gadgets

Each gadget lists the formatters it supports. A number in parentheses means several variants exist.

```text
ActivitySurrogateDisableTypeCheck (BinaryFormatter (2), LosFormatter (2), NetDataContractSerializer (2), SoapFormatter)
ActivitySurrogateSelector (BinaryFormatter (2), LosFormatter, SoapFormatter)
ActivitySurrogateSelectorFromFile (BinaryFormatter (2), LosFormatter, SoapFormatter)
AssemblyInstallerLoad (FastJson (2), JavaScriptSerializer (2), Json.NET (2), MessagePackTypeless (2), MessagePackTypelessLz4 (2), SharpSerializerBinary (2), SharpSerializerXml (2), Xaml (2), YamlDotNet < 5.0.0 (2))
AxHostState (BinaryFormatter, LosFormatter, NetDataContractSerializer, SoapFormatter)
BaseActivationFactory (Json.NET)
ClaimsIdentity (BinaryFormatter, DataContractJsonSerializer, DataContractSerializer, LosFormatter, NetDataContractSerializer, SoapFormatter)
ClaimsPrincipal (BinaryFormatter, DataContractJsonSerializer, DataContractSerializer, LosFormatter, NetDataContractSerializer, SoapFormatter)
DataSet (BinaryFormatter, LosFormatter, SoapFormatter)
DataSetOldBehaviour (BinaryFormatter (2), LosFormatter (2))
DataSetOldBehaviourFromFile (BinaryFormatter (2), LosFormatter (2))
DataSetTypeSpoof (BinaryFormatter, LosFormatter, SoapFormatter)
DataSetXxe (BinaryFormatter (2), FsPickler (2), Json.NET (2), LosFormatter (2), SoapFormatter (2))
DataTable (BinaryFormatter (2), LosFormatter (2), SoapFormatter)
DataTableTypeSpoof (BinaryFormatter (2), LosFormatter (2), SoapFormatter)
DataViewManagerXxe (FastJson, JavaScriptSerializer, SharpSerializerBinary, SharpSerializerXml, Xaml)
DynamicUpdateMapExtension (Xaml)
FileLogTraceListener (DataContractJsonSerializer, FastJson, JavaScriptSerializer, Json.NET, MessagePackTypeless, MessagePackTypelessLz4, SharpSerializerXml, Xaml, YamlDotNet < 5.0.0)
FileSystemInfo (BinaryFormatter (2), DataContractJsonSerializer (2), DataContractSerializer (2), Json.NET (2), LosFormatter (2), NetDataContractSerializer (2), SoapFormatter (2))
FormsIdentity (BinaryFormatter, DataContractJsonSerializer, DataContractSerializer, LosFormatter, NetDataContractSerializer, SoapFormatter)
GenericIdentity (BinaryFormatter, DataContractJsonSerializer, DataContractSerializer, LosFormatter, NetDataContractSerializer, SoapFormatter)
GenericPrincipal (BinaryFormatter (2), DataContractJsonSerializer, DataContractSerializer, LosFormatter (2), NetDataContractSerializer, SoapFormatter (2))
GetterCompilerResults (Json.NET (4))
GetterSecurityException (Json.NET (4))
GetterSettingsPropertyValue (Json.NET (4), MessagePackTypeless, MessagePackTypelessLz4, Xaml (4))
InfiniteProgressPage (FastJson, JavaScriptSerializer, Json.NET, SharpSerializerXml, Xaml, YamlDotNet < 5.0.0)
ObjectDataProvider (DataContractSerializer (2), FastJson, FsPickler, JavaScriptSerializer, Json.NET, MessagePackTypeless, MessagePackTypelessLz4, SharpSerializerBinary, SharpSerializerXml, Xaml (2), XmlSerializer (2), YamlDotNet < 5.0.0)
ObjRef (BinaryFormatter, LosFormatter, SoapFormatter)
PictureBox (FastJson, JavaScriptSerializer, Json.NET, MessagePackTypeless, MessagePackTypelessLz4, SharpSerializerXml, Xaml, YamlDotNet < 5.0.0)
PSObject (BinaryFormatter, LosFormatter, NetDataContractSerializer, SoapFormatter)
ResourceDictionary (Xaml)
ResXFileRef (Xaml (3), YamlDotNet < 5.0.0 (3))
RolePrincipal (BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter)
SessionSecurityToken (BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter)
SessionViewStateHistoryItem (BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter)
TempFileCollection (BinaryFormatter, DataContractSerializer, LosFormatter, NetDataContractSerializer, SoapFormatter)
TextFormattingRunProperties (BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter)
ToolboxItemContainer (BinaryFormatter, LosFormatter, SoapFormatter)
TypeConfuseDelegate (BinaryFormatter (3), LosFormatter (3), NetDataContractSerializer (3))
TypeConfuseDelegateFileOperations (BinaryFormatter (5), LosFormatter (5), NetDataContractSerializer (5))
TypeConfuseDelegateMono (BinaryFormatter, LosFormatter, NetDataContractSerializer)
WbemClassObjectUnmarshal (BinaryFormatter (2), DataContractSerializer (2), FsPickler (2), Json.NET (2), LosFormatter (2), NetDataContractSerializer (2), SoapFormatter (2))
WindowsClaimsIdentity (BinaryFormatter (4), DataContractSerializer (3), Json.NET (3), LosFormatter (4), NetDataContractSerializer (4), SoapFormatter (3))
WindowsIdentity (BinaryFormatter (3), DataContractSerializer (3), Json.NET (3), LosFormatter (3), NetDataContractSerializer (3), SoapFormatter (3))
WindowsPrincipal (BinaryFormatter, DataContractJsonSerializer, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter)
WorkflowDesigner (FastJson, JavaScriptSerializer, Json.NET, MessagePackTypeless, MessagePackTypelessLz4, SharpSerializerBinary, SharpSerializerXml, Xaml)
WSManPluginInstance (DataContractJsonSerializer, DataContractSerializer, FastJson, JavaScriptSerializer, Json.NET, MessagePackTypeless, MessagePackTypelessLz4, NetDataContractSerializer, SharpSerializerBinary, SharpSerializerXml, Xaml, XmlSerializer, YamlDotNet < 5.0.0)
XamlAssemblyLoadFromFile (BinaryFormatter (2), LosFormatter (2), NetDataContractSerializer (2), SoapFormatter)
XamlImageInfo (Json.NET (2))
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
Resx (Generates RESX and .RESOURCES files)
SessionSecurityTokenHandler (Generates XML payload for the SessionSecurityTokenHandler class)
SharePoint (Generates payloads for the following SharePoint CVEs: CVE-2026-50522, CVE-2025-53770, CVE-2025-49704, CVE-2024-38018, CVE-2020-1147, CVE-2019-0604, CVE-2018-8421)
ThirdPartyGadgets (Implements gadgets for 3rd Party Libraries)
TransactionManagerReenlist (Generates payload for the TransactionManager.Reenlist method)
ViewState (Generates a ViewState using known MachineKey parameters)
Xps (Generates a malicious XPS document (CVE-2020-0605) - binary output, use --outputpath to save it as an .xps file)
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
      --rawcmd               Command will be executed as is without `cmd /c ` being appended (anything after the first space is an argument).
```
