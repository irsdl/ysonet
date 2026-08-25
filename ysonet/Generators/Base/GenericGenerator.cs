using NDesk.Options;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization.Formatters.Soap;
using System.Web.UI;
using ysonet.Helpers;

namespace ysonet.Generators
{
    // Split into two files by concern:
    //   GenericGenerator.cs            - the object-graph path (Serialize) and the shared
    //                                    gadget contract (naming, options, facets, bridging).
    //   GenericGenerator.HandWritten.cs - the hand written payload path, for a gadget that
    //                                    writes its own document or bytes instead of handing
    //                                    an object graph to Serialize().
    public abstract partial class GenericGenerator : IGenerator
    {
        public SerializationBinder serializationBinder = null;
        public abstract object Generate(string formatter, InputArgs inputArgs);
        public abstract string Finders();
        public abstract List<string> SupportedFormatters();

        // This is used to return the name of the gadget
        // It must be overridden especially in cases where a gadget inherits from another gadget
        public virtual string Name()
        {
            // Return the name of the gadget by using the actual class name (remove "Generator" from the end of the class name if it exists)
            // This ensures that derived classes automatically get unique names without requiring manual overrides
            string name = this.GetType().Name;
            if (name.EndsWith("Generator"))
            {
                name = name.Substring(0, name.Length - "Generator".Length);
            }
            return name;
        }

        // This is used when we want a gadget to support incoming from another gadget
        public virtual string SupportedBridgedFormatter()
        {
            return Formatters.None;
        }
        public object BridgedPayload { get; set; }

        // A compressed outer payload can occasionally be larger after its inner payload
        // was minified. A bridge consumer that wants to compare the two finished compressed
        // forms opts in here; PayloadRunner then carries an unminified copy of the upstream
        // chain beside the ordinary BridgedPayload. The default keeps every other chain on
        // the single-generation path.
        public object UnminifiedBridgedPayload { get; set; }

        public virtual bool NeedsUnminifiedBridgedPayload(string formatter, InputArgs inputArgs)
        {
            return false;
        }

        public virtual string AdditionalInfo()
        {
            // This is when we have nothing more to add to keep the help section cleaner
            return "";
        }

        public virtual void Init(InputArgs inputArgs)
        {
            // Overridable to provide more flexibility for rare cases
            OptionSet options = Options();
            if (options != null)
            {
                InputArgs tempInputArgs = inputArgs.DeepCopy();

                if (tempInputArgs.ExtraInternalArguments.Count > 0)
                {
                    // This means it is an internal call from other gadgets or plugins so current ExtraArguments becomes irrelevant and ExtraInternalArguments are important
                    tempInputArgs.ExtraArguments = tempInputArgs.ExtraInternalArguments;
                    tempInputArgs.ExtraInternalArguments = new List<string>(); // Clearing the list to prevent double use just in case!
                }

                try
                {
                    List<String> extraArguments = Options().Parse(tempInputArgs.ExtraArguments);
                }
                catch (OptionException e)
                {
                    throw new Exception("Invalid option for " + Name() + ": " + e.Message +
                        " (see 'ysonet -g " + Name() + " --fullhelp' for the gadget options)");
                }
            }
        }

        public virtual OptionSet Options()
        {
            return null;
        }

        // Most gadgets run a shell command. Gadgets that expect a file path, DLL,
        // URL, or that ignore the command override this.
        public virtual CommandInputType CommandInput()
        {
            return CommandInputType.ShellCommand;
        }

        // No variants by default. Gadgets with a var/ig option override this to
        // list their selectable variants.
        public virtual List<GadgetVariant> Variants()
        {
            return new List<GadgetVariant>();
        }

        // --legacyfx predates per-gadget capability metadata, so the compatibility
        // default is true. A gadget whose graph is tied to CLR4 (or another runtime)
        // overrides this to keep the option off its interactive/CLI surface.
        public virtual bool SupportsLegacyFx()
        {
            return true;
        }

        private void GuardLegacyFx(InputArgs inputArgs)
        {
            if (inputArgs != null && inputArgs.LegacyFx && !SupportsLegacyFx())
            {
                GadgetFacetSet facets = Facets();
                string targets = facets != null && facets.Versions != null
                    && facets.Versions.Count > 0
                    ? string.Join(", ", facets.Versions.ToArray())
                    : "a non-CLR2 runtime";
                throw new NotSupportedException(Name() + " does not support --legacyfx; "
                    + "its payload graph targets " + targets + " and cannot be rewritten "
                    + "into a CLR2 graph. Drop --legacyfx or select the target-specific "
                    + "gadget for that runtime.");
            }
        }

        // Broad discovery facets. The honest default is "uncategorized" on kind and
        // requirements, with input left to derive from CommandInput(). A gadget
        // overrides this to declare what its source, tests, and help actually prove.
        //
        // Facets drive the category search. ONE value also affects generation:
        // PayloadKind.DenialOfService marks a gadget that Helpers/Core/DosPolicy.cs
        // refuses to build without the --i-understand-dos acknowledgement, and that
        // every bulk run leaves out (see GenerateWithInit below). No other facet
        // value changes what is generated.
        public virtual GadgetFacetSet Facets()
        {
            return new GadgetFacetSet();
        }

        // Reject a variant+formatter pair the chosen variant declared it cannot
        // produce (via GadgetVariant.Without in Variants()). Call it at the top of
        // Generate(), after Init() has parsed the variant number. It turns an
        // impossible pair into one clear message (naming the formatter, variant, and
        // gadget) instead of a deep framework exception - e.g. a variant whose document
        // shape has no implementation for the requested formatter. On the
        // non-UI paths (CLI, sweep, bridged, tests) PayloadRunner wraps this throw
        // into a clean RunResult.Fail; the interactive editor validates the same rule
        // up front. An unknown variant number or an empty opt-out list is a no-op.
        protected void GuardVariantFormatter(int variantNumber, string formatter)
        {
            GadgetVariant match = null;
            foreach (GadgetVariant v in Variants())
            {
                if (v.Number == variantNumber)
                {
                    match = v;
                    break;
                }
            }
            if (match != null && !match.SupportsFormatter(formatter))
                throw new Exception(formatter + " is not supported by variant " + match.Number
                    + " (" + match.Label + ") of " + Name() + ".");
        }

        // Last-line denial-of-service defense. Every normal generation path ends up
        // here (GenerateWithNoTest and GenerateInner both call it), so a DoS gadget
        // cannot be built without the acknowledgement even by a caller that skipped
        // PayloadRunner. PayloadRunner still preflights the same rule, because only
        // it can refuse before the bridge/formatter checks and return the warning
        // with the payload; this throw is the backstop, not the primary gate.
        public object GenerateWithInit(string formatter, InputArgs inputArgs)
        {
            GuardLegacyFx(inputArgs);

            if ((inputArgs == null || !inputArgs.DosAcknowledged) && Helpers.Core.DosPolicy.IsDosGadget(this))
                throw new Exception(Helpers.Core.DosPolicy.RefusalMessage(Name()));

            Init(inputArgs);
            return Generate(formatter, inputArgs);
        }

        public object GenerateWithNoTest(string formatter, InputArgs inputArgs)
        {
            InputArgs tempInputArgs = inputArgs.DeepCopy();
            tempInputArgs.Test = false;
            return GenerateWithInit(formatter, tempInputArgs);
        }

        // Generate THIS gadget as the inner payload of another gadget or plugin. Use this,
        // not GenerateWithNoTest, whenever the caller hardcodes which inner gadget it wraps.
        //
        // Like GenerateWithNoTest it skips the local self-test, so embedding a gadget never
        // fires the payload on the operator's machine. It also isolates the OPTIONS. Init()
        // parses inputArgs.ExtraArguments for whichever generator it is called on, so handing
        // the caller's own arguments to an inner generator gives the inner gadget the OUTER
        // module's flags. When the two happen to share an option name - "var"/"variant" is the
        // one that collides in practice - the inner gadget either fails on a value meant for
        // the outer one or, worse, silently builds a different payload that still generates
        // and still passes the matrix. See dev-kitchen notes and the regression test
        // OuterVariantDoesNotReachTheInnerTypeConfuseDelegate.
        //
        // Only the parsed option list is dropped. Everything genuinely shared - the command,
        // Minify, UseSimpleType, debug mode - still reaches the inner payload. A caller that
        // really does want to steer the inner gadget sets ExtraInternalArguments, which is
        // preserved here and which Init() swaps in ahead of ExtraArguments (see
        // TextFormattingRunPropertiesGenerator's xamlurl hand-off and SharePointPlugin).
        //
        // A plugin or gadget that generates a gadget the USER chose (-g on the command line,
        // e.g. ViewState, SharePoint, Resx) must keep calling GenerateWithNoTest/
        // GenerateWithInit, because there the forwarded options are the point.
        public object GenerateInner(string formatter, InputArgs inputArgs)
        {
            InputArgs innerArgs = inputArgs.DeepCopy();
            innerArgs.ExtraArguments = new List<string>();
            return GenerateWithNoTest(formatter, innerArgs);
        }

        public object SerializeWithInit(object payloadObj, string formatter, InputArgs inputArgs)
        {
            GuardLegacyFx(inputArgs);
            Init(inputArgs);
            return Serialize(payloadObj, formatter, inputArgs);
        }

        public object SerializeWithNoTest(object payloadObj, string formatter, InputArgs inputArgs)
        {
            InputArgs tempInputArgs = inputArgs.DeepCopy();
            tempInputArgs.Test = false;
            return SerializeWithInit(payloadObj, formatter, tempInputArgs);
        }

        public virtual List<string> Labels()
        {
            return new List<string> { "" };
        }

        public virtual string Contributors()
        {
            return "";
        }

        public string Credit()
        {
            if (String.IsNullOrEmpty(Contributors()) || Finders().ToLower().Equals(Contributors().ToLower()))
            {
                return "[Finders: " + Finders() + "]";
            }
            else
            {
                return "[Finders: " + Finders() + "] [Contributors: " + Contributors() + "]";
            }

        }

        public Boolean IsSupported(string formatter)
        {
            var formatters = SupportedFormatters();
            var lowercased = formatters.Select(x => x.Split(new string[] { " " }, StringSplitOptions.None)[0].ToLower()).ToList();
            if (lowercased.Contains(formatter.ToLower())) return true;
            else return false;
        }

        // A payload that terminates the runtime when it fires cannot be self-tested in
        // this process: -t would kill ysonet.exe with no message, right after printing
        // the payload. A gadget in that position overrides this to route its self-test
        // through a child ysonet process (see Helpers/Core/IsolatedSelfTest.cs), which
        // tests the exact bytes the user gets and reports the outcome.
        //
        // Do NOT override this on a gadget that installs its own serializationBinder:
        // the child deserializes with a plain formatter and would resolve types
        // differently. RunSelfTest below refuses that pair, and the test
        // IsolatedSelfTestRefusesACustomBinder locks the refusal.
        public virtual bool SelfTestNeedsChildProcess(string formatter, InputArgs inputArgs)
        {
            return false;
        }

        // Some targets can only be BUILT on a single-threaded-apartment thread: WPF
        // objects, and anything whose constructor creates a System.Windows.Application.
        // A gadget aimed at one of those overrides this so -t deserializes on an STA
        // thread instead of the caller's; on a plain worker thread the payload throws
        // before it reaches the sink, which reads as "the gadget does not work".
        //
        // This is about the TARGET's threading requirement, not about safety, so it is
        // independent of SelfTestNeedsChildProcess: a gadget may need neither, either,
        // or in principle both.
        public virtual bool SelfTestNeedsStaThread(string formatter, InputArgs inputArgs)
        {
            return false;
        }

        // Exact target assemblies that an isolated CLR2 victim needs beside the payload.
        // The default is empty. A gadget override describes files and full identities only;
        // generic staging and resolution must never know which gadget requested them.
        protected virtual IEnumerable<Helpers.Core.Clr2SelfTestDependency>
            Clr2SelfTestDependencies()
        {
            return new Helpers.Core.Clr2SelfTestDependency[0];
        }

        // The one place -t decides HOW to run. Called by each formatter branch below
        // with its own in-process deserialize; routes to a child process when the
        // gadget declared it must, and onto an STA thread when the target needs one.
        // Swallowing the in-process error is the long-standing behavior (most gadgets
        // throw after firing); Debugging.ShowErrors surfaces it in debug mode.
        private void RunSelfTest(byte[] payload, string formatter, InputArgs inputArgs, Action inProcess)
        {
            RunSelfTest(payload, formatter, inputArgs, inProcess, null);
        }

        // isolatedRootTypeName is the assembly qualified name a DataContractJsonSerializer
        // payload must be read back as. That format writes no type name into the document, so
        // the child has no other way to know one; every other format leaves it null.
        private void RunSelfTest(byte[] payload, string formatter, InputArgs inputArgs, Action inProcess,
            string isolatedRootTypeName)
        {
            if (inputArgs == null || !inputArgs.Test)
                return;

            if (inputArgs.TestClr2)
            {
                // The shipped host reads with a plain framework formatter. A custom binder
                // would make the local and CLR2 reads resolve different types, so retain the
                // same refusal used by the ordinary isolated-child path.
                if (serializationBinder != null)
                    throw new Exception(Name() + " cannot run a CLR2 self-test: it installs "
                        + "its own SerializationBinder, which the CLR2 host does not reproduce.");

                Console.Error.WriteLine("[self-test CLR2] " + Name()
                    + ": launching the deliberately vulnerable one-shot CLR2 test process.");
                Helpers.Core.Clr2SelfTestResult result = Helpers.Core.Clr2SelfTest.Run(
                    payload, formatter, Clr2SelfTestDependencies());
                Helpers.Core.Clr2SelfTest.PrintResult(Name(), result);
                return;
            }

            if (SelfTestNeedsChildProcess(formatter, inputArgs))
            {
                // The child deserializes with a plain formatter, so a gadget that installs
                // its own binder (PSObject resolves the bundled vulnerable assembly through
                // one) would be tested against different types than it ships. Refuse loudly
                // instead of silently reporting a self-test that proved something else.
                if (serializationBinder != null)
                    throw new Exception(Name() + " cannot run an isolated self-test: it installs "
                        + "its own SerializationBinder, which the child process does not reproduce. "
                        + "Drop the binder or the SelfTestNeedsChildProcess override.");

                Helpers.Core.IsolatedSelfTest.Run(payload, formatter, inputArgs, Name(), isolatedRootTypeName);
                return;
            }

            if (SelfTestNeedsStaThread(formatter, inputArgs))
            {
                // Record it on the args as well as acting on it: IsSTAThread is what tells
                // any later caller how this payload was tested, and it used to be the flag a
                // gadget set for itself before this hook existed.
                inputArgs.IsSTAThread = true;
                RunOnStaThread(delegate
                {
                    try { inProcess(); }
                    catch (Exception err) { Debugging.ShowErrors(inputArgs, err); }
                });
                return;
            }

            try { inProcess(); }
            catch (Exception err) { Debugging.ShowErrors(inputArgs, err); }
        }

        // Run an action on a fresh STA thread and wait for it. The caller's thread may
        // already be STA (ysonet's own Main is not), but a nested apartment is free and
        // this way the behaviour does not depend on who called.
        private static void RunOnStaThread(System.Threading.ThreadStart action)
        {
            var staThread = new System.Threading.Thread(action);
            staThread.SetApartmentState(System.Threading.ApartmentState.STA);
            staThread.Start();
            staThread.Join();
        }

        // The ONE place a finished payload LAYER is post-processed before anybody sees it.
        //
        // Both payload paths call it at the same point: after format-specific minification,
        // and BEFORE RunSelfTest and the return. That order is what makes -t read the exact
        // bytes the operator gets, and it is why the hook cannot live in PayloadRunner: by
        // the time PayloadRunner has the outer payload, a bridged or hard-coded inner gadget
        // has already been embedded, and some LosFormatter payloads are a native
        // ObjectStateFormatter record rather than a BinaryFormatter blob the outer bytes
        // would reveal. Finishing here means each layer transforms its own format, in its own
        // generator, before the next layer wraps it.
        //
        // Today it does one thing: the --legacyfx assembly identity rewrite, which is a no-op
        // (and allocates nothing) unless the operator asked for it. A new whole-payload step
        // belongs here rather than in a second boundary.
        protected object FinalizeGeneratedPayload(object payload, string formatter, InputArgs inputArgs)
        {
            // Backstop direct Generate()/Serialize() callers that bypass GenerateWithInit.
            GuardLegacyFx(inputArgs);

            if (inputArgs == null || !inputArgs.LegacyFx)
                return payload;

            LegacyFrameworkIdentities.RewriteReport report;
            object result = LegacyFrameworkIdentities.Apply(payload, formatter, inputArgs, out report);
            Debugging.ShowNote(inputArgs, "--legacyfx: " + report.Detail);
            return result;
        }

        // The same hook where the caller already knows it is holding bytes.
        private byte[] FinalizeGeneratedBytes(byte[] payload, string formatter, InputArgs inputArgs)
        {
            return (byte[])FinalizeGeneratedPayload(payload, formatter, inputArgs);
        }

        public object Serialize(object payloadObj, string formatter, InputArgs inputArgs)
        {
            MemoryStream stream = new MemoryStream();

            if (formatter.ToLower().Equals("binaryformatter"))
            {
                BinaryFormatter fmt = new BinaryFormatter();

                if (inputArgs.Minify)
                {
                    ysonet.Helpers.ModifiedVulnerableBinaryFormatters.BinaryFormatter fmtLocal = new ysonet.Helpers.ModifiedVulnerableBinaryFormatters.BinaryFormatter();
                    fmtLocal.Serialize(stream, payloadObj);
                }
                else
                {
                    fmt.Serialize(stream, payloadObj);
                }


                // The self-test reads the FINAL bytes, not the pre-transform stream, so -t
                // always exercises exactly what the operator is handed.
                byte[] bfPayload = FinalizeGeneratedBytes(stream.ToArray(), formatter, inputArgs);
                RunSelfTest(bfPayload, formatter, inputArgs, delegate
                {
                    if (serializationBinder != null)
                        fmt.Binder = serializationBinder;
                    fmt.Deserialize(new MemoryStream(bfPayload));
                });
                return bfPayload;
            }
            /*
             * We don't actually need to use ObjectStateFormatter in YSoNet because it is the same as LosFormatter without MAC/keys
            else if (formatter.ToLower().Equals("objectstateformatter"))
            {
                ObjectStateFormatter osf = new ObjectStateFormatter();
                osf.Serialize(stream, payloadObj);
                if (inputArgs.Test)
                {
                    try
                    {
                        stream.Position = 0;
                        osf.Deserialize(stream);
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
                return stream.ToArray();
            }
            */
            else if (formatter.ToLower().Equals("soapformatter"))
            {
                SoapFormatter sf = new SoapFormatter();
                sf.Serialize(stream, payloadObj);

                if (inputArgs.Minify)
                {
                    stream.Position = 0;
                    if (inputArgs.UseSimpleType)
                    {
                        stream = XmlMinifier.Minify(stream, new String[] { "Microsoft.PowerShell.Editor" }, null, FormatterType.SoapFormatter, true);
                    }
                    else
                    {
                        stream = XmlMinifier.Minify(stream, null, null, FormatterType.SoapFormatter, true);
                    }
                }

                byte[] soapPayload = FinalizeGeneratedBytes(stream.ToArray(), formatter, inputArgs);
                RunSelfTest(soapPayload, formatter, inputArgs, delegate
                {
                    if (serializationBinder != null)
                        sf.Binder = serializationBinder;
                    sf.Deserialize(new MemoryStream(soapPayload));
                });
                return soapPayload;
            }
            else if (formatter.ToLower().Equals("netdatacontractserializer"))
            {
                NetDataContractSerializer ndcs = new NetDataContractSerializer();
                ndcs.Serialize(stream, payloadObj);

                if (inputArgs.Minify)
                {
                    stream.Position = 0;
                    if (inputArgs.UseSimpleType)
                    {
                        stream = XmlMinifier.Minify(stream, new string[] { "mscorlib", "Microsoft.PowerShell.Editor" }, new string[] { @"\<Signature2[^\/]+<\/Signature2\>" }, FormatterType.NetDataContractXML, true);
                    }
                    else
                    {
                        stream = XmlMinifier.Minify(stream, null, null, FormatterType.NetDataContractXML, true);
                    }
                }

                byte[] ndcsPayload = FinalizeGeneratedBytes(stream.ToArray(), formatter, inputArgs);
                RunSelfTest(ndcsPayload, formatter, inputArgs, delegate
                {
                    if (serializationBinder != null)
                        ndcs.Binder = serializationBinder;
                    ndcs.Deserialize(new MemoryStream(ndcsPayload));
                });
                return ndcsPayload;
            }
            else if (formatter.ToLower().Equals("losformatter"))
            {
                LosFormatter lf = new LosFormatter();

                if (inputArgs.Minify)
                {
                    stream = Helpers.ModifiedVulnerableBinaryFormatters.SimpleMinifiedObjectLosFormatter.Serialize(payloadObj);
                }
                else
                {
                    lf.Serialize(stream, payloadObj);
                }

                byte[] losPayload = FinalizeGeneratedBytes(stream.ToArray(), formatter, inputArgs);
                RunSelfTest(losPayload, formatter, inputArgs, delegate
                {
                    lf.Deserialize(new MemoryStream(losPayload));
                });
                return losPayload;
            }
            else
            {
                throw new Exception("Formatter not supported");
            }
        }


    }
}
