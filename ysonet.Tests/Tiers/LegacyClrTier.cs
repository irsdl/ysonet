using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using ysonet.Generators;
using ysonet.Helpers;
using ysonet.Helpers.Core;
using ysonet.Interactive;
using ysonet.Plugins;

namespace ysonet.Tests
{
    /// <summary>
    /// What a LEGACY row expects to see when the payload lands on CLR 2. Never "no exception":
    /// two carriers were measured deserializing cleanly on CLR 2 and doing nothing at all, so
    /// recording exit status or the absence of a throw would have reported false passes.
    /// </summary>
    internal enum LegacyEffect
    {
        /// <summary>The file named in -c is gone afterwards, and its sentinel neighbour is not.</summary>
        DeletedFile = 0,
        /// <summary>A connection arrived at this run's loopback listener.</summary>
        LoopbackConnection = 1,
        /// <summary>The directory named in -c exists afterwards.</summary>
        CreatedDirectory = 2,
        /// <summary>The fire backend recorded the command the payload was given.</summary>
        Command = 3,
        /// <summary>
        /// The gadget takes a C# SOURCE file rather than a command, so the fixture WRITES that
        /// source and the effect is what the compiled class does when its constructor runs: it
        /// creates a directory this run owns.
        ///
        /// This exists because the ActivitySurrogate family carries a compiled assembly as
        /// data, and a command sink can never observe it - the plain gadget declares
        /// CommandInputType.Ignored and runs a fixed e.dll. Handing it a source file the suite
        /// wrote is the only way to make its real effect visible, and it is also what lets the
        /// CLR-v2 compiler question be asked at all.
        /// </summary>
        SourceCreatesDirectory = 4,
    }

    /// <summary>
    /// One curated LEGACY cell: a payload source, a reader, the effect that proves it landed,
    /// and what this repository has MEASURED it to do on CLR 2. A source is either a gadget
    /// plus formatter or a plugin plus its argv; the reader is always explicit.
    ///
    /// A row declares its expectation because a measured negative is a deliverable, not a
    /// failure to hide. "TypeConfuseDelegate does not reach CLR 2, and the reason is that its
    /// own payload names System 4.0.0.0" is the answer an operator needs; deleting the row
    /// would turn that into "nobody looked".
    /// </summary>
    internal sealed class LegacyClrRow
    {
        public readonly string Gadget;
        public readonly string Formatter;
        public readonly string Plugin;
        public readonly string Reader;
        public readonly string[] PluginArgs;
        /// <summary>
        /// Arguments that produce the same authenticated Base64 envelope with a rejected key.
        /// When present, the engine also flips one byte of the accepted payload and requires
        /// both controls to fail authentication before the accepted payload may count as a fire.
        /// This is deliberately row data, so private plugin/gadget rows use the same proof.
        /// </summary>
        public string[] AuthenticationRejectArgs;
        public readonly LegacyEffect Effect;
        public readonly bool ExpectFire;
        /// <summary>The classified reason a no-fire row is expected to produce.</summary>
        public readonly string ExpectedReason;
        /// <summary>Why the row is in the table. Printed on a mismatch.</summary>
        public readonly string Note;

        /// <summary>Extra CLI arguments, space separated. Empty for none.</summary>
        public string ExtraArgs = "";
        /// <summary>Assembly qualified root type, for a document that names no type.</summary>
        public string RootType;
        /// <summary>Generate this row with the global --minify context.</summary>
        public bool Minify;

        /// <summary>
        /// Generate this row's payload with --legacyfx, so the framework identities it names
        /// are the CLR-v2 ones. This is what turns a `payload-names-4x-assembly` negative into
        /// a measurable question rather than a permanent answer.
        /// </summary>
        public bool LegacyFx;

        /// <summary>
        /// The lanes this row APPLIES to, by RuntimeVersion token, or null for "every lane
        /// whose formatter set contains this row's formatter".
        ///
        /// A uniform row cannot state an honest 3.0 floor. A WPF or WCF chain carried by
        /// BinaryFormatter/SoapFormatter/LosFormatter is INAPPLICABLE on the 2.0 lane - not a
        /// measured negative - because the type it needs does not exist there at all, and the
        /// lane's forbidden-load guard would reject the result even if the assembly were
        /// physically present on the machine.
        /// </summary>
        public string[] Lanes;

        /// <summary>
        /// The lanes this row is expected to FIRE in, or null for "every applicable lane"
        /// (when <see cref="ExpectFire"/> is set) / "none" (when it is not). Use it for a
        /// carrier that only exists from 3.0 upwards, where 2.0 is a measured negative and
        /// 3.0/3.5 are positives.
        /// </summary>
        public string[] FiringLanes;

        private LegacyClrRow(string gadget, string formatter, LegacyEffect effect,
            bool expectFire, string expectedReason, string note)
        {
            Gadget = gadget;
            Formatter = formatter;
            Reader = formatter;
            PluginArgs = new string[0];
            Effect = effect;
            ExpectFire = expectFire;
            ExpectedReason = expectedReason;
            Note = note;
        }

        private LegacyClrRow(string plugin, string reader, LegacyEffect effect,
            bool expectFire, string expectedReason, string note, string[] pluginArgs)
        {
            Plugin = plugin;
            Reader = reader;
            PluginArgs = pluginArgs ?? new string[0];
            Effect = effect;
            ExpectFire = expectFire;
            ExpectedReason = expectedReason;
            Note = note;
        }

        public bool IsPlugin { get { return !string.IsNullOrEmpty(Plugin); } }

        public static LegacyClrRow Fires(string gadget, string formatter, LegacyEffect effect, string note)
        {
            return new LegacyClrRow(gadget, formatter, effect, true, null, note);
        }

        public static LegacyClrRow DoesNotFire(string gadget, string formatter, LegacyEffect effect,
            string reason, string note)
        {
            return new LegacyClrRow(gadget, formatter, effect, false, reason, note);
        }

        public static LegacyClrRow PluginFires(string plugin, string reader, LegacyEffect effect,
            string note, params string[] pluginArgs)
        {
            return new LegacyClrRow(plugin, reader, effect, true, null, note, pluginArgs);
        }

        public LegacyClrRow With(string extraArgs) { ExtraArgs = extraArgs ?? ""; return this; }
        public LegacyClrRow WithRootType(string rootType) { RootType = rootType; return this; }
        public LegacyClrRow WithMinify() { Minify = true; return this; }
        public LegacyClrRow WithLegacyFx() { LegacyFx = true; return this; }
        public LegacyClrRow WithAuthenticatedBase64Controls(params string[] rejectedArgs)
        {
            AuthenticationRejectArgs = rejectedArgs;
            return this;
        }
        public LegacyClrRow InLanes(params string[] lanes) { Lanes = lanes; return this; }
        public LegacyClrRow FiresIn(params string[] lanes) { FiringLanes = lanes; return this; }

        /// <summary>Does this row belong to the lane at all?</summary>
        public bool AppliesTo(LegacyClrLane lane)
        {
            if (!lane.Supports(Reader)) return false;
            if (Lanes == null) return true;
            foreach (string token in Lanes)
                if (string.Equals(token, lane.VersionToken, StringComparison.Ordinal)) return true;
            return false;
        }

        /// <summary>What this row expects to see IN THIS LANE.</summary>
        public bool ExpectsFireIn(LegacyClrLane lane)
        {
            if (FiringLanes == null) return ExpectFire;
            foreach (string token in FiringLanes)
                if (string.Equals(token, lane.VersionToken, StringComparison.Ordinal)) return true;
            return false;
        }

        public string Describe(LegacyClrLane lane)
        {
            if (IsPlugin)
                return Plugin + " -> " + Reader
                    + (PluginArgs.Length == 0 ? "" : " " + string.Join(" ", PluginArgs))
                    + " [" + lane.Label + "]";
            return Gadget + " " + Formatter
                + (LegacyFx ? " --legacyfx" : "")
                + (Minify ? " --minify" : "")
                + (ExtraArgs.Length == 0 ? "" : " " + ExtraArgs)
                + " [" + lane.Label + "]";
        }
    }

    internal partial class Tests
    {
        // ---- classified no-fire reasons ---------------------------------------
        //
        // A failure has to be CLASSIFIED, not just counted. "the framework does not have this
        // type" is a runtime-version fact; "our payload hardcodes 4.0.0.0" and "that assembly
        // is not on this target" are not, and only the first one could ever be fixed by
        // choosing a different framework.

        /// <summary>The payload writes a 4.x assembly identity, so the reader cannot bind it.</summary>
        internal const string LegacyReasonPayloadNames4x = "payload-names-4x-assembly";
        /// <summary>The type the chain needs does not exist on CLR 2 at all.</summary>
        internal const string LegacyReasonTypeAbsent = "type-absent-on-clr2";
        /// <summary>An assembly the chain names is not installed on this target.</summary>
        internal const string LegacyReasonAssemblyAbsent = "target-assembly-absent";
        /// <summary>The 2.0 carrier has a different member shape from the 4.x one.</summary>
        internal const string LegacyReasonMemberShape = "carrier-member-shape-differs";
        /// <summary>It deserialized cleanly and produced nothing. The trap this tier exists to avoid.</summary>
        internal const string LegacyReasonNoEffect = "deserialized-no-effect";
        /// <summary>
        /// The reader refused and its message names nothing: no type, no assembly, no member.
        /// The 3.5 JavaScriptSerializer is the case that forced this - its type resolver
        /// throws a bare "Operation is not valid due to the current state of the object" with
        /// no inner exception - and inventing a cause for it would be a guess. The row's
        /// printed line carries the STATIC observation beside it instead.
        /// </summary>
        internal const string LegacyReasonReaderRefused = "reader-refused-without-a-cause";
        /// <summary>Something else. The child's own first line is printed beside it.</summary>
        internal const string LegacyReasonOther = "child-error";

        /// <summary>
        /// The curated LEGACY table: PUBLIC gadgets only.
        ///
        /// This file is tracked, so it may only name public modules. A contributor with a
        /// private area adds its rows through <see cref="RunPrivateLegacyRows"/>, which hands
        /// them to the SAME engine (<see cref="RunLegacyRowsIn"/>); nothing about the harness
        /// is duplicated on that side and nothing private is named here.
        ///
        /// Every row below was measured on CLR 2.0.50727 before it was written down. A row
        /// runs in every lane whose formatter set contains its formatter, which is how one
        /// curated row earns 2.0, 3.0 and 3.5 evidence without a second harness.
        /// </summary>
        private static readonly LegacyClrRow[] LegacyClrRows =
        {
            // ObjRef is the clean positive: every formatter it advertises fires on CLR 2. The
            // chain is System.Exception carrying an ObjRefLite, and .NET Remoting shipped in
            // 2.0, so nothing in the payload is newer than the target. The child registers a
            // TCP client channel first, because the runtime only emits the outbound call when
            // a matching CLIENT channel exists (process global, exactly as the 4.x fire row).
            LegacyClrRow.Fires("ObjRef", LegacyClrLane.BinaryFormatter,
                LegacyEffect.LoopbackConnection,
                "remoting carrier; the whole chain predates CLR 4"),
            LegacyClrRow.Fires("ObjRef", LegacyClrLane.SoapFormatter,
                LegacyEffect.LoopbackConnection,
                "SOAP binds assembly identities strictly, and this payload names none that is 4.x"),
            LegacyClrRow.Fires("ObjRef", LegacyClrLane.LosFormatter,
                LegacyEffect.LoopbackConnection,
                "LosFormatter is the BinaryFormatter stream in base64, so it inherits the same result"),

            // TempFileCollection is the split result, and the most instructive row in the
            // table: the SAME payload fires on the two lenient readers and is refused by the
            // three strict ones. Its type name carries "System, Version=4.0.0.0"; the
            // BinaryFormatter binder unifies that to the 2.0 System.dll sitting right there,
            // while SOAP, NetDataContractSerializer and DataContractSerializer bind the
            // version as written and fail before the payload is reached.
            LegacyClrRow.Fires("TempFileCollection", LegacyClrLane.BinaryFormatter,
                LegacyEffect.DeletedFile,
                "the BinaryFormatter binder unifies the 4.0.0.0 System identity to the 2.0 one"),
            LegacyClrRow.Fires("TempFileCollection", LegacyClrLane.LosFormatter,
                LegacyEffect.DeletedFile,
                "same stream as BinaryFormatter, wrapped in the ObjectStateFormatter token"),
            LegacyClrRow.DoesNotFire("TempFileCollection", LegacyClrLane.SoapFormatter,
                LegacyEffect.DeletedFile, LegacyReasonPayloadNames4x,
                "SOAP puts the assembly identity in the namespace URI and binds it verbatim"),
            LegacyClrRow.DoesNotFire("TempFileCollection", LegacyClrLane.NetDataContractSerializer,
                LegacyEffect.DeletedFile, LegacyReasonPayloadNames4x,
                "the NetDataContractSerializer z:Type/z:Assembly pair is bound verbatim"),
            LegacyClrRow.DoesNotFire("TempFileCollection", LegacyClrLane.DataContractSerializer,
                LegacyEffect.DeletedFile, LegacyReasonPayloadNames4x,
                "the <root type=...> envelope is resolved with Type.GetType, which does not unify"),

            // The command-execution family, which is what most operators reach for first. It
            // does NOT reach CLR 2, and the reason is the payload's own assembly strings
            // rather than the technique: a CLR-2 System.dll is present and unused. Recorded
            // so the answer is "looked, and here is why not" instead of "nobody looked".
            LegacyClrRow.DoesNotFire("TypeConfuseDelegate", LegacyClrLane.BinaryFormatter,
                LegacyEffect.Command, LegacyReasonPayloadNames4x,
                "the sorted-container chain names System 4.0.0.0 for types the 2.0 System.dll has"),
            LegacyClrRow.DoesNotFire("TypeConfuseDelegate", LegacyClrLane.LosFormatter,
                LegacyEffect.Command, LegacyReasonPayloadNames4x,
                "same stream as BinaryFormatter"),
            LegacyClrRow.DoesNotFire("TypeConfuseDelegate", LegacyClrLane.NetDataContractSerializer,
                LegacyEffect.Command, LegacyReasonPayloadNames4x,
                "the same identity in the z:Type/z:Assembly pair, bound verbatim"),

            // Four carriers that each fail DIFFERENTLY, so the classifier is exercised by the
            // real tier and not only by its unit test. They are measurements, not proposals:
            // nothing here is a suggestion to change a chain so that it reaches further down.
            //
            // WindowsIdentity resolves on CLR 2 and then finds a different member set. That is
            // the one answer in this table that IS a runtime-version fact about the carrier
            // rather than about an identity string we wrote.
            LegacyClrRow.DoesNotFire("WindowsIdentity", LegacyClrLane.BinaryFormatter,
                LegacyEffect.Command, LegacyReasonMemberShape,
                "the 2.0 carrier's serialization constructor runs and its member set differs"),
            // DataSet's own carrier reaches CLR 2; what stops it is its default INNER gadget
            // needing a PowerShell assembly the target does not have. An absent target
            // assembly is a property of the target, not of the framework version.
            LegacyClrRow.DoesNotFire("DataSet", LegacyClrLane.BinaryFormatter,
                LegacyEffect.Command, LegacyReasonAssemblyAbsent,
                "the DataSet carrier runs on 2.0; its default inner gadget needs an assembly"
                + " that is not there"),
            // The two rows that justify the whole "no exception is not a fire" rule: both
            // deserialize cleanly on CLR 2 and do nothing at all. A tier that recorded exit
            // status or the absence of a throw would report these as passes.
            LegacyClrRow.DoesNotFire("AxHostState", LegacyClrLane.BinaryFormatter,
                LegacyEffect.Command, LegacyReasonNoEffect,
                "deserializes cleanly on CLR 2 and produces no effect"),
            LegacyClrRow.DoesNotFire("ActivitySurrogateSelector", LegacyClrLane.BinaryFormatter,
                LegacyEffect.Command, LegacyReasonNoEffect,
                "deserializes cleanly on CLR 2 and produces no effect"),

            // The 3.5-only readers get their own surface rather than only inheriting the
            // BinaryFormatter rows. FileLogTraceListener's effect needs no command and no
            // network: the target creates the directory it is given.
            LegacyClrRow.DoesNotFire("FileLogTraceListener", LegacyClrLane.JavaScriptSerializer,
                LegacyEffect.CreatedDirectory, LegacyReasonReaderRefused,
                "the 3.5 type resolver refuses the __type string without saying why; the static"
                + " note beside the row is what shows it names Microsoft.VisualBasic 10.0.0.0"),
            LegacyClrRow.DoesNotFire("FileLogTraceListener", LegacyClrLane.DataContractJsonSerializer,
                LegacyEffect.CreatedDirectory, LegacyReasonPayloadNames4x,
                "the row supplies the same 10.0.0.0 root type, because the document names none")
                .WithRootType("Microsoft.VisualBasic.Logging.FileLogTraceListener, Microsoft.VisualBasic,"
                    + " Version=10.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"),

            // ---- the same cells, generated with --legacyfx --------------------------
            //
            // Every row above whose reason is `payload-names-4x-assembly` is a question the
            // identity rewrite can answer, so each one is measured a SECOND time with the
            // option on. The pair is the deliverable: "this reader refuses the 4.x identity,
            // and here is what happens when the payload names the 2.0 one instead".
            //
            // These are not predictions. Each was run against a real CLR 2.0.50727 child
            // before it was written down, exactly like the rows above.
            LegacyClrRow.Fires("TempFileCollection", LegacyClrLane.SoapFormatter,
                LegacyEffect.DeletedFile,
                "SOAP binds the namespace URI's assembly identity verbatim, so naming System"
                + " 2.0.0.0 is all it needed").WithLegacyFx(),
            LegacyClrRow.Fires("TempFileCollection", LegacyClrLane.NetDataContractSerializer,
                LegacyEffect.DeletedFile,
                "the z:Type/z:Assembly pair is bound verbatim too").WithLegacyFx(),
            LegacyClrRow.Fires("TempFileCollection", LegacyClrLane.DataContractSerializer,
                LegacyEffect.DeletedFile,
                "the <root type=...> envelope is resolved with Type.GetType, which needs the"
                + " target's own assembly version").WithLegacyFx(),

            // The command-execution family with the option on, and the most useful pair in the
            // table. Without --legacyfx these three are classified `payload-names-4x-assembly`,
            // which reads as "an identity string we wrote is in the way". With the identity
            // fixed, the reader gets further and names the REAL blocker: the chain's
            // `System.Func`3` does not exist in mscorlib 2.0.0.0 (Func<> arrived in System.Core
            // 3.5 and only reached mscorlib in 4.0). So the identity was never the whole story,
            // and the honest classification changes from ours to the framework's.
            LegacyClrRow.DoesNotFire("TypeConfuseDelegate", LegacyClrLane.BinaryFormatter,
                LegacyEffect.Command, LegacyReasonTypeAbsent,
                "with System at 2.0.0.0 the reader reaches the graph and refuses System.Func`3,"
                + " which mscorlib 2.0 does not have").WithLegacyFx(),
            LegacyClrRow.DoesNotFire("TypeConfuseDelegate", LegacyClrLane.LosFormatter,
                LegacyEffect.Command, LegacyReasonTypeAbsent,
                "same stream as BinaryFormatter").WithLegacyFx(),
            LegacyClrRow.DoesNotFire("TypeConfuseDelegate", LegacyClrLane.NetDataContractSerializer,
                LegacyEffect.Command, LegacyReasonTypeAbsent,
                "the same graph through the z:Type/z:Assembly pair").WithLegacyFx(),

            // The CLR-v2-specific command chain replaces Comparer<T>.Create with Workflow's
            // ObjectSerializedRef reconstruction of Array.FunctorComparer<string>. It authors
            // Func<string,string,Process> in System.Core 3.5 directly and forces the remaining
            // CLR-v2 identities itself, so neither row needs .WithLegacyFx().
            LegacyClrRow.Fires("TypeConfuseDelegateLegacyWorkflow",
                LegacyClrLane.BinaryFormatter, LegacyEffect.Command,
                "the fake delegate holder and Workflow comparer reconstruction reach "
                + "Process.Start from TreeSet.OnDeserialization")
                .InLanes(RuntimeVersion.NetFx35),
            LegacyClrRow.Fires("TypeConfuseDelegateLegacyWorkflow",
                LegacyClrLane.BinaryFormatter, LegacyEffect.Command,
                "the minified NRBF graph preserves the holder entries, Workflow member order, "
                + "and TreeSet trigger")
                .InLanes(RuntimeVersion.NetFx35).WithMinify(),
            LegacyClrRow.Fires("TypeConfuseDelegateLegacyWorkflow",
                LegacyClrLane.SoapFormatter, LegacyEffect.Command,
                "the direct SOAP document advertises List<object> and TreeSet<string>, with "
                + "Workflow ObjectSerializedRef confined to the internal comparer")
                .InLanes(RuntimeVersion.NetFx35),
            LegacyClrRow.Fires("TypeConfuseDelegateLegacyWorkflow",
                LegacyClrLane.SoapFormatter, LegacyEffect.Command,
                "the minified direct SOAP graph keeps its genuine closed-generic identities "
                + "and reaches Process.Start without an outer carrier")
                .InLanes(RuntimeVersion.NetFx35).WithMinify(),
            LegacyClrRow.Fires("TypeConfuseDelegateLegacyWorkflow",
                LegacyClrLane.LosFormatter, LegacyEffect.Command,
                "the LosFormatter ObjectState wrapper carries the same CLR-v2 graph")
                .InLanes(RuntimeVersion.NetFx35),
            LegacyClrRow.Fires("TypeConfuseDelegateLegacyWorkflow",
                LegacyClrLane.LosFormatter, LegacyEffect.Command,
                "the minified LosFormatter form preserves the delegate type's separately "
                + "qualified mscorlib arguments")
                .InLanes(RuntimeVersion.NetFx35).WithMinify(),

            // Microsoft.VisualBasic is versioned off the VB product number, so its CLR-v2
            // identity is 8.0.0.0 rather than 2.0.0.0. These two rows are what prove the map
            // got that right against a real target rather than in a fixture.
            //
            // The JavaScriptSerializer pair is also what settles a reason code that could not
            // settle itself. Without --legacyfx the 3.5 type resolver refuses with a bare
            // "Operation is not valid due to the current state of the object" - no type, no
            // assembly, no member - which is why the classifier has a
            // `reader-refused-without-a-cause` outcome at all. With the identity at 8.0.0.0 it
            // FIRES, so the cause was the version string after all; the reader simply never
            // said so.
            LegacyClrRow.Fires("FileLogTraceListener", LegacyClrLane.JavaScriptSerializer,
                LegacyEffect.CreatedDirectory,
                "the 3.5 type resolver takes the __type string once it names Microsoft.VisualBasic"
                + " 8.0.0.0, which is what its silent refusal was really about").WithLegacyFx(),
            LegacyClrRow.Fires("FileLogTraceListener", LegacyClrLane.DataContractJsonSerializer,
                LegacyEffect.CreatedDirectory,
                "the document names no type, so the ROW supplies the CLR-v2 root identity; that is"
                + " what a real consumer has fixed in its own code")
                .WithLegacyFx()
                .WithRootType("Microsoft.VisualBasic.Logging.FileLogTraceListener, Microsoft.VisualBasic,"
                    + " Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"),

            // ---- ObjectDataProvider: the catalogue's pre-4.0 code-execution candidate -----
            //
            // ObjectDataProvider and XamlReader are PresentationFramework types, and
            // PresentationFramework shipped in .NET 3.0, not 4.0. The gadget's declared 4.0
            // floor is a property of the identity string the payload writes, not of the
            // technique, which is exactly what --legacyfx exists to separate.
            //
            // Every row here is 3.5 ONLY, and the reason is the carrier rather than the reader.
            // All three of ObjectDataProvider's CLR-2-capable readers reach it through
            // System.Data.Services `ExpandedWrapper`2` (JavaScriptSerializer is the exception -
            // it names the provider directly - but JavaScriptSerializer is itself 3.5, in
            // System.Web.Extensions). System.Data.Services is 3.5, so 2.0 and 3.0 are
            // INAPPLICABLE rather than measured negatives, and InLanes says so.
            LegacyClrRow.Fires("ObjectDataProvider", LegacyClrLane.XmlSerializer,
                LegacyEffect.Command,
                "XamlReader.Parse on a ResourceDictionary; with the identities rewritten the"
                + " payload names only PresentationFramework 3.0.0.0 and System.Data.Services"
                + " 3.5.0.0")
                .InLanes(RuntimeVersion.NetFx35).WithLegacyFx(),
            LegacyClrRow.DoesNotFire("ObjectDataProvider", LegacyClrLane.XmlSerializer,
                LegacyEffect.Command, LegacyReasonPayloadNames4x,
                "the same document naming PresentationFramework 4.0.0.0, which Type.GetType"
                + " resolves verbatim off the <root type=...> envelope")
                .InLanes(RuntimeVersion.NetFx35),

            // DataContractSerializer is the one ObjectDataProvider reader that does NOT reach
            // the sink on CLR 2, and it is not an identity problem: with --legacyfx the child
            // binds every assembly the payload names (System.Data.Services 3.5.0.0,
            // PresentationFramework 3.0.0.0, PresentationCore, WindowsBase) and then throws a
            // bare NullReferenceException while building the graph. No type, no assembly, no
            // member is named, which is exactly the `reader-refused-without-a-cause` case.
            // Variant 1 drives Process.Start through the ExpandedWrapper's projected property,
            // and the 3.0 DataContractSerializer does not populate it the way 4.x does.
            LegacyClrRow.DoesNotFire("ObjectDataProvider", LegacyClrLane.DataContractSerializer,
                LegacyEffect.Command, LegacyReasonReaderRefused,
                "every named assembly binds and the reader still throws NullReferenceException"
                + " with nothing named; the 3.0 reader does not build the projected property")
                .InLanes(RuntimeVersion.NetFx35).WithLegacyFx(),
            LegacyClrRow.DoesNotFire("ObjectDataProvider", LegacyClrLane.DataContractSerializer,
                LegacyEffect.Command, LegacyReasonPayloadNames4x,
                "the <root type=...> envelope is resolved with Type.GetType, which does not unify")
                .InLanes(RuntimeVersion.NetFx35),

            LegacyClrRow.Fires("ObjectDataProvider", LegacyClrLane.JavaScriptSerializer,
                LegacyEffect.Command,
                "the only ObjectDataProvider reader that needs no ExpandedWrapper: its __type"
                + " strings name PresentationFramework and System directly")
                .InLanes(RuntimeVersion.NetFx35).WithLegacyFx(),
            // The SAME silent refusal FileLogTraceListener produces on this reader, and for the
            // same underlying reason: the 3.5 SimpleTypeResolver rejects a __type it cannot bind
            // by throwing "Operation is not valid due to the current state of the object" with
            // no inner exception. The --legacyfx twin above is what proves the version string
            // was the cause, because the reader itself never says so.
            LegacyClrRow.DoesNotFire("ObjectDataProvider", LegacyClrLane.JavaScriptSerializer,
                LegacyEffect.Command, LegacyReasonReaderRefused,
                "the 3.5 SimpleTypeResolver refuses the 4.0.0.0 __type without naming anything;"
                + " its --legacyfx twin firing is what identifies the version string as the cause")
                .InLanes(RuntimeVersion.NetFx35),

            // ---- the twins two negatives above never got --------------------------------
            //
            // ActivitySurrogateSelector and AxHostState were classified `deserialized-no-effect`
            // rather than `payload-names-4x-assembly`, so the pairing rule that gives every
            // identity-blocked negative a --legacyfx twin skipped them. Both name a framework
            // assembly that HAS a CLR-v2 build (System.Workflow.ComponentModel 3.0.0.0 and
            // System.Windows.Forms 2.0.0.0), so "it deserialized and did nothing" was never a
            // settled answer - it was an unasked question. These rows ask it.
            //
            // Both twins came back NEGATIVE, and both answers are better than the ones they
            // replace, because the identity is now provably not the blocker.
            //
            // NOTE: there is deliberately NO ActivitySurrogateSelector --legacyfx twin here.
            // A twin was written and then removed, because the row it would pair with cannot
            // measure what it claims: ActivitySurrogateSelector declares
            // CommandInputType.Ignored and always runs the prebuilt e.dll, whose shipped
            // ExploitClass pops a MessageBox. A LegacyEffect.Command row therefore watches a
            // fire sink this gadget never touches ON ANY RUNTIME, so `deserialized-no-effect`
            // is guaranteed regardless of CLR version and says nothing about CLR 2. The
            // pre-existing no-legacyfx row above has the same defect and is left alone pending
            // the maintainer's decision (test-integrity policy: a row is only removed with
            // approval). See dev-kitchen/todo/clr2-coverage-sweep.md.
            //
            // AxHostState: the CARRIER rebuilds - the child reports the produced object as
            // System.Windows.Forms.AxHost+State - so nothing about AxHost is 4.x. What produces
            // no effect is its default INNER gadget, TextFormattingRunProperties, which needs
            // Microsoft.PowerShell.Editor (PowerShell 3.0, a .NET 4 era install) and is simply
            // not on a CLR-2 box. AxHost.State swallows the inner failure, which is why the
            // reader reports success and the classifier sees `deserialized-no-effect`. A
            // different inner gadget is a different question, and --bgc is how to ask it.
            LegacyClrRow.DoesNotFire("AxHostState", LegacyClrLane.BinaryFormatter,
                LegacyEffect.Command, LegacyReasonNoEffect,
                "the AxHost.State carrier rebuilds on CLR 2; its default inner gadget needs"
                + " Microsoft.PowerShell.Editor, which a CLR-2 target does not have")
                .WithLegacyFx(),

            // This row puts a payload we have ALREADY PROVEN fires on CLR 2
            // (TempFileCollection, which deletes the file it is given, measured in all three
            // lanes) inside AxHost.State via --bgc. It still produces no effect there. That
            // result is deliberately scoped to this bridge/inner pair: the default
            // ActivitySurrogateSelectorFromFile AxHost carrier now fires once its Func<>
            // delegate entry names System.Core 3.5. The older conclusion that AxHost never
            // unpacks any CLR-2 stream was too broad; it mistook a swallowed inner bind failure
            // for carrier behaviour.
            LegacyClrRow.DoesNotFire("AxHostState", LegacyClrLane.BinaryFormatter,
                LegacyEffect.DeletedFile, LegacyReasonNoEffect,
                "TempFileCollection fires standalone but not through this AxHostState bridge;"
                + " this pair is a measured negative, not a claim about every inner stream")
                .With("--bgc TempFileCollection").WithLegacyFx(),

            // ---- why no BinaryFormatter/SoapFormatter chain executes code on CLR 2 --------
            //
            // These two rows exist to answer a question operators keep asking, and that the
            // ObjRef result makes urgent: ObjRef lands on CLR 2 on every reader it advertises,
            // so a rogue remoting server can hand a CLR-2 victim any BinaryFormatter payload it
            // likes - but which one actually RUNS there? The measured answer is none of ours,
            // and the reason is different for each family, which is why both are recorded.
            //
            // TextFormattingRunProperties is the gadget the published ObjRef/RogueRemotingServer
            // write-up uses as its second stage. The static pre-filter lists it as a floor
            // candidate because its payload names Microsoft.PowerShell.Editor 3.0.0.0 and no 4.x
            // version at all - but that 3.0.0.0 is the POWERSHELL product number, not a
            // framework one, and PowerShell 3.0 is a .NET 4 era install. So the blocker is the
            // target's own assembly inventory, not a version string we wrote, and no rewrite can
            // change it. This is the same trap the map records for Microsoft.VisualBasic, in the
            // opposite direction.
            LegacyClrRow.DoesNotFire("TextFormattingRunProperties", LegacyClrLane.BinaryFormatter,
                LegacyEffect.Command, LegacyReasonAssemblyAbsent,
                "its 3.0.0.0 is the PowerShell product version, not a framework one;"
                + " Microsoft.PowerShell.Editor ships with PowerShell 3.0, which needs .NET 4"),

            // GenericPrincipal is the identity/principal family's row, and the measurement
            // corrected the guess behind it. GenericPrincipal itself IS a mscorlib 2.0 type, so
            // it looked like an AxHostState-shaped case where only the inner gadget blocks. It
            // is not: the reader never gets that far, because the principal's identity MEMBER is
            // written as System.Security.Claims.ClaimsIdentity, which arrived in mscorlib 4.5.
            // Rewriting mscorlib to 2.0.0.0 therefore points the reader at a 2.0 mscorlib that
            // has no such type, and it refuses by name.
            //
            // That makes the whole family (ClaimsIdentity, ClaimsPrincipal, GenericIdentity,
            // WindowsClaimsIdentity, WindowsPrincipal) 4.5-gated at the CARRIER, not merely at
            // the inner gadget, so one measured row stands for it rather than six near-identical
            // children. It is also why a bare "the carrier is old enough" argument is not
            // evidence: the member set is part of the carrier.
            LegacyClrRow.DoesNotFire("GenericPrincipal", LegacyClrLane.BinaryFormatter,
                LegacyEffect.Command, LegacyReasonTypeAbsent,
                "the mscorlib 2.0 carrier writes a System.Security.Claims.ClaimsIdentity member,"
                + " and that type only reached mscorlib in 4.5")
                .WithLegacyFx(),

            // ---- the ActivitySurrogate chain, measured through the source-file gadget ------
            //
            // This fixture compiles a small, readable .cs file whose constructor creates a
            // test-owned directory. That lets the tier measure execution rather than treating
            // successful deserialization as a fire. --legacyfx has two gadget-specific jobs:
            // compile that carried source with the v3.5 provider, and author Func<> delegate
            // entries as System.Core 3.5.0.0. CLR 4 normally records Func<> in mscorlib, and a
            // version-only rewrite cannot express that assembly relocation.
            //
            // The default AxHost.State carrier and the larger DataSet carrier both execute on
            // CLR 2 once those two load-bearing identities are correct. The old AxHost negative
            // was therefore not evidence that AxHost ignored PropertyBagBinary; it had swallowed
            // the inner Func<> bind failure. .NET 3.5 is the honest floor because System.Core
            // 3.5 is part of the chain.
            LegacyClrRow.Fires("ActivitySurrogateSelectorFromFile", LegacyClrLane.BinaryFormatter,
                LegacyEffect.SourceCreatesDirectory,
                "the default AxHost carrier executes a CLR-v2-compiled sample whose Func"
                + " delegates name System.Core 3.5.0.0")
                .InLanes(RuntimeVersion.NetFx35).WithLegacyFx(),
            LegacyClrRow.Fires("ActivitySurrogateSelectorFromFile", LegacyClrLane.BinaryFormatter,
                LegacyEffect.SourceCreatesDirectory,
                "the minified BinaryFormatter form preserves the CLR-v2 delegate identity")
                .InLanes(RuntimeVersion.NetFx35).WithMinify().WithLegacyFx(),
            LegacyClrRow.DoesNotFire("ActivitySurrogateSelectorFromFile",
                LegacyClrLane.BinaryFormatter, LegacyEffect.SourceCreatesDirectory,
                LegacyReasonNoEffect,
                "the older variant 2 chain deserializes through AxHost.State but does not"
                + " instantiate the carried class on CLR 2")
                .InLanes(RuntimeVersion.NetFx35).With("--var 2").WithLegacyFx(),
            LegacyClrRow.Fires("ActivitySurrogateSelectorFromFile", LegacyClrLane.SoapFormatter,
                LegacyEffect.SourceCreatesDirectory,
                "the SoapFormatter wrapper executes the CLR-v2-compatible inner stream")
                .InLanes(RuntimeVersion.NetFx35).WithLegacyFx(),
            LegacyClrRow.Fires("ActivitySurrogateSelectorFromFile", LegacyClrLane.SoapFormatter,
                LegacyEffect.SourceCreatesDirectory,
                "the minified SoapFormatter form executes the CLR-v2-compatible inner stream")
                .InLanes(RuntimeVersion.NetFx35).WithMinify().WithLegacyFx(),
            LegacyClrRow.Fires("ActivitySurrogateSelectorFromFile", LegacyClrLane.LosFormatter,
                LegacyEffect.SourceCreatesDirectory,
                "the LosFormatter wrapper executes the CLR-v2-compatible inner stream")
                .InLanes(RuntimeVersion.NetFx35).WithLegacyFx(),
            LegacyClrRow.Fires("ActivitySurrogateSelectorFromFile", LegacyClrLane.LosFormatter,
                LegacyEffect.SourceCreatesDirectory,
                "the minified LosFormatter form executes the CLR-v2-compatible inner stream")
                .InLanes(RuntimeVersion.NetFx35).WithMinify().WithLegacyFx(),

            // Variant 3 preserves the historical DataSet root as an explicit alternative and
            // proves that the delegate relocation is carrier-independent.
            LegacyClrRow.Fires("ActivitySurrogateSelectorFromFile", LegacyClrLane.BinaryFormatter,
                LegacyEffect.SourceCreatesDirectory,
                "the DataSet carrier unpacks the chain, whose Func delegates name System.Core"
                + " 3.5.0.0, and the CLR-v2-compiled source creates the test directory")
                .InLanes(RuntimeVersion.NetFx35)
                .With("--var 3").WithLegacyFx(),
            LegacyClrRow.DoesNotFire("ActivitySurrogateSelectorFromFile", LegacyClrLane.BinaryFormatter,
                LegacyEffect.SourceCreatesDirectory, LegacyReasonNoEffect,
                "the identical chain whose carried assembly was built by the running 4.x"
                + " compiler; an identity rewrite owns no slot inside compiled IL")
                .InLanes(RuntimeVersion.NetFx30, RuntimeVersion.NetFx35),

            // ---- ObjectDataProvider variant 2 --------------------------------------------
            //
            // Variant 2 means something different per formatter, so it is measured per
            // formatter rather than assumed to share variant 1's answer. On XmlSerializer it
            // wraps a LosFormatter inner payload, and that inner payload is the SortedSet-based
            // TypeConfuseDelegate chain - the 4.0-only type this tier already records as
            // type-absent-on-clr2. On DataContractSerializer it is the XamlReader.Parse shape,
            // which is what variant 1 uses on XmlSerializer, so it is the interesting one.
            LegacyClrRow.DoesNotFire("ObjectDataProvider", LegacyClrLane.XmlSerializer,
                LegacyEffect.Command, LegacyReasonTypeAbsent,
                "variant 2 carries a LosFormatter inner payload built on SortedSet`1, which"
                + " does not exist before 4.0")
                .InLanes(RuntimeVersion.NetFx35).With("--var 2").WithLegacyFx(),
            // Variant 2 fails on DataContractSerializer exactly as variant 1 does, with the same
            // bare NullReferenceException after every assembly binds. So the blocker is the 3.0
            // DataContractSerializer's handling of the ExpandedWrapper graph itself, not the
            // shape carried inside it - the variant that works on XmlSerializer does not rescue
            // this reader. That is worth a row precisely because it was the plausible guess.
            LegacyClrRow.DoesNotFire("ObjectDataProvider", LegacyClrLane.DataContractSerializer,
                LegacyEffect.Command, LegacyReasonReaderRefused,
                "the same unexplained NullReferenceException variant 1 produces, so the reader,"
                + " not the payload shape, is what fails here")
                .InLanes(RuntimeVersion.NetFx35).With("--var 2").WithLegacyFx(),

            // ---- plugin envelopes -------------------------------------------------------
            // The source is the complete plugin output and the reader is the consumer API,
            // not the formatter used for the nested gadget. TempFileCollection gives every
            // envelope the same narrow, test-owned deletion effect.
            LegacyClrRow.PluginFires("ViewState", LegacyClrLane.ViewStatePageState,
                LegacyEffect.DeletedFile,
                "the Page-owned ObjectStateFormatter validates the legacy MAC with its"
                + " page-derived modifier and ViewStateUserKey before reading the object graph",
                ViewStateTestHarness.LegacyPluginArgs(false, ViewStateTestHarness.ValidationKey))
                .WithAuthenticatedBase64Controls(ViewStateTestHarness.LegacyPluginArgs(false,
                    ViewStateTestHarness.WrongValidationKey)),
            LegacyClrRow.PluginFires("ViewState", LegacyClrLane.ViewStatePageState,
                LegacyEffect.DeletedFile,
                "the authenticated legacy envelope still accepts the minified nested graph",
                ViewStateTestHarness.LegacyPluginArgs(true, ViewStateTestHarness.ValidationKey))
                .WithAuthenticatedBase64Controls(ViewStateTestHarness.LegacyPluginArgs(true,
                    ViewStateTestHarness.WrongValidationKey)),

            LegacyClrRow.PluginFires("ApplicationTrust",
                LegacyClrLane.ApplicationTrustFromXml, LegacyEffect.DeletedFile,
                "ApplicationTrust.FromXml and ExtraInfo consume the hexadecimal BinaryFormatter"
                + " blob on every CLR-v2 framework lane",
                "-g", "TempFileCollection", "--legacyfx", "--no-comment"),
            LegacyClrRow.PluginFires("ApplicationTrust",
                LegacyClrLane.ApplicationTrustFromXml, LegacyEffect.DeletedFile,
                "the minified nested graph survives the ApplicationTrust XML envelope",
                "-g", "TempFileCollection", "--legacyfx", "--no-comment", "--minify"),

            LegacyClrRow.PluginFires("TransactionManagerReenlist",
                LegacyClrLane.TransactionManagerReenlist, LegacyEffect.DeletedFile,
                "TransactionManager.Reenlist consumes the framed recovery-information blob",
                "-g", "TempFileCollection", "--legacyfx"),
            LegacyClrRow.PluginFires("TransactionManagerReenlist",
                LegacyClrLane.TransactionManagerReenlist, LegacyEffect.DeletedFile,
                "the minified nested graph survives the five-byte Reenlist frame",
                "-g", "TempFileCollection", "--legacyfx", "--minify"),

            LegacyClrRow.PluginFires("Altserialization",
                LegacyClrLane.HttpStaticObjectsCollection, LegacyEffect.DeletedFile,
                "HttpStaticObjectsCollection.Deserialize reaches the framed BinaryFormatter value",
                "-M", "HttpStaticObjectsCollection", "-g", "TempFileCollection", "--legacyfx"),
            LegacyClrRow.PluginFires("Altserialization",
                LegacyClrLane.HttpStaticObjectsCollection, LegacyEffect.DeletedFile,
                "the minified graph survives the HttpStaticObjectsCollection frame",
                "-M", "HttpStaticObjectsCollection", "-g", "TempFileCollection", "--legacyfx",
                "--minify"),
            LegacyClrRow.PluginFires("Altserialization",
                LegacyClrLane.SessionStateItemCollection, LegacyEffect.DeletedFile,
                "SessionStateItemCollection.Deserialize plus enumeration reads the framed value",
                "-M", "SessionStateItemCollection", "-g", "TempFileCollection", "--legacyfx"),
            LegacyClrRow.PluginFires("Altserialization",
                LegacyClrLane.SessionStateItemCollection, LegacyEffect.DeletedFile,
                "the minified graph survives the SessionStateItemCollection frame",
                "-M", "SessionStateItemCollection", "-g", "TempFileCollection", "--legacyfx",
                "--minify"),

            LegacyClrRow.PluginFires("Resx", LegacyClrLane.ResXResourceReader,
                LegacyEffect.DeletedFile,
                "ResXResourceReader enumerates the BinaryFormatter data element on CLR 2",
                "-M", "BinaryFormatter", "-g", "TempFileCollection", "--legacyfx"),
            LegacyClrRow.PluginFires("Resx", LegacyClrLane.ResXResourceReader,
                LegacyEffect.DeletedFile,
                "the minified graph and document survive ResXResourceReader enumeration",
                "-M", "BinaryFormatter", "-g", "TempFileCollection", "--legacyfx", "--minify"),
        };

        // How long a child gets before it is killed and the row fails loudly.
        private const int LegacyChildTimeoutMs = 90000;

        // Rows owned by a mounted private area. Same engine, same lanes, no name in a tracked
        // file. Unimplemented in a clean clone, so the compiler removes the call.
        static partial void RunPrivateLegacyRows(TestRunOptions options, LegacyClrLane lane, string childExe);

        // ---- tier orchestration ------------------------------------------------

        /// <summary>
        /// The LEGACY tier: prove which payloads land on the CLR 2 generation (.NET 2.0, 3.0,
        /// 3.5) without recompiling ysonet for it, and record the version each result earns.
        ///
        /// It stands alone like OOB rather than requiring --full, so a contributor can run it
        /// in seconds. A lane whose prerequisite is absent is a NAMED SKIP, never a pass.
        /// </summary>
        private static void RunLegacyTier(TestRunOptions options)
        {
            Console.Error.WriteLine();
            Console.Error.WriteLine("---- LEGACY tier (CLR 2.0: .NET 2.0 / 3.0 / 3.5) ----");

            // The tier's own canaries run FIRST and gate nothing else explicitly: if the child
            // is not on CLR 2, or a lane silently carries a newer reference, every row below
            // would be measuring the wrong thing.
            if (TestEnvironment.CanRun(TestEnvironment.Clr2Runtime, "LEGACY child self-checks"))
            {
                Run("The CLR-2 child reports the runtime it is really on", LegacyClrChildReportsItsRuntime);
                Run("A v4.0 runtime config is never accepted as CLR-2 evidence", LegacyClrChildRefusesAFourPointOhConfig);
                Run("A LEGACY lane cannot compile a type from a newer framework", LegacyLaneReferencesExcludeNewerAssemblies);
            }

            if (TestEnvironment.CanRun(TestEnvironment.Clr2Runtime,
                    "shipped CLR2 self-test host")
                && TestEnvironment.CanRun(TestEnvironment.NetFx3xReferenceAssemblies,
                    "shipped CLR2 self-test host"))
            {
                Run("The shipped CLR2 self-test host fires the CLR2-only workflow gadget",
                    ShippedClr2SelfTestHostFiresTheLegacyWorkflowGadget);
            }

            foreach (LegacyClrLane lane in LegacyClrLane.All)
            {
                string name = "LEGACY lane " + lane.Label;
                if (!TestEnvironment.CanRun(TestEnvironment.Clr2Runtime, name)) continue;
                if (lane.Tag != "20"
                    && !TestEnvironment.CanRun(TestEnvironment.NetFx3xReferenceAssemblies, name))
                    continue;
                Run(name, delegate { RunLegacyLane(options, lane); });
            }

            Console.Error.WriteLine();
        }

        private static void ShippedClr2SelfTestHostFiresTheLegacyWorkflowGadget()
        {
            foreach (string formatter in new[]
                { Formatters.BinaryFormatter, Formatters.SoapFormatter })
            {
                string marker = TestArtifactPath("ysonet_shipped_clr2_selftest_effect_"
                    + formatter.ToLowerInvariant());
                SafeDeleteDir(marker);
                try
                {
                    InputArgs input = new InputArgs();
                    input.Cmd = "mkdir \"" + marker + "\"";
                    // The user-facing action is simply "test locally". This CLR2-only gadget
                    // must promote that request to the shipped CLR2 victim automatically.
                    input.Test = true;
                    RunResult result = PayloadRunner.GenerateGadget(new GenerationRequest
                    {
                        GadgetName = "TypeConfuseDelegateLegacyWorkflow",
                        FormatterName = formatter,
                        OutputFormat = "",
                        InputArgs = input,
                    });
                    AssertTrue(result.Success,
                        formatter + " product CLR2 self-test route generates and launches: "
                            + result.ErrorMessage);
                    AssertTrue(WaitForDir(marker, 5000),
                        formatter + " separately shipped CLR2 host reaches the test-owned "
                            + "command sink");
                }
                finally
                {
                    SafeDeleteDir(marker);
                }
            }
        }

        private static void RunLegacyLane(TestRunOptions options, LegacyClrLane lane)
        {
            string childExe = LegacyClrChild.EnsureBuilt(lane);
            if (childExe == null)
                throw new Exception("could not build the CLR-2 child for lane " + lane.Label
                    + ": " + LegacyClrChild.LastError);

            Console.Error.WriteLine("  [legacy] lane " + lane.Label + "  compiler: "
                + LegacyClrChild.Compiler);

            var failures = new FailureCollector();
            int fired = 0, negatives = 0;
            RunLegacyRowsIn(lane, childExe, LegacyClrRows, failures, ref fired, ref negatives);

            // A private area's rows go through the same engine, so nothing about the harness
            // is duplicated there and nothing private is named here.
            RunPrivateLegacyRows(options, lane, childExe);

            Console.Error.WriteLine("  [legacy] lane " + lane.Label + ": " + fired
                + " fired, " + negatives + " measured negatives");
            if (failures.Count > 0)
                throw new Exception(string.Join("; ", failures.ToArray()));
        }

        /// <summary>
        /// Run a set of rows in one lane. Internal so a private test area can hand its own
        /// rows to exactly this engine instead of copying it.
        /// </summary>
        internal static void RunLegacyRowsIn(LegacyClrLane lane, string childExe, LegacyClrRow[] rows,
            FailureCollector failures, ref int fired, ref int negatives)
        {
            foreach (LegacyClrRow row in rows)
            {
                // A row whose reader this lane cannot execute, or that declared itself
                // inapplicable here (a 3.0 carrier in the 2.0 lane), simply does not belong to
                // the lane. That is the lane doing its job, not a skipped check.
                if (!row.AppliesTo(lane)) continue;
                if (row.IsPlugin)
                {
                    if (PluginRegistry.CreatePluginInstance(row.Plugin) == null)
                    {
                        Console.Error.WriteLine("  [skip] " + row.Describe(lane)
                            + ": plugin is not registered in this build");
                        continue;
                    }
                }
                else if (!GadgetIsRegistered(row.Gadget))
                {
                    Console.Error.WriteLine("  [skip] " + row.Describe(lane)
                        + ": gadget is not registered in this build");
                    continue;
                }
                RunLegacyRow(lane, childExe, row, failures, ref fired, ref negatives);
            }
        }

        private static void RunLegacyRow(LegacyClrLane lane, string childExe, LegacyClrRow row,
            FailureCollector failures, ref int fired, ref int negatives)
        {
            string label = row.Describe(lane);
            if (!row.IsPlugin && RefuseToFireDosGadget(row.Gadget, failures)) return;

            // The loopback rows need a listener this machine can actually accept on. An
            // absent capability is a named skip; Unknown runs the row and records that its
            // coverage is unverified.
            if (row.Effect == LegacyEffect.LoopbackConnection
                && !TestEnvironment.CanRun(TestEnvironment.LoopbackTcp, label))
                return;

            string source = row.IsPlugin ? row.Plugin : row.Gadget;
            string cell = source + "_" + row.Reader.Replace(".", "") + "_" + lane.Tag;
            string root = TestArtifactPath("ysonet_legacyclr_" + cell);
            string payloadFile = TestArtifactPath("ysonet_legacyclr_" + cell + ".bin");
            LoopbackListener listener = null;
            FireTarget marker = null;
            string victim = null, sentinel = null, directory = null, sourceFile = null;
            try
            {
                // ---- the effect fixture, and the -c value it produces ----
                string command;
                switch (row.Effect)
                {
                    case LegacyEffect.DeletedFile:
                        SafeDeleteDir(root);
                        Directory.CreateDirectory(root);
                        victim = Path.Combine(root, "victim.txt");
                        sentinel = Path.Combine(root, "sentinel.txt");
                        File.WriteAllText(victim, "this file must be deleted by the payload");
                        File.WriteAllText(sentinel, "this file must survive");
                        command = victim;   // only the victim path ever reaches the payload
                        break;
                    case LegacyEffect.LoopbackConnection:
                        listener = new LoopbackListener();
                        command = listener.TcpUrl;
                        break;
                    case LegacyEffect.CreatedDirectory:
                        SafeDeleteDir(root);
                        directory = root;
                        command = root;
                        break;
                    case LegacyEffect.Command:
                        marker = FireBackend.Create("9" + cell.Replace(".", "").Replace("-", ""));
                        command = marker.Command;
                        break;
                    case LegacyEffect.SourceCreatesDirectory:
                        // The gadget's -c is "<source>.cs;<references>", so the fixture writes
                        // the source and the effect is what its constructor does. The class is
                        // deliberately trivial and names only mscorlib types, so a failure is
                        // about the payload chain or the compiler version, never about the
                        // exploit class being clever.
                        SafeDeleteDir(root);
                        directory = root;
                        sourceFile = TestArtifactPath("ysonet_legacyclr_" + cell + "_exploit.cs");
                        SafeDelete(sourceFile);
                        File.WriteAllText(sourceFile,
                            "class E" + Environment.NewLine
                            + "{" + Environment.NewLine
                            + "    public E()" + Environment.NewLine
                            + "    {" + Environment.NewLine
                            + "        System.IO.Directory.CreateDirectory(@\"" + root + "\");"
                            + Environment.NewLine
                            + "    }" + Environment.NewLine
                            + "}" + Environment.NewLine);
                        command = sourceFile + ";System.dll,System.Core.dll";
                        break;
                    default:
                        failures.Add(label + ": unknown effect " + row.Effect);
                        return;
                }

                // ---- deserialize on CLR 2 ----
                string rowChild = row.IsPlugin
                    ? LegacyClrChild.EnsureBuilt(lane, row.Reader)
                    : childExe;
                if (rowChild == null)
                {
                    failures.Add(label + ": could not build the reader child: "
                        + LegacyClrChild.LastError);
                    return;
                }

                // ---- generate in THIS 4.7.2 process; only the bytes travel ----
                byte[] payload = null;
                if (row.AuthenticationRejectArgs != null)
                {
                    if (!row.IsPlugin || row.Effect != LegacyEffect.DeletedFile)
                    {
                        failures.Add(label + ": authenticated Base64 controls currently require a"
                            + " plugin row with the test-owned deleted-file effect");
                        return;
                    }

                    string generationError;
                    byte[] wrongKey = GenerateLegacyPluginPayload(row.Plugin,
                        row.AuthenticationRejectArgs, command, out generationError);
                    if (wrongKey == null)
                    {
                        failures.Add(label + ": wrong-key control generation failed: "
                            + generationError);
                        return;
                    }
                    if (!RunLegacyAuthenticationControl(lane, row, rowChild, payloadFile,
                        wrongKey, victim, sentinel, "wrong-key", label, failures))
                        return;

                    payload = GenerateLegacyPluginPayload(row.Plugin, row.PluginArgs, command,
                        out generationError);
                    if (payload == null)
                    {
                        failures.Add(label + ": generation failed: " + generationError);
                        return;
                    }

                    byte[] tampered;
                    try
                    {
                        tampered = Encoding.UTF8.GetBytes(ViewStateTestHarness.TamperBase64(
                            Encoding.UTF8.GetString(payload)));
                    }
                    catch (Exception ex)
                    {
                        failures.Add(label + ": could not build the tampered Base64 control: "
                            + ex.Message);
                        return;
                    }
                    if (!RunLegacyAuthenticationControl(lane, row, rowChild, payloadFile,
                        tampered, victim, sentinel, "tampered", label, failures))
                        return;
                }

                if (payload == null)
                {
                    RunResult result;
                    if (row.IsPlugin)
                    {
                        var argv = new List<string>(row.PluginArgs);
                        argv.Add("-c");
                        argv.Add(command);
                        result = PayloadRunner.RunPlugin(row.Plugin, argv.ToArray());
                    }
                    else
                    {
                        InputArgs input = new InputArgs();
                        input.Cmd = command;
                        input.Test = false;   // the effect must come from the CHILD, never from here
                        input.Minify = row.Minify;
                        // The identity rewrite is part of the CELL, not a property of the harness:
                        // a row measures "this source on this reader, WITH OR WITHOUT --legacyfx".
                        input.LegacyFx = row.LegacyFx;
                        if (row.Effect == LegacyEffect.Command) input.IsRawCmd = true;
                        if (row.ExtraArgs.Length > 0)
                            input.ExtraArguments = new List<string>(row.ExtraArgs.Split(
                                new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries));

                        result = PayloadRunner.GenerateGadget(new GenerationRequest
                        {
                            GadgetName = row.Gadget,
                            FormatterName = row.Formatter,
                            OutputFormat = "",
                            InputArgs = input,
                        });
                    }
                    if (result == null || !result.Success)
                    {
                        failures.Add(label + ": generation failed: "
                            + (result == null ? "no result" : result.ErrorMessage));
                        return;
                    }
                    payload = PayloadBytes(result.Raw);
                    if (payload == null)
                    {
                        failures.Add(label + ": unexpected payload type "
                            + (result.Raw == null ? "null" : result.Raw.GetType().Name));
                        return;
                    }
                }
                SafeDelete(payloadFile);
                File.WriteAllBytes(payloadFile, payload);

                string output = LegacyClrChild.Run(rowChild, row.Reader, payloadFile,
                    row.RootType, row.Effect == LegacyEffect.LoopbackConnection,
                    LegacyChildTimeoutMs);

                // The guard that makes every other assertion mean something. A machine
                // without CLR 2 rolls the child forward, and a 4.x fire recorded as 2.0
                // evidence would be the worst failure this tier could have.
                string clr = LegacyValue(output, "clr=");
                if (!LegacyReportsClr2(output))
                {
                    failures.Add(label + ": the child reported CLR '" + (clr ?? "(nothing)")
                        + "', not " + LegacyClrLane.Clr2VersionPrefix
                        + ", so this result is not CLR-2 evidence. Child output: " + OneLine(output));
                    return;
                }

                // ---- did the effect happen? ----
                bool observed;
                string effectDetail = "";
                switch (row.Effect)
                {
                    case LegacyEffect.DeletedFile:
                        observed = !File.Exists(victim);
                        if (observed && !File.Exists(sentinel))
                        {
                            failures.Add(label + ": the sentinel beside the target was deleted too,"
                                + " so the payload removed more than the one path it was given");
                            return;
                        }
                        break;
                    case LegacyEffect.LoopbackConnection:
                        observed = listener.Fired(LegacyEffectWaitMs);
                        break;
                    case LegacyEffect.CreatedDirectory:
                    case LegacyEffect.SourceCreatesDirectory:
                        observed = WaitForDir(directory, LegacyEffectWaitMs);
                        break;
                    default:
                        observed = marker.Wait(LegacyEffectWaitMs);
                        if (!observed) effectDetail = " (" + marker.Describe() + ")";
                        break;
                }

                bool expectFire = row.ExpectsFireIn(lane);
                string loaded = LegacyLoadedSummary(output);
                if (observed)
                {
                    // A claim about a lane is only worth anything if nothing from a newer
                    // framework was in the process while the effect happened.
                    string forbidden = LegacyForbiddenLoad(lane, output);
                    if (forbidden != null)
                    {
                        failures.Add(label + ": the effect was observed, but " + forbidden);
                        return;
                    }
                    if (!expectFire)
                    {
                        // Good news that still has to be loud: the table and the gadget's
                        // metadata are both now out of date.
                        failures.Add(label + ": this row is recorded as NOT firing on CLR 2 ("
                            + row.ExpectedReason + ") and it FIRED. That is new evidence: update"
                            + " the row and consider lowering the gadget's version floor to "
                            + lane.Label + ".");
                        return;
                    }
                    fired++;
                    if (row.IsPlugin)
                        RuntimeBuild.RecordPluginFired(row.Plugin, lane.VersionToken);
                    else
                        RuntimeBuild.RecordFired(row.Gadget, lane.VersionToken);
                    Console.Error.WriteLine("  [legacy] " + label + "  FIRED   loaded: " + loaded);
                    return;
                }

                string reason = ClassifyLegacyNoFire(output);
                if (expectFire)
                {
                    failures.Add(label + ": the effect was not observed" + effectDetail
                        + ", but this row is recorded as firing on CLR 2 (" + row.Note
                        + "). Classified as " + reason + ". Child output: " + OneLine(output));
                    return;
                }
                if (!string.Equals(reason, row.ExpectedReason, StringComparison.Ordinal))
                {
                    failures.Add(label + ": did not fire, as recorded, but for a DIFFERENT reason:"
                        + " expected " + row.ExpectedReason + ", classified " + reason
                        + ". Child output: " + OneLine(output));
                    return;
                }
                negatives++;
                Console.Error.WriteLine("  [legacy] " + label + "  NO-FIRE " + reason
                    + (PayloadNamesA4xAssembly(payload)
                        ? "  (static: the payload writes a 4.x assembly version)" : ""));
            }
            catch (Exception ex) { failures.Add(label + ": " + ex.GetType().Name + ": " + ex.Message); }
            finally
            {
                if (listener != null) listener.Dispose();
                if (marker != null) marker.Dispose();
                SafeDelete(payloadFile);
                SafeDeleteDir(root);
            }
        }

        private static byte[] GenerateLegacyPluginPayload(string plugin, string[] baseArgs,
            string command, out string error)
        {
            var argv = new List<string>(baseArgs ?? new string[0]);
            argv.Add("-c");
            argv.Add(command);
            var commandLine = new StringBuilder("-p ").Append(CommandEcho.Quote(plugin));
            foreach (string arg in argv)
                commandLine.Append(' ').Append(CommandEcho.Quote(arg));

            int exit;
            string output, stderr;
            if (!TryRunYsonet(commandLine.ToString(), out exit, out output, out stderr))
            {
                error = "ysonet.exe was not found beside the test runner";
                return null;
            }
            if (exit != 0)
            {
                error = "ysonet.exe exited " + exit + ": " + OneLine(stderr);
                return null;
            }
            byte[] payload = Encoding.UTF8.GetBytes(output.Trim());
            if (payload.Length == 0) { error = "ysonet.exe produced no payload"; return null; }
            error = null;
            return payload;
        }

        private static bool RunLegacyAuthenticationControl(LegacyClrLane lane, LegacyClrRow row,
            string child, string payloadFile, byte[] payload, string victim, string sentinel,
            string control, string label, FailureCollector failures)
        {
            SafeDelete(payloadFile);
            File.WriteAllBytes(payloadFile, payload);
            string output = LegacyClrChild.Run(child, row.Reader, payloadFile, row.RootType,
                false, LegacyChildTimeoutMs);
            if (!LegacyReportsClr2(output))
            {
                failures.Add(label + " " + control + " control: the child did not report CLR "
                    + LegacyClrLane.Clr2VersionPrefix + ". Child output: " + OneLine(output));
                return false;
            }
            if (!LegacyReportsAuthenticationFailure(output))
            {
                failures.Add(label + " " + control + " control: the reader did not report an"
                    + " authentication failure. Child output: " + OneLine(output));
                return false;
            }
            if (!File.Exists(victim) || !File.Exists(sentinel))
            {
                failures.Add(label + " " + control + " control: a rejected ViewState still"
                    + " reached the file-deletion payload");
                return false;
            }
            string forbidden = LegacyForbiddenLoad(lane, output);
            if (forbidden != null)
            {
                failures.Add(label + " " + control + " control: " + forbidden);
                return false;
            }
            return true;
        }

        private static bool LegacyReportsAuthenticationFailure(string output)
        {
            if (output == null) return false;
            return output.IndexOf("System.Security.Cryptography.CryptographicException",
                       StringComparison.OrdinalIgnoreCase) >= 0
                || output.IndexOf("Validation of viewstate MAC failed",
                       StringComparison.OrdinalIgnoreCase) >= 0
                || output.IndexOf("Unable to validate data",
                       StringComparison.OrdinalIgnoreCase) >= 0;
        }

        // How long an effect gets. Shorter than the marker budget the FULL tier uses for a
        // spawned process, because everything here is either synchronous (a deleted file, a
        // created directory) or a loopback connection, except the command rows, which are
        // given the full marker budget by the caller of Wait below.
        private const int LegacyEffectWaitMs = MarkerWaitMs;

        // ---- reading the child's report ----------------------------------------

        /// <summary>The value of a "key=" line the child printed, or null.</summary>
        internal static string LegacyValue(string output, string key)
        {
            if (output == null) return null;
            foreach (string rawLine in output.Split('\n'))
            {
                string line = rawLine.Trim();
                if (line.StartsWith(key, StringComparison.Ordinal))
                    return line.Substring(key.Length).Trim();
            }
            return null;
        }

        /// <summary>
        /// The one guard every LEGACY result depends on: did the child really run on CLR 2?
        /// One function, used by the row runner AND by the false-pass regression, so the two
        /// cannot drift apart and the test is not asserting a constant.
        /// </summary>
        internal static bool LegacyReportsClr2(string output)
        {
            string clr = LegacyValue(output, "clr=");
            return clr != null
                && clr.StartsWith(LegacyClrLane.Clr2VersionPrefix, StringComparison.Ordinal);
        }

        /// <summary>Every "loaded=name|version|gac" line, as "name version" pairs.</summary>
        private static string LegacyLoadedSummary(string output)
        {
            var parts = new List<string>();
            foreach (string rawLine in (output ?? "").Split('\n'))
            {
                string line = rawLine.Trim();
                if (!line.StartsWith("loaded=", StringComparison.Ordinal)) continue;
                string[] fields = line.Substring("loaded=".Length).Split('|');
                if (fields.Length >= 2) parts.Add(fields[0] + " " + fields[1]);
            }
            return parts.Count == 0 ? "(nothing recorded)" : string.Join(", ", parts.ToArray());
        }

        /// <summary>
        /// The first recorded load this lane forbids, or null. This is what a lane claim rests
        /// on: nothing can BLOCK a GAC load, so the child records what arrived and the parent
        /// asserts the set.
        /// </summary>
        internal static string LegacyForbiddenLoad(LegacyClrLane lane, string output)
        {
            foreach (string rawLine in (output ?? "").Split('\n'))
            {
                string line = rawLine.Trim();
                if (!line.StartsWith("loaded=", StringComparison.Ordinal)) continue;
                string[] fields = line.Substring("loaded=".Length).Split('|');
                if (fields.Length < 2) continue;
                Version version = null;
                try { version = new Version(fields[1]); } catch { }
                string why;
                if (lane.IsForbidden(fields[0], version, out why)) return why;
            }
            return null;
        }

        /// <summary>
        /// Classify WHY a payload did not land on CLR 2, from what the child reported. The
        /// order matters: an assembly-load failure that names a 4.x version is our own payload
        /// writing a version the target cannot bind, which is a different answer from the
        /// assembly genuinely being absent.
        ///
        /// Kept separate from the row runner so it can be tested against real, recorded child
        /// output without a CLR-2 machine.
        /// </summary>
        internal static string ClassifyLegacyNoFire(string output)
        {
            string error = LegacyValue(output, "error=");
            if (error == null) return LegacyReasonNoEffect;

            // Both spellings, because SOAP puts the assembly identity in a namespace URI and
            // percent-encodes the '=' ("Version%3D4.0.0.0").
            if (error.IndexOf("Version=4.", StringComparison.OrdinalIgnoreCase) >= 0
                || error.IndexOf("Version%3D4.", StringComparison.OrdinalIgnoreCase) >= 0
                || error.IndexOf("Version=10.0.0.0", StringComparison.OrdinalIgnoreCase) >= 0
                || error.IndexOf("Version%3D10.0.0.0", StringComparison.OrdinalIgnoreCase) >= 0)
                return LegacyReasonPayloadNames4x;

            if (error.IndexOf("TypeLoadException", StringComparison.Ordinal) >= 0
                || error.IndexOf("Unable to load type", StringComparison.OrdinalIgnoreCase) >= 0
                // NetDataContractSerializer's own wording. It names the type AND the assembly it
                // looked in, which reads like an absent assembly and is the opposite: the
                // assembly was found and does not have the type. This spelling only shows up
                // once the payload names an identity the target CAN bind, which is why it
                // arrived with --legacyfx rather than before it.
                || error.IndexOf("cannot load the type to deserialize", StringComparison.OrdinalIgnoreCase) >= 0
                || error.IndexOf("could not be found in assembly", StringComparison.OrdinalIgnoreCase) >= 0)
                return LegacyReasonTypeAbsent;

            if (error.IndexOf("Could not load file or assembly", StringComparison.OrdinalIgnoreCase) >= 0
                || error.IndexOf("Unable to find assembly", StringComparison.OrdinalIgnoreCase) >= 0
                || error.IndexOf("no assembly associated", StringComparison.OrdinalIgnoreCase) >= 0)
                return LegacyReasonAssemblyAbsent;

            if (error.IndexOf("was not found", StringComparison.OrdinalIgnoreCase) >= 0
                && error.IndexOf("Member ", StringComparison.Ordinal) >= 0)
                return LegacyReasonMemberShape;

            // A message that names no type, no assembly and no member cannot be turned into a
            // cause. Saying so is the honest answer; the caller prints what the BYTES show
            // beside it, clearly marked as static rather than measured.
            if (!NamesSomethingSpecific(error))
                return LegacyReasonReaderRefused;

            return LegacyReasonOther;
        }

        private static readonly string[] LegacySpecificWords =
            { "Version=", "Version%3D", "assembly", "type", "member" };

        private static bool NamesSomethingSpecific(string error)
        {
            foreach (string word in LegacySpecificWords)
                if (error.IndexOf(word, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            return false;
        }

        /// <summary>
        /// A STATIC observation about the generated bytes, printed beside a classified
        /// negative. Deliberately kept out of the classification: what the wire says is not
        /// what the runtime did, and mixing the two would turn a guess into a finding.
        /// </summary>
        internal static bool PayloadNamesA4xAssembly(byte[] payload)
        {
            if (payload == null) return false;
            // Latin1 keeps every byte a character, so a version string inside a binary stream
            // is found exactly as one inside an XML or JSON document.
            string text = Encoding.GetEncoding(28591).GetString(payload);
            return text.IndexOf("Version=4.", StringComparison.OrdinalIgnoreCase) >= 0
                || text.IndexOf("Version%3D4.", StringComparison.OrdinalIgnoreCase) >= 0
                || text.IndexOf("Version=10.0.0.0", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static byte[] PayloadBytes(object raw)
        {
            byte[] bytes = raw as byte[];
            if (bytes != null) return bytes;
            string text = raw as string;
            if (text != null) return new UTF8Encoding(false).GetBytes(text);
            return null;
        }

        private static string OneLine(string text)
        {
            if (text == null) return "";
            return text.Replace("\r", " ").Replace("\n", " | ").Trim();
        }

        // ---- LEGACY-tier self checks -------------------------------------------

        /// <summary>
        /// The tier's own canary, and the first row it runs: build the 2.0 lane's child and
        /// require it to say it is on CLR 2. Every other row's evidence depends on this being
        /// true, so it is asserted rather than assumed.
        /// </summary>
        private static void LegacyClrChildReportsItsRuntime()
        {
            LegacyClrLane lane = LegacyClrLane.All[0];
            string exe = LegacyClrChild.EnsureBuilt(lane);
            AssertTrue(exe != null, "the CLR-2 child builds: " + LegacyClrChild.LastError);

            string output = LegacyClrChild.Run(exe, "--probe", null, null, false, LegacyChildTimeoutMs);
            string clr = LegacyValue(output, "clr=");
            AssertTrue(LegacyReportsClr2(output),
                "the child reports CLR " + LegacyClrLane.Clr2VersionPrefix + ", got '" + clr + "'");
            Console.Error.WriteLine("  [legacy] CLR 2 child: " + clr
                + " (mscorlib file version " + LegacyValue(output, "mscorlibFile=") + ")");
            Console.Error.WriteLine("  [legacy] a 2.0 claim means 2.0 AT THIS SERVICING LEVEL:"
                + " installing 3.5 SP1 service-packs the 2.0 files in place, and a 2.0-only box"
                + " is not installable on modern Windows.");
        }

        /// <summary>
        /// The false-pass regression, and a state this machine can really reach: a child whose
        /// config asks for v4.0 runs on CLR 4 (measured). The harness must REJECT that result
        /// rather than record a 4.x fire as 2.0 evidence.
        /// </summary>
        private static void LegacyClrChildRefusesAFourPointOhConfig()
        {
            LegacyClrLane lane = LegacyClrLane.All[0];
            string exe = LegacyClrChild.EnsureBuilt(lane);
            AssertTrue(exe != null, "the CLR-2 child builds: " + LegacyClrChild.LastError);
            try
            {
                LegacyClrChild.WriteRuntimeConfig(exe, "v4.0");
                string output = LegacyClrChild.Run(exe, "--probe", null, null, false, LegacyChildTimeoutMs);
                string clr = LegacyValue(output, "clr=");
                AssertTrue(clr != null, "the rolled-forward child still reports a CLR");
                // The runner itself is a 4.7.2 process, so CLR 4 is always installed here and
                // a v4.0 config always resolves to it. That makes this deterministic rather
                // than best-effort: the child really does move, and the guard must say no.
                AssertTrue(!clr.StartsWith(LegacyClrLane.Clr2VersionPrefix, StringComparison.Ordinal),
                    "a v4.0 supportedRuntime really does move the child off CLR 2, got '" + clr + "'");
                AssertTrue(!LegacyReportsClr2(output),
                    "the guard every row uses REJECTS a CLR " + clr + " result as CLR-2 evidence");
                Console.Error.WriteLine("  [legacy] a v4.0 config ran on CLR " + clr
                    + ", and the guard refused it, so the .exe.config pin is not what proves the runtime");
            }
            finally
            {
                // Put the pin back before any row uses the child again.
                LegacyClrChild.WriteRuntimeConfig(exe, LegacyClrChild.PinnedRuntime);
            }
        }

        /// <summary>
        /// What proves /noconfig is doing its job. The v3.5 compiler reads csc.rsp, which
        /// auto-references System.Core.dll (3.5); without /noconfig the 2.0 lane silently
        /// gains the surface it exists to exclude. So compiling a 3.5-only type into the 2.0
        /// lane must FAIL.
        /// </summary>
        private static void LegacyLaneReferencesExcludeNewerAssemblies()
        {
            LegacyClrLane lane = LegacyClrLane.All[0];
            string probeExe = Path.Combine(AppDomain.CurrentDomain.BaseDirectory,
                "ysonet_legacyclr_refprobe_" + RunToken + ".exe");
            string error;
            // System.Func<T,TResult> lives in System.Core.dll, which is 3.5.
            bool compiled = LegacyClrChild.TryCompile(lane,
                "\r\ninternal class LegacyLaneProbe { private static Func<int, int> F; }\r\n",
                probeExe, out error);
            AssertTrue(!compiled, "the 2.0 lane must not be able to compile a 3.5-only type;"
                + " it compiled, so this lane is carrying a reference it should not have");
            AssertTrue(error != null && error.IndexOf("Func", StringComparison.Ordinal) >= 0,
                "the compiler's own diagnostic names the 3.5 type: " + error);
        }

        // ---- NORMAL-tier rows (no CLR 2 needed) --------------------------------

        /// <summary>
        /// Every lane must own at least one row, or a lane silently covers nothing while
        /// looking like coverage.
        /// </summary>
        private static void LegacyRowsCoverEveryLane()
        {
            AssertTrue(LegacyClrRows.Length > 0, "the LEGACY table has rows");
            foreach (LegacyClrLane lane in LegacyClrLane.All)
            {
                int count = 0, positives = 0;
                foreach (LegacyClrRow row in LegacyClrRows)
                {
                    if (!row.AppliesTo(lane)) continue;
                    count++;
                    if (row.ExpectsFireIn(lane)) positives++;
                }
                AssertTrue(count > 0, "lane " + lane.Label + " has at least one row");
                AssertTrue(positives > 0, "lane " + lane.Label + " has at least one row that FIRES,"
                    + " so the lane can produce a positive result and not only negatives");

                // A lane that declares a reader no row uses is the failure this tier is
                // most likely to grow: the lane looks like coverage, its child is compiled
                // with that reference set, and nothing ever executes that reader.
                foreach (string reader in lane.Readers)
                {
                    bool used = false;
                    foreach (LegacyClrRow row in LegacyClrRows)
                        if (string.Equals(row.Reader, reader, StringComparison.OrdinalIgnoreCase)
                            && row.AppliesTo(lane))
                            used = true;
                    AssertTrue(used, "lane " + lane.Label + " declares " + reader
                        + ", so at least one row must exercise it; a declared reader with no"
                        + " row is a lane that silently covers less than it claims");
                }
            }

            // A no-fire row without a classified reason would be a silently swallowed
            // negative, which is the thing this tier exists to stop.
            foreach (LegacyClrRow row in LegacyClrRows)
            {
                if (row.ExpectFire) continue;
                AssertTrue(!string.IsNullOrEmpty(row.ExpectedReason),
                    row.Describe(LegacyClrLane.All[0])
                        + " records a classified reason for not firing");
            }

            // A DataContractJsonSerializer document names no type, so a row using it must
            // supply the root type or the child cannot build anything at all.
            foreach (LegacyClrRow row in LegacyClrRows)
                if (!row.IsPlugin && row.Formatter == LegacyClrLane.DataContractJsonSerializer)
                    AssertTrue(!string.IsNullOrEmpty(row.RootType),
                        row.Gadget + " + DataContractJsonSerializer supplies a root type");

            // A row naming a formatter its gadget does not advertise would only be caught
            // when the tier runs, on a machine with CLR 2, as a generation failure. Catch it
            // here instead, where every contributor sees it.
            foreach (LegacyClrRow row in LegacyClrRows)
            {
                if (row.IsPlugin)
                {
                    IPlugin plugin = PluginRegistry.CreatePluginInstance(row.Plugin);
                    AssertTrue(plugin != null, "LEGACY row names a real plugin: " + row.Plugin);
                    List<string> versions = plugin.RuntimeVersions();
                    foreach (LegacyClrLane lane in LegacyClrLane.All)
                        if (row.AppliesTo(lane) && row.ExpectsFireIn(lane))
                            AssertTrue(versions.Contains(lane.VersionToken), row.Plugin
                                + " declares the runtime version its LEGACY row fires on: "
                                + lane.VersionToken);
                    foreach (string arg in row.PluginArgs)
                        AssertTrue(!string.Equals(arg, "-c", StringComparison.OrdinalIgnoreCase)
                                && !string.Equals(arg, "--command", StringComparison.OrdinalIgnoreCase),
                            row.Plugin + " LEGACY argv leaves -c to the effect fixture");
                    continue;
                }
                IGenerator g = GadgetRegistry.CreateGadgetInstance(row.Gadget);
                AssertTrue(g != null, "LEGACY row names a real gadget: " + row.Gadget);
                bool advertised = false;
                foreach (string entry in g.SupportedFormatters())
                    if (string.Equals(entry.Split(' ')[0], row.Formatter, StringComparison.OrdinalIgnoreCase))
                        advertised = true;
                AssertTrue(advertised, row.Gadget + " advertises " + row.Formatter
                    + "; a LEGACY row cannot name a formatter the gadget does not support");
            }
        }

        /// <summary>
        /// The classifier, against real child output recorded on CLR 2.0.50727. A measured
        /// negative has to stay visible AND keep its reason, so this pins the exact strings
        /// the three strict readers produce.
        /// </summary>
        private static void LegacyNoFireIsClassifiedNotSwallowed()
        {
            // NetDataContractSerializer, TempFileCollection, recorded 2026-08-05.
            AssertEqual(LegacyReasonPayloadNames4x, ClassifyLegacyNoFire(
                "clr=2.0.50727.9179\nerror=System.IO.FileNotFoundException: Could not load file"
                + " or assembly 'System, Version=4.0.0.0, Culture=neutral,"
                + " PublicKeyToken=b77a5c561934e089' or one of its dependencies.\n"),
                "a 4.x assembly identity we wrote outranks 'assembly not found'");

            // SoapFormatter, TempFileCollection: the identity is percent-encoded in the
            // namespace URI, which is why the classifier looks for both spellings.
            AssertEqual(LegacyReasonPayloadNames4x, ClassifyLegacyNoFire(
                "clr=2.0.50727.9179\nerror=System.Runtime.Serialization.SerializationException:"
                + " Parse Error, no assembly associated with Xml key"
                + " a1:http://schemas.microsoft.com/clr/nsassem/System.CodeDom.Compiler/"
                + "System%2C%20Version%3D4.0.0.0%2C%20Culture%3Dneutral TempFileCollection\n"),
                "the percent-encoded SOAP form is classified the same way");

            // A genuinely absent target assembly is a different answer, and not a
            // runtime-version fact at all.
            AssertEqual(LegacyReasonAssemblyAbsent, ClassifyLegacyNoFire(
                "clr=2.0.50727.9179\nerror=System.Runtime.Serialization.SerializationException:"
                + " Unable to find assembly 'Microsoft.PowerShell.Editor'.\n"),
                "an absent target assembly is a target property, not a runtime one");

            AssertEqual(LegacyReasonTypeAbsent, ClassifyLegacyNoFire(
                "clr=2.0.50727.9179\nerror=System.Runtime.Serialization.SerializationException:"
                + " Unable to load type System.Security.Claims.ClaimsIdentity\n"),
                "a type the framework does not have IS a runtime-version fact");

            // NetDataContractSerializer, TypeConfuseDelegate with --legacyfx, recorded
            // 2026-08-06. It names the type AND the assembly it looked in, which reads like an
            // absent assembly and means the opposite: System 2.0.0.0 was found and does not
            // have SortedSet<T> (that arrived in 4.0). This wording only appears once the
            // payload names an identity the target CAN bind, so it was invisible until the
            // identity rewrite existed.
            AssertEqual(LegacyReasonTypeAbsent, ClassifyLegacyNoFire(
                "clr=2.0.50727.9179\nerror=System.Runtime.Serialization.SerializationException:"
                + " The deserializer cannot load the type to deserialize because type"
                + " 'System.Collections.Generic.SortedSet`1[[System.String, mscorlib,"
                + " Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]' could"
                + " not be found in assembly 'System, Version=2.0.0.0, Culture=neutral,"
                + " PublicKeyToken=b77a5c561934e089'.\n"),
                "'found the assembly, it has no such type' is a type fact, not an assembly one");

            AssertEqual(LegacyReasonMemberShape, ClassifyLegacyNoFire(
                "clr=2.0.50727.9179\nerror=System.Runtime.Serialization.SerializationException:"
                + " Member 'm_userToken' was not found.\n"),
                "a different member shape on the 2.0 carrier is its own answer");

            // The 3.5 JavaScriptSerializer type resolver, recorded 2026-08-06. It names
            // nothing at all, so the classifier must say that rather than invent a cause.
            AssertEqual(LegacyReasonReaderRefused, ClassifyLegacyNoFire(
                "clr=2.0.50727.9179\nerror=System.InvalidOperationException: Operation is not"
                + " valid due to the current state of the object.\n"),
                "a reader that refuses without naming anything gets its own reason");

            // The static half is deliberately NOT part of the classification: the wire saying
            // "Version=10.0.0.0" is not the runtime saying why it refused.
            AssertTrue(PayloadNamesA4xAssembly(Encoding.ASCII.GetBytes(
                "{\"__type\":\"X, Microsoft.VisualBasic, Version=10.0.0.0\"}")),
                "the static note sees a 4.x-era assembly version in the generated bytes");
            AssertTrue(!PayloadNamesA4xAssembly(Encoding.ASCII.GetBytes(
                "{\"__type\":\"X, System, Version=2.0.0.0\"}")),
                "and does not fire on a 2.0 identity");

            // The trap: two carriers deserialized cleanly on CLR 2 and did nothing at all.
            // "No exception" must never be read as a fire.
            AssertEqual(LegacyReasonNoEffect, ClassifyLegacyNoFire(
                "clr=2.0.50727.9179\nresult=System.Windows.Forms.AxHost+State\ndone=1\n"),
                "a clean deserialize with no effect is a measured negative, not a pass");
        }

        /// <summary>
        /// The free pre-filter, from the finding that the most common CLR-2 blocker is an
        /// assembly VERSION string in our own payload rather than an absent type. It declares
        /// nothing and fails nothing: it prints which gadgets are worth a LEGACY row, so a
        /// contributor does not spend a child process to find out.
        /// </summary>
        private static void LegacyFloorCandidatesAreReported()
        {
            string csFixture = WriteTestArtifact("ysonet_legacy_floor_fixture.cs",
                "public class YsonetTestFixture { public YsonetTestFixture() { } }");
            string dllFixture = new Uri(typeof(NDesk.Options.OptionSet).Assembly.CodeBase).LocalPath;
            string contentFixture = ContentFixture();
            var candidates = new List<string>();
            var writes4x = new List<string>();
            try
            {
                foreach (string name in GadgetRegistry.GetGadgetNames())
                {
                    if (name == "Generic") continue;
                    if (DosPolicy.IsDosGadget(name)) continue;
                    IGenerator g = GadgetRegistry.CreateGadgetInstance(name);
                    if (g == null) continue;

                    List<string> formatters = g.SupportedFormatters();
                    if (formatters == null || formatters.Count == 0) continue;
                    string formatter = formatters[0].Split(' ')[0];

                    InputArgs ia = new InputArgs();
                    ia.Cmd = SampleInputForGadget(g.CommandInput(), csFixture, dllFixture, contentFixture);
                    RunResult r;
                    try
                    {
                        r = PayloadRunner.GenerateGadget(new GenerationRequest
                        {
                            GadgetName = name,
                            FormatterName = formatter,
                            OutputFormat = "",
                            InputArgs = ia,
                        });
                    }
                    catch (Exception) { continue; }
                    if (r == null || !r.Success || r.Raw == null) continue;

                    byte[] payload = PayloadBytes(r.Raw);
                    if (payload == null) continue;
                    // Latin1 keeps every byte a character, so a version string inside a binary
                    // stream is found exactly as one inside an XML or JSON document.
                    string text = Encoding.GetEncoding(28591).GetString(payload);
                    bool names4x = text.IndexOf("Version=4.", StringComparison.OrdinalIgnoreCase) >= 0
                        || text.IndexOf("Version%3D4.", StringComparison.OrdinalIgnoreCase) >= 0;
                    if (names4x) writes4x.Add(name);
                    else candidates.Add(name + " (-f " + formatter + ")");
                }
            }
            finally
            {
                try { File.Delete(csFixture); } catch { }
                try { File.Delete(contentFixture); } catch { }
            }

            Console.Error.WriteLine("  [info] LEGACY floor candidates (payload names no 4.x assembly"
                + " version, so a CLR-2 row may be worth measuring): "
                + (candidates.Count == 0 ? "none" : string.Join(", ", candidates.ToArray())));
            Console.Error.WriteLine("  [info] gadgets whose default payload DOES name a 4.x assembly"
                + " version (" + writes4x.Count + "): a strict reader refuses these on CLR 2, and"
                + " BinaryFormatter/LosFormatter may still unify the identity, so it is a filter,"
                + " not a verdict.");
            AssertTrue(candidates.Count + writes4x.Count > 0,
                "the pre-check inspected at least one generated payload");
        }
    }
}
