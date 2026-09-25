using Microsoft.Win32;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using ysonet.Helpers;

namespace ysonet.Tests
{
    // Reporting only. No payload bytes, commands, paths, exception messages or
    // private module names enter this public document. Unknown dimensions stay null.
    internal static class RuntimeEvidence
    {
        internal sealed class Cell
        {
            public string kind, module, formatter, configuration, targetRuntime, source;
            public int? variant;
            public bool? minify;
            public string generation = "not-tested", deserialization = "not-tested", effect = "not-tested";
            public string reason = "No observation recorded for this configuration";
            public string[] requirements;
        }

        private static readonly List<Cell> Cells = new List<Cell>();
        private static HashSet<string> Gadgets, Plugins;
        private static readonly object Sync = new object();

        internal static Cell NewCell(string kind, string module, string formatter, int? variant, bool? minify,
            string configuration, string runtime = null, [CallerMemberName] string source = null)
        {
            lock (Sync)
            {
                if (Gadgets == null)
                {
                    Gadgets = new HashSet<string>(CliListing.Gadgets(), StringComparer.OrdinalIgnoreCase);
                    Plugins = new HashSet<string>(CliListing.Plugins(), StringComparer.OrdinalIgnoreCase);
                }
                var cell = new Cell { kind = kind, module = module, formatter = formatter, variant = variant,
                    minify = minify, configuration = configuration, targetRuntime = runtime ?? RuntimeBuild.Token(),
                    source = "ysonet.Tests.Tests." + source };
                if (kind == "gadget" && Gadgets.Contains(module))
                {
                    var g = GadgetRegistry.CreateGadgetInstance(module);
                    cell.requirements = GadgetFacetReader.Expand(g).Where(c => variant == null || c.VariantNumber == variant)
                        .SelectMany(c => c.Requirements).Distinct().ToArray();
                    Cells.Add(cell);
                }
                else if (kind == "plugin" && Plugins.Contains(module)) Cells.Add(cell);
                return cell;
            }
        }

        internal static void Generation(string module, string formatter, int? variant, bool minify,
            bool success, bool expectedRejection, [CallerMemberName] string source = null)
        {
            var cell = NewCell("gadget", module, formatter, variant, minify, "generation-matrix", source: source);
            cell.generation = success ? "verified" : expectedRejection ? "expected-rejection" : "failed";
            cell.reason = success ? "Nonempty payload produced" : expectedRejection ? "Declared limitation asserted" : "Generation failed";
        }

        internal static void ObservedEffect(string kind, string module, string runtime, string formatter,
            int? variant, bool? minify, string source)
        {
            var cell = NewCell(kind, module, formatter, variant, minify, source, runtime, source);
            cell.targetRuntime = runtime;
            cell.effect = "verified";
            cell.reason = "Existing test-owned sink observed the effect; other phases were not separately recorded";
        }

        internal static string Document(IEnumerable<Cell> observations = null)
        {
            // Include every advertised cell, including DoS and tiers not run. An
            // unobserved declaration cannot inherit a sibling's successful result.
            List<Cell> all;
            lock (Sync) all = new List<Cell>(observations ?? Cells);
            foreach (string name in CliListing.Gadgets())
                foreach (var capability in GadgetFacetReader.Expand(GadgetRegistry.CreateGadgetInstance(name)))
                    foreach (string formatter in capability.Formatters)
                        foreach (bool minify in new[] { false, true })
                            if (!all.Any(c => c.kind == "gadget" && c.module == name && c.formatter == formatter
                                && c.variant == capability.VariantNumber && c.minify == minify && c.configuration == "generation-matrix"))
                                all.Add(new Cell { kind = "gadget", module = name, formatter = formatter,
                                    variant = capability.VariantNumber, minify = minify, configuration = "generation-matrix",
                                    targetRuntime = RuntimeBuild.Token(), requirements = capability.Requirements.ToArray(),
                                    source = "ysonet.Tests.Tests.GadgetFullMatrixGenerates" });
            foreach (string name in CliListing.Plugins())
                if (!all.Any(c => c.kind == "plugin" && c.module == name))
                    all.Add(new Cell { kind = "plugin", module = name, configuration = "unobserved", targetRuntime = RuntimeBuild.Token() });
            return JsonConvert.SerializeObject(new
            {
                schemaVersion = 1, complete = true, toolVersion = UpdateChecker.CurrentVersion(),
                completedUtc = DateTime.UtcNow.ToString("o"), verdict = TestEnvironment.Verdict,
                environment = new { reportedOsVersion = Environment.OSVersion.VersionString, windowsBuild = WindowsBuild(),
                    osBits = Environment.Is64BitOperatingSystem ? 64 : 32, processBits = IntPtr.Size * 8,
                    clrVersion = Environment.Version.ToString(), frameworkRelease = RuntimeBuild.ReleaseValue(), runtime = RuntimeBuild.Token() },
                prerequisites = TestEnvironment.RecordedCapabilities().Select(t => new { name = t.Token, state = t.State.ToString() }).ToArray(),
                cells = all.OrderBy(c => c.kind).ThenBy(c => c.module).ThenBy(c => c.formatter).ThenBy(c => c.variant).ThenBy(c => c.minify).ThenBy(c => c.configuration).ToArray()
            }, new JsonSerializerSettings { Formatting = Formatting.Indented, StringEscapeHandling = StringEscapeHandling.EscapeNonAscii });
        }

        // Environment.OSVersion can report a Windows compatibility version when
        // the host has no supportedOS manifest. Keep that value labelled and record
        // the installed build independently, without a hostname or local path.
        private static string WindowsBuild()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    if (key == null) return null;
                    string build = key.GetValue("CurrentBuildNumber") as string;
                    object revision = key.GetValue("UBR");
                    return build == null ? null : build + (revision == null ? "" : "." + revision);
                }
            }
            catch { return null; }
        }

        internal static void Write()
        {
            string path = Environment.GetEnvironmentVariable("YSONET_RUNTIME_EVIDENCE_FILE");
            if (string.IsNullOrEmpty(path)) return;
            string text = Document();
            string temp = path + ".tmp";
            File.WriteAllText(temp, text, new UTF8Encoding(false));
            if (File.Exists(path)) File.Delete(path);
            File.Move(temp, path);
        }
    }
}
