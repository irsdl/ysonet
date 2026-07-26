using System;
using System.Collections.Generic;
using Microsoft.Win32;
using ysonet.Generators;
using ysonet.Helpers;

namespace ysonet.Tests
{
    // Which .NET Framework build this test run is executing on, plus the record of
    // which gadgets actually fired on it.
    //
    // Why this exists: the runtime version facet is only worth anything if the
    // declarations are earned. The FULL suite already fires most of the catalog into
    // test-owned sinks, so a run is direct evidence of "this payload works on build
    // X" - it just was not written down anywhere. This turns the run into the record,
    // instead of asking anyone to re-test by hand.
    //
    // The build comes from the documented registry value, not from
    // Environment.Version (which reports the CLR, 4.0.30319 for every 4.x) and not
    // from the target framework the tests were compiled against.
    internal static class RuntimeBuild
    {
        private const string NdpKey = @"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full";

        private static bool _probed;
        private static string _token;     // a RuntimeVersion token, or null when unknown
        private static int _release;

        // Microsoft's documented "Release value >= N means this version" table, newest
        // first. A build newer than everything listed still matches the highest entry,
        // which is why the docs say to test with >= rather than equality.
        private static readonly int[] ReleaseThresholds =
        {
            533320,  // 4.8.1
            528040,  // 4.8
            461808,  // 4.7.2
            461308,  // 4.7.1
            460798,  // 4.7
            394802,  // 4.6.2
            394254,  // 4.6.1
            393295,  // 4.6
            379893,  // 4.5.2
            378675,  // 4.5.1
            378389,  // 4.5
        };

        private static readonly string[] ThresholdTokens =
        {
            RuntimeVersion.NetFx481, RuntimeVersion.NetFx48,
            RuntimeVersion.NetFx472, RuntimeVersion.NetFx471, RuntimeVersion.NetFx47,
            RuntimeVersion.NetFx462, RuntimeVersion.NetFx461, RuntimeVersion.NetFx46,
            RuntimeVersion.NetFx452, RuntimeVersion.NetFx451, RuntimeVersion.NetFx45,
        };

        // The RuntimeVersion token for the running build, or null when the registry
        // does not say (a non-Windows host, or a 4.x older than 4.5). Callers must
        // treat null as "cannot establish evidence" and skip with a reason, never as
        // a pass.
        public static string Token()
        {
            Probe();
            return _token;
        }

        public static int ReleaseValue()
        {
            Probe();
            return _release;
        }

        // ".NET Framework 4.8.1 (Release 533325)" for the run header and failures.
        public static string Describe()
        {
            Probe();
            if (_token == null)
                return "unknown .NET Framework build (no " + NdpKey + " Release value)";
            return GadgetFacetReader.Label(_token) + " (Release " + _release + ")";
        }

        private static void Probe()
        {
            if (_probed)
                return;
            _probed = true;
            try
            {
                using (RegistryKey key = RegistryKey
                    .OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                    .OpenSubKey(NdpKey))
                {
                    if (key == null)
                        return;
                    object value = key.GetValue("Release");
                    if (value == null)
                        return;
                    _release = Convert.ToInt32(value);
                }
            }
            catch
            {
                return; // an unreadable registry is "unknown", never a guess
            }

            for (int i = 0; i < ReleaseThresholds.Length; i++)
            {
                if (_release >= ReleaseThresholds[i])
                {
                    _token = ThresholdTokens[i];
                    return;
                }
            }
        }

        // ---- What fired on this build -----------------------------------------

        private static readonly HashSet<string> _fired =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Called by every fire helper the moment a payload's effect is observed
        // (marker file, listener hit, created directory, OOB callback). Gadgets only:
        // plugins carry no facets, so they have nothing to record against.
        public static void RecordFired(string gadgetName)
        {
            if (!string.IsNullOrEmpty(gadgetName))
                lock (_fired) _fired.Add(gadgetName);
        }

        public static List<string> FiredGadgets()
        {
            lock (_fired)
            {
                var list = new List<string>(_fired);
                list.Sort(StringComparer.OrdinalIgnoreCase);
                return list;
            }
        }

        public static bool AnythingFired()
        {
            lock (_fired) return _fired.Count > 0;
        }
    }
}
