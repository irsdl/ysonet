using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using Newtonsoft.Json.Linq;

namespace ysonet.Helpers
{
    // Checks GitHub for a newer YSoNet release. The version parsing and comparison
    // is split from the network call so it can be unit tested without a live
    // request: Check(current, fetch) takes an injectable fetcher, and the pure
    // helpers (NormalizeVersion, CompareVersions, TryParseRelease, LooksLikeVersion)
    // are internal so tests can exercise them directly.
    //
    // Releases are tagged "ysonet/vYEAR.MONTH.RELEASE" (see tag-build-release.yml),
    // so the GitHub tag_name looks like "ysonet/v2026.7.4". NormalizeVersion strips
    // the repo prefix and the leading 'v' before comparing.
    public static class UpdateChecker
    {
        // The GitHub API for the newest published release of this repo.
        public const string LatestReleaseApiUrl = "https://api.github.com/repos/irsdl/ysonet/releases/latest";
        // Human-facing page to download from, used when the API gives no html_url.
        public const string ReleasesPageUrl = "https://github.com/irsdl/ysonet/releases/latest";

        // The distinct outcomes of a check, so callers can word each case well
        // instead of guessing from booleans.
        public enum UpdateStatus
        {
            UpToDate,        // running the latest published release
            UpdateAvailable, // a newer release exists
            Ahead,           // running a version newer than the latest release (local/pre-release build)
            Unreachable,     // could not reach GitHub (offline, timeout, HTTP error)
            Unparseable      // reached GitHub but could not read a version (format changed)
        }

        // The outcome of a check. Status is authoritative; Succeeded/UpdateAvailable
        // are convenience views over it. Error carries detail for the failure cases.
        public class Result
        {
            public UpdateStatus Status;
            public string Error;
            public string CurrentVersion; // e.g. "v2026.7.4" (may be empty if unknown)
            public string LatestVersion;  // e.g. "v2026.7.5" (raw tag when Unparseable)
            public string ReleaseUrl = ReleasesPageUrl;

            // The check ran to completion and produced a comparable version.
            public bool Succeeded
            {
                get
                {
                    return Status == UpdateStatus.UpToDate
                        || Status == UpdateStatus.UpdateAvailable
                        || Status == UpdateStatus.Ahead;
                }
            }

            // A newer release than the running build is available.
            public bool UpdateAvailable { get { return Status == UpdateStatus.UpdateAvailable; } }
        }

        // Run a real check against GitHub using the current build's version.
        public static Result Check()
        {
            return Check(CurrentVersion(), DefaultFetch);
        }

        // Testable core: compare the given current version against whatever the
        // fetcher returns for the releases API. The fetch delegate returns the raw
        // response body (JSON) or throws on a network error.
        public static Result Check(string currentVersion, Func<string, string> fetch)
        {
            var r = new Result { CurrentVersion = currentVersion };
            if (fetch == null)
            {
                r.Status = UpdateStatus.Unreachable;
                r.Error = "no way to reach GitHub";
                return r;
            }

            string json;
            try
            {
                json = fetch(LatestReleaseApiUrl);
            }
            catch (Exception e)
            {
                r.Status = UpdateStatus.Unreachable;
                r.Error = e.Message;
                return r;
            }

            string tag, url;
            if (!TryParseRelease(json, out tag, out url))
            {
                // Reached GitHub but the body was not the expected release object.
                r.Status = UpdateStatus.Unparseable;
                r.Error = "could not read the latest release information";
                return r;
            }
            if (!string.IsNullOrEmpty(url))
                r.ReleaseUrl = url;

            string norm = NormalizeVersion(tag);
            if (!LooksLikeVersion(norm))
            {
                // Got a tag, but it is not a recognizable vYEAR.MONTH.RELEASE version.
                r.LatestVersion = tag; // show what GitHub actually returned
                r.Status = UpdateStatus.Unparseable;
                r.Error = "unexpected version format: " + tag;
                return r;
            }

            r.LatestVersion = "v" + norm;
            int cmp = CompareVersions(currentVersion, r.LatestVersion);
            if (cmp > 0)
                r.Status = UpdateStatus.UpdateAvailable;
            else if (cmp == 0)
                r.Status = UpdateStatus.UpToDate;
            else
                r.Status = UpdateStatus.Ahead;
            return r;
        }

        // The running build's product version, e.g. "v2026.7.4". Read from the
        // assembly informational version (set from the VERSION file at build time),
        // falling back to the numeric file version. Empty if unknown.
        public static string CurrentVersion()
        {
            try
            {
                var asm = System.Reflection.Assembly.GetExecutingAssembly();
                object[] info = asm.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false);
                if (info.Length > 0)
                {
                    string v = ((System.Reflection.AssemblyInformationalVersionAttribute)info[0]).InformationalVersion;
                    if (!string.IsNullOrEmpty(v) && v != "1.0.0.0")
                    {
                        int plus = v.IndexOf('+'); // drop a "+ysonet" build suffix
                        return plus >= 0 ? v.Substring(0, plus) : v;
                    }
                }
                System.Version fv = asm.GetName().Version;
                return (fv != null && fv.ToString() != "1.0.0.0") ? ("v" + fv) : "";
            }
            catch { return ""; }
        }

        // Pull tag_name and html_url out of the releases-API JSON. Returns false if
        // the body is not the expected object or has no tag.
        internal static bool TryParseRelease(string json, out string tag, out string url)
        {
            tag = null;
            url = null;
            if (string.IsNullOrEmpty(json))
                return false;
            try
            {
                JObject o = JObject.Parse(json);
                JToken t = o["tag_name"];
                if (t != null)
                    tag = t.ToString();
                JToken u = o["html_url"];
                if (u != null)
                    url = u.ToString();
                return !string.IsNullOrEmpty(tag);
            }
            catch
            {
                return false;
            }
        }

        // Strip a leading repo prefix ("ysonet/") and a leading 'v' so
        // "ysonet/v2026.7.4" and "v2026.7.4" both become "2026.7.4".
        internal static string NormalizeVersion(string raw)
        {
            if (string.IsNullOrEmpty(raw))
                return "";
            string s = raw.Trim();
            int slash = s.LastIndexOf('/');
            if (slash >= 0)
                s = s.Substring(slash + 1);
            s = s.TrimStart('v', 'V');
            return s.Trim();
        }

        // True when a normalized string is a dotted numeric version (e.g. "2026.7.4"),
        // which is the only shape CompareVersions can trust. A tag GitHub returns in
        // any other shape means the release format changed.
        internal static bool LooksLikeVersion(string normalized)
        {
            if (string.IsNullOrEmpty(normalized))
                return false;
            return Regex.IsMatch(normalized, @"^\d+(\.\d+)*$");
        }

        // Compare two dotted numeric versions after normalizing. Returns > 0 when
        // latest is newer than current, 0 when equal, < 0 when current is newer.
        // Missing trailing parts count as 0, so "v2026.7" == "v2026.7.0".
        internal static int CompareVersions(string current, string latest)
        {
            int[] pc = ParseParts(NormalizeVersion(current));
            int[] pl = ParseParts(NormalizeVersion(latest));
            int n = Math.Max(pc.Length, pl.Length);
            for (int i = 0; i < n; i++)
            {
                int vc = i < pc.Length ? pc[i] : 0;
                int vl = i < pl.Length ? pl[i] : 0;
                if (vl != vc)
                    return vl > vc ? 1 : -1;
            }
            return 0;
        }

        // Split "2026.7.4" into [2026, 7, 4]. Keeps only the leading digits of each
        // part so an unexpected suffix (e.g. "4-beta") does not throw.
        private static int[] ParseParts(string v)
        {
            if (string.IsNullOrEmpty(v))
                return new int[0];
            string[] chunks = v.Split('.');
            var parts = new List<int>();
            foreach (string chunk in chunks)
            {
                int val = 0;
                foreach (char ch in chunk.Trim())
                {
                    if (ch < '0' || ch > '9')
                        break;
                    val = (val * 10) + (ch - '0');
                }
                parts.Add(val);
            }
            return parts.ToArray();
        }

        // The default network fetch: a plain GitHub API GET. GitHub requires a
        // User-Agent and (on this framework) TLS 1.2, both set here.
        private static string DefaultFetch(string url)
        {
            try { ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12; }
            catch { /* older frameworks may not define it; the default may still work */ }

            var req = (HttpWebRequest)WebRequest.Create(url);
            req.UserAgent = "ysonet-update-check";
            req.Accept = "application/vnd.github+json";
            req.Timeout = 10000;
            req.ReadWriteTimeout = 10000;

            using (var resp = (HttpWebResponse)req.GetResponse())
            using (var stream = resp.GetResponseStream())
            using (var reader = new StreamReader(stream))
            {
                return reader.ReadToEnd();
            }
        }
    }
}
