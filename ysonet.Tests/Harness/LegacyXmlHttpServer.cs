using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace ysonet.Tests
{
    /// <summary>
    /// A test-owned HTTP endpoint on an ephemeral loopback port that both ANSWERS and
    /// RECORDS. LoopbackListener accepts a connection and closes it, which is enough to
    /// prove "something called out"; this one is needed where a row has to prove WHAT was
    /// requested, or has to hand the target a document to carry on with:
    ///
    ///  - the external-DTD rows assert the exact request target, so a payload that fetched
    ///    some other URL cannot pass as a hit;
    ///  - an out-of-band chain needs the first request to be ANSWERED with a real DTD before
    ///    the second request can ever happen.
    ///
    /// It is a plain TcpListener on 127.0.0.1:0, exactly like LoopbackListener, so it needs
    /// the same loopback capability the shared probe measures and no HttpListener URL ACL.
    ///
    /// Every route is registered before the payload runs. An unregistered path is answered
    /// 404 and still recorded, because "the target asked for the wrong thing" is a result
    /// worth seeing rather than a timeout.
    /// </summary>
    internal sealed class LegacyXmlHttpServer : IDisposable
    {
        private readonly TcpListener _listener;
        private readonly Thread _thread;
        private readonly Dictionary<string, string> _routes =
            new Dictionary<string, string>(StringComparer.Ordinal);
        // Per route, because one caller's answer has to be believed by a DTD parser and
        // another's by the WPF markup loader, which picks its converter by CONTENT TYPE
        // (MimeObjectFactory maps application/xaml+xml; anything else is fetched and
        // dropped). Serving one fixed type would silently make that row untestable.
        private readonly Dictionary<string, string> _contentTypes =
            new Dictionary<string, string>(StringComparer.Ordinal);
        private const string DefaultContentType = "application/xml-dtd";
        private readonly List<string> _requests = new List<string>();
        private volatile bool _stop;

        public int Port { get; private set; }

        public LegacyXmlHttpServer()
        {
            _listener = new TcpListener(IPAddress.Loopback, 0);
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _thread = new Thread(AcceptLoop) { IsBackground = true };
            _thread.Start();
        }

        /// <summary>An absolute URL on this server for a path like "/x.dtd".</summary>
        public string UrlFor(string path)
        {
            return "http://127.0.0.1:" + Port + path;
        }

        /// <summary>
        /// Answer <paramref name="path"/> with <paramref name="body"/> (UTF-8), as an
        /// external DTD.
        /// </summary>
        public void Serve(string path, string body)
        {
            Serve(path, body, DefaultContentType);
        }

        /// <summary>
        /// Same, under an explicit Content-Type. Use this when the CLIENT decides what to do
        /// with the response by its content type.
        /// </summary>
        public void Serve(string path, string body, string contentType)
        {
            lock (_routes)
            {
                _routes[path] = body ?? "";
                _contentTypes[path] = string.IsNullOrEmpty(contentType) ? DefaultContentType : contentType;
            }
        }

        /// <summary>Every request target seen so far, in arrival order.</summary>
        public string[] Requests
        {
            get { lock (_requests) return _requests.ToArray(); }
        }

        /// <summary>
        /// Wait up to <paramref name="totalMs"/> for a request whose target starts with
        /// <paramref name="prefix"/>, and return that target (null on timeout). Returning the
        /// whole target is what lets a caller assert the query string an exfiltration chain
        /// put in it.
        /// </summary>
        public string WaitForRequest(string prefix, int totalMs)
        {
            int waited = 0;
            while (true)
            {
                foreach (string target in Requests)
                    if (target.StartsWith(prefix, StringComparison.Ordinal))
                        return target;
                if (waited >= totalMs)
                    return null;
                Thread.Sleep(50);
                waited += 50;
            }
        }

        private void AcceptLoop()
        {
            try
            {
                while (!_stop)
                {
                    TcpClient client = _listener.AcceptTcpClient();
                    // One short-lived thread per connection: the DTD parser can hold the
                    // first response open while it opens the second request, so a serial
                    // loop would deadlock the very chain these rows exist to observe.
                    var worker = new Thread(delegate () { Handle(client); }) { IsBackground = true };
                    worker.Start();
                }
            }
            catch { /* Stop() unblocks AcceptTcpClient with an exception */ }
        }

        private void Handle(TcpClient client)
        {
            try
            {
                using (client)
                using (NetworkStream stream = client.GetStream())
                {
                    stream.ReadTimeout = 5000;
                    string requestLine = ReadRequestHead(stream);
                    if (requestLine == null)
                        return;

                    string target = TargetOf(requestLine);
                    lock (_requests) _requests.Add(target);

                    string body;
                    bool known;
                    string contentType;
                    lock (_routes)
                    {
                        known = _routes.TryGetValue(PathOf(target), out body);
                        if (!known || !_contentTypes.TryGetValue(PathOf(target), out contentType))
                            contentType = DefaultContentType;
                    }
                    if (!known) body = "";

                    byte[] payload = new UTF8Encoding(false).GetBytes(body);
                    string head = (known ? "HTTP/1.1 200 OK\r\n" : "HTTP/1.1 404 Not Found\r\n")
                        + "Content-Type: " + contentType + "\r\n"
                        + "Content-Length: " + payload.Length + "\r\n"
                        + "Connection: close\r\n\r\n";
                    byte[] headBytes = Encoding.ASCII.GetBytes(head);
                    stream.Write(headBytes, 0, headBytes.Length);
                    if (payload.Length > 0)
                        stream.Write(payload, 0, payload.Length);
                    stream.Flush();
                }
            }
            catch { /* a client that hangs up mid-request is not a test failure */ }
        }

        // Read up to the blank line that ends the request head. Only the first line is used;
        // the rest is drained so the client does not see a reset before it finished writing.
        private static string ReadRequestHead(Stream stream)
        {
            var head = new StringBuilder();
            var one = new byte[1];
            while (head.Length < 8192)
            {
                int read = stream.Read(one, 0, 1);
                if (read <= 0)
                    break;
                head.Append((char)one[0]);
                if (head.Length >= 4
                    && head[head.Length - 1] == '\n' && head[head.Length - 2] == '\r'
                    && head[head.Length - 3] == '\n' && head[head.Length - 4] == '\r')
                    break;
            }

            string text = head.ToString();
            int eol = text.IndexOf("\r\n", StringComparison.Ordinal);
            if (eol < 0)
                return text.Length == 0 ? null : text;
            return text.Substring(0, eol);
        }

        // "GET /x.dtd?a=b HTTP/1.1" -> "/x.dtd?a=b"
        private static string TargetOf(string requestLine)
        {
            string[] parts = requestLine.Split(' ');
            return parts.Length >= 2 ? parts[1] : requestLine;
        }

        private static string PathOf(string target)
        {
            int q = target.IndexOf('?');
            return q < 0 ? target : target.Substring(0, q);
        }

        public void Dispose()
        {
            _stop = true;
            try { _listener.Stop(); } catch { }
        }
    }
}
