using System;

namespace ysonet.Tests
{
    // A test-owned TCP endpoint on an ephemeral loopback port. Payloads that call out
    // (an SSRF-style fetch, a remoting connection, an external DTD) are pointed at it,
    // and the accepted connection is the proof the payload fired.
    //
    // It lives in its own file so the loopback CAPABILITY probe in TestEnvironment and
    // the payload rows that depend on it exercise the same implementation. A probe
    // built on a different socket would be measuring something the rows do not use.
    internal sealed class LoopbackListener : IDisposable
    {
        private readonly System.Net.Sockets.TcpListener _listener;
        private readonly System.Threading.Thread _thread;
        private volatile bool _hit;
        private volatile bool _stop;
        public int Port { get; private set; }

        // Test seam: how many listeners this process has created. A gating test asserts
        // the count does NOT move when a capability is absent, which is how it proves a
        // helper stopped before its network action instead of merely failing quietly.
        internal static int CreatedCount;

        public LoopbackListener()
        {
            _listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            _listener.Start();
            Port = ((System.Net.IPEndPoint)_listener.LocalEndpoint).Port;
            CreatedCount++;
            _thread = new System.Threading.Thread(AcceptLoop);
            _thread.IsBackground = true;
            _thread.Start();
        }

        private void AcceptLoop()
        {
            try
            {
                while (!_stop)
                {
                    var client = _listener.AcceptTcpClient();
                    _hit = true;
                    try { client.Close(); } catch { }
                }
            }
            catch { /* Stop() unblocks AcceptTcpClient with an exception */ }
        }

        public string HttpUrl { get { return "http://127.0.0.1:" + Port + "/x"; } }
        public string HttpsUrl { get { return "https://127.0.0.1:" + Port + "/x"; } }
        public string TcpUrl { get { return "tcp://127.0.0.1:" + Port + "/x"; } }

        public bool Fired(int totalMs)
        {
            int waited = 0;
            while (waited < totalMs && !_hit) { System.Threading.Thread.Sleep(50); waited += 50; }
            return _hit;
        }

        public void Dispose()
        {
            _stop = true;
            try { _listener.Stop(); } catch { }
        }
    }
}
