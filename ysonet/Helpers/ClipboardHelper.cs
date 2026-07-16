using System;
using System.Threading;

namespace ysonet.Helpers
{
    // Copies text to the Windows clipboard. System.Windows.Forms.Clipboard needs a
    // single-threaded apartment (STA), and a console app runs MTA, so the copy is
    // marshalled onto a short-lived STA thread (the same approach ClipboardPlugin
    // uses). Best effort: returns false with a reason instead of throwing, so the
    // interactive UI can report it without crashing.
    public static class ClipboardHelper
    {
        public static bool TrySetText(string text, out string error)
        {
            error = null;
            if (text == null)
                text = "";

            string err = null;
            bool ok = false;
            Thread t = new Thread(delegate ()
            {
                // OpenClipboard fails ("Requested Clipboard operation did not
                // succeed") when another process momentarily holds the clipboard, so
                // retry a few times with a short pause - the standard mitigation.
                for (int attempt = 0; attempt < 10 && !ok; attempt++)
                {
                    try
                    {
                        // SetText throws on an empty string; use Clear() for that case.
                        if (text.Length == 0)
                            System.Windows.Forms.Clipboard.Clear();
                        else
                            System.Windows.Forms.Clipboard.SetText(text);
                        ok = true;
                    }
                    catch (Exception e)
                    {
                        err = e.Message;
                        Thread.Sleep(15);
                    }
                }
            });
            t.SetApartmentState(ApartmentState.STA);
            t.Start();
            t.Join();

            error = err;
            return ok;
        }
    }
}
