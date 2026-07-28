using NDesk.Options;
using System;

namespace ysonet.Plugins
{
    public interface IPlugin
    {
        string Name();
        string Description();
        string Credit();

        // True when this plugin must not appear in any listing until
        // --display-private (--prv). It still runs normally when named with -p.
        // Return false unless the plugin is unpublished research kept in the
        // git-ignored Plugins\Private\ folder.
        bool IsPrivate();

        OptionSet Options();
        object Run(String[] args);
    }
}
