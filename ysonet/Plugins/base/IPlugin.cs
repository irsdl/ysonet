using NDesk.Options;
using System;
using System.Collections.Generic;

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

        // Runtime-version evidence for the complete plugin envelope and its consumer,
        // independent of the gadget selected inside it. Use RuntimeVersion.Unspecified
        // until an effect has been observed on a concrete target runtime.
        List<string> RuntimeVersions();

        OptionSet Options();
        object Run(String[] args);
    }
}
