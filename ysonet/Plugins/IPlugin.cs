using System;
using NDesk.Options;

namespace ysonet.Plugins
{
    public interface IPlugin
    {
        string Name();
        string Description();
        string Credit();
        OptionSet Options();
        object Run(String[] args);
    }
}
