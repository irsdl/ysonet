using NDesk.Options;
using System;

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
