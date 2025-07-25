using System;

namespace ysonet.Helpers
{
    public class Debugging
    {
        public static void ShowErrors(InputArgs inputArgs, Exception err)
        {
            if (inputArgs.IsDebugMode)
            {
                Console.WriteLine(err.StackTrace);
            }
        }
    }
}
