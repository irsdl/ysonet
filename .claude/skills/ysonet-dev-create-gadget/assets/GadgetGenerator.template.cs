// Draft template for a new ysonet gadget.
//
// Replace __NAME__ first. The empty or uncategorized members below are honest
// draft defaults, not a finished gadget. Resolve every TODO and implement the
// named real chain before adding the file to ysonet.csproj. Returning an
// unrelated gadget would make generation tests pass while publishing false
// behavior.

using NDesk.Options;
using System;
using System.Collections.Generic;
using ysonet.Helpers;

namespace ysonet.Generators
{
    public class __NAME__Generator : GenericGenerator
    {
        // TODO: Use ysonet-categorize-gadget to replace the unknown axes.
        // Explicit Uncategorized input prevents the draft from implying that
        // the base ShellCommand default is verified evidence.
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithInputs(PayloadInput.Uncategorized);
        }

        // TODO: Add verified original researcher names.
        public override string Finders()
        {
            return "";
        }

        // TODO: Add only formatters produced by the real implementation.
        public override List<string> SupportedFormatters()
        {
            return new List<string>();
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            throw new NotImplementedException(
                "__NAME__ real gadget chain has not been implemented.");
        }

        // OPTIONAL CREDIT BLOCK. Keep only when the implementer and finder
        // credits differ.
        //
        // public override string Contributors()
        // {
        //     return "VERIFIED IMPLEMENTER";
        // }

        // OPTIONAL HELP BLOCK. Put concise purpose, target dependencies, CVEs,
        // and public references here.
        //
        // public override string AdditionalInfo()
        // {
        //     return "VERIFIED PURPOSE AND TARGET NOTES";
        // }

        // OPTIONAL LABEL BLOCK. Use GadgetTags constants only.
        //
        // public override List<string> Labels()
        // {
        //     return new List<string> { GadgetTags.Independent };
        // }

        // OPTIONAL VARIANT BLOCK. Keep Options(), Variants(), the field, and the
        // GuardVariantFormatter call together. Parse all invalid values clearly.
        //
        // private int variant_number = 1;
        //
        // public override OptionSet Options()
        // {
        //     return new OptionSet
        //     {
        //         {
        //             "var|variant=",
        //             "VERIFIED VARIANT HELP",
        //             v =>
        //             {
        //                 int parsed;
        //                 if (!int.TryParse(v, out parsed))
        //                     throw new OptionException(
        //                         "variant must be a number", "variant");
        //                 variant_number = parsed;
        //             }
        //         }
        //     };
        // }
        //
        // public override List<GadgetVariant> Variants()
        // {
        //     return new List<GadgetVariant>
        //     {
        //         new GadgetVariant(1, "VERIFIED VARIANT LABEL")
        //     };
        // }

        // OPTIONAL BRIDGE BLOCK. Keep only when this gadget consumes another
        // gadget's serialized payload. Also add GadgetTags.Bridged to Labels()
        // and handle BridgedPayload in Generate().
        //
        // public override string SupportedBridgedFormatter()
        // {
        //     return Formatters.BinaryFormatter;
        // }

        // OPTIONAL INPUT BLOCK. Delete to keep the ShellCommand default after
        // evidence proves that -c is a shell command.
        //
        // public override CommandInputType CommandInput()
        // {
        //     return CommandInputType.FilePath;
        // }

        // REAL GENERATE PATTERNS. Move only the relevant shape into Generate().
        //
        // GuardVariantFormatter(variant_number, formatter);
        //
        // if (formatter.Equals(Formatters.BinaryFormatter,
        //     StringComparison.OrdinalIgnoreCase))
        // {
        //     object graph = BuildRealGraph(inputArgs);
        //     return Serialize(graph, formatter, inputArgs);
        // }
        //
        // if (formatter.Equals(Formatters.JsonNet,
        //     StringComparison.OrdinalIgnoreCase))
        // {
        //     string payload = BuildRealJson(inputArgs);
        //     if (inputArgs.Minify)
        //         payload = JsonMinifier.Minify(payload, null, null);
        //     if (inputArgs.Test)
        //         SerializersHelper.JsonNet_deserialize(payload);
        //     return payload;
        // }
    }
}
