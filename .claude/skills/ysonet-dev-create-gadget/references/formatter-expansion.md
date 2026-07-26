# Formatter and serializer expansion

Read this file in full for every new gadget or material formatter change. The
goal is the maximum formatter set that can truthfully carry the named technique,
not merely the first serializer that accepts an object.

Run this expansion independently of the request or implementation plan. A plan
that omits formatter work, names only a seed formatter, or assumes a narrow set
does not waive the audit.

## Contents

- Derive the candidate inventory
- Explore each candidate
- Record the evidence matrix
- Decide support truthfully
- Implement and verify

## Derive the candidate inventory

Rebuild the inventory from current source. Take the union of:

1. constants in `ysonet/Generators/Base/IGenerator.cs`;
2. cleaned tokens from every generator's `SupportedFormatters()`, following
   `CliListing.Formatters()` and `GadgetFacetReader.CleanFormatter()`;
3. serializer families in
   `ysonet/Helpers/Serialization/SerializersHelper*.cs`; and
4. dedicated helpers, inline payload builders, package references, and plugins
   that expose another usable serialization path.

Do not use any one source alone. The constants omit some live public tokens,
while `ShowAll()` omits DataContractJsonSerializer, FastJson, and FsPickler.
ObjectStateFormatter has helpers but is intentionally not public because the
base generator treats it as equivalent to LosFormatter; verify that product
decision before proposing it as a new formatter.

At the time this guide was written, the public baseline included:

```text
BinaryFormatter, DataContractJsonSerializer, DataContractSerializer, FastJson,
FsPickler, JavaScriptSerializer, Json.NET, LosFormatter,
MessagePackTypeless, MessagePackTypelessLz4, NetDataContractSerializer,
SharpSerializerBinary, SharpSerializerXml, SoapFormatter, Xaml,
XmlSerializer, YamlDotNet
```

Treat that list as a cross-check, not as authority. Preserve version or variant
annotations separately from the cleaned formatter token.

## Explore each candidate

Start from one complete representation of the real technique. For each
serializer and each variant:

1. Identify the exact target deserializer, expected root/runtime type, output
   shape, type metadata, and target-side dependency.
2. Try direct serialization of the real graph. Use
   `GenericGenerator.Serialize()` for its supported base formatter family and
   the matching `SerializersHelper` method when it represents the actual target
   path.
3. If direct serialization fails, inspect the closest working gadgets and the
   serializer implementation. Try a serializer-specific representation of the
   same chain: public-member projections, known types, type-name metadata,
   setter ordering, surrogates, reflection-built state, exclusions, or a
   hand-built document matching the target parser.
4. Use a dedicated helper when serializer internals require cache preparation,
   private state, a custom writer, compression, or binary framing.
5. Test both minify states. When no safe minification exists, preserve a valid
   identical payload rather than changing semantics.
6. Deserialize through the actual target formatter using a test-owned sink.
   Exercise `inputArgs.Test`, but add an assertion outside paths that catch and
   only display deserialization errors.

`SerializersHelper.ShowAll()` and `TestAll()` are exploration aids only. They
swallow individual failures, do not cover every live public formatter, and do
not prove that the named runtime effect occurred.

Never replace the technique with an unrelated leaf gadget to make a serializer
work. Serializer-specific graphs may differ structurally, but they must reach
the same named primitive and observable effect.

## Record the evidence matrix

Keep a working matrix in the implementation notes or plan:

| Candidate | Variant | Construction | Output | Minify | Round-trip/effect | Status and evidence |
|---|---:|---|---|---|---|---|
| `<token>` | `1` | direct/helper/template | bytes/text | same/custom | test/sink | supported/impossible/excluded/unproven + reason |

Use exactly these status meanings:

- `supported`: generated output reaches the intended deserializer and preserves
  the named chain; both minify states generate valid output.
- `proven impossible`: a reproducible serializer or framework limitation
  remains after checking the nearest implementation and reasonable
  serializer-specific shapes.
- `product-excluded`: technically redundant or intentionally outside ysonet's
  public formatter model; cite the current product rule.
- `not yet proven`: evidence, dependency, environment, or investigation is
  incomplete. State the next experiment. Do not relabel it impossible.

A serializer exception from the first graph attempt proves only that attempt
failed. Continue through every plausible construction path before assigning
`proven impossible`.

## Decide support truthfully

Add only `supported` tokens to `SupportedFormatters()`. If no variant supports a
token, leave it out. When at least one variant supports it, keep it in the
gadget-wide union and mark each unsupported variant with `.Without(...)` plus
`GuardVariantFormatter(...)`.

Add a stable expected-failure matrix entry only for an advertised union token
that a particular variant fundamentally cannot produce. Do not create expected
failures for merely unproven work or for tokens omitted from the gadget.

Adding a brand-new public formatter token is a product change. Update constants
when appropriate, default output encoding, formatter listing/cleaning,
representative encoding coverage, help/completion surfaces, docs, and target
dependencies together.

## Implement and verify

Keep shared graph construction separate from serializer-specific emission.
Normalize formatter matching case-insensitively and return the established
shape for that formatter. Honor `inputArgs.Test` and `inputArgs.Minify` in every
branch, including dedicated helpers.

Run focused generation and deserialization for every advertised token and
variant. Add safe effect coverage for each materially different deserialization
family. Then run the Debug tier, FULL matrix, formatter listing smoke, and one
real generation for every materially different branch.

In the handoff, summarize the supported set and every impossible, excluded, or
unproven candidate with its evidence. This makes "maximum possible" auditable
without overstating support. State explicitly that the audit was performed even
when it was absent from the implementation plan.
