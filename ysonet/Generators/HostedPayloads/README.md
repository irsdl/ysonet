# HostedPayloads

Gadgets here are payload bodies, not sinks. Each one builds the content that gets
executed, then hands it to another gadget's chain to carry and trigger. They define no
serialized type of their own, so they cannot be serialized alone.

Membership test: does `Generate()` pass another generator's object to `Serialize()`?
If yes, the file belongs here. If the generator serializes a type it defines (its own
`*Marshal` class or a real framework type), it stays in `Generators/`, even when it
nests another gadget's payload inside. Having a `Variants()` list or a `var/variant`
option has nothing to do with it.

Every gadget here is tagged `GadgetTags.Hosted`.

Current members, both delivering a XAML `ResourceDictionary`:

| Gadget | Host chain (variant 1) | Host chain (variant 2) |
| --- | --- | --- |
| `XamlAssemblyLoadFromFile` | `TypeConfuseDelegateGenerator.GetXamlGadget` | `TextFormattingRunPropertiesMarshal` |
| `ActivitySurrogateDisableTypeCheck` | `TypeConfuseDelegateGenerator.GetXamlGadget` | `TextFormattingRunPropertiesMarshal` |

Notes for adding one:

- Keep the namespace `ysonet.Generators`. The folder is for humans; discovery is by
  reflection over `IGenerator` and ignores namespaces.
- Add the file to `ysonet.csproj` `<Compile Include="Generators\HostedPayloads\...">`.
- The host chain decides the formatter set. `GetXamlGadget` returns a live closed-generic
  sorted container, which SoapFormatter's stock writer rejects. For roots whose direct SOAP
  document is implemented, call `SerializeSoapXamlGadget` instead; it authors through
  non-generic aliases and exposes the native CLR4 TCD types to the target. An unsupported
  document shape must be refused explicitly.
- `GetXamlGadget(xaml, container)` picks that root: 1 `SortedSet` (default, the shipped
  bytes), 2 `SortedDictionary`, 3 `TreeSet`. Both members above expose it as a
  `--rootcontainer` option to evade a blocklist on the exact `SortedSet` wire name.
  SoapFormatter directly supports roots 1 and 3; the deeper SortedDictionary root 2 is
  refused before generation (and before the `.cs` compile in XamlAssemblyLoadFromFile).
  This is not a Workflow surrogate or an outer carrier: the SOAP reader sees the selected
  native `SortedSet<string>` or `TreeSet<string>` root. Variant 2 declares
  `WithoutOptions("rootcontainer")`, so the interactive editor hides the setting when
  the TextFormattingRunProperties wrapper is selected.
- Both members override `SelfTestNeedsChildProcess` for variant 1. Deserializing this
  XAML in-process fires the payload and then fail-fasts the CLR, so `-t` runs in a child
  ysonet process (`Helpers/Core/IsolatedSelfTest.cs`). A new hosted gadget that carries
  its payload the same way needs the same override.
