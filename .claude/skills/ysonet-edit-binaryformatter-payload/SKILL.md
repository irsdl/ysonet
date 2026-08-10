---
name: ysonet-edit-binaryformatter-payload
description: Inspect, decode, dump, hand-edit, and re-emit a BinaryFormatter / MS-NRBF byte stream as readable JSON without deserializing it, using ysonet's record-level parser. Use when reading an unknown BF blob, changing type or assembly names in an existing payload, hand-building or splicing BF records, spoofing a type, debugging a minified binary payload, or embedding a BF stream inside another gadget. Not for designing a new gadget chain and not for porting a chain to modern .NET.
---

# Edit a BinaryFormatter payload through the JSON round trip

`ysonet/Helpers/ModifiedVulnerableBinaryFormatters/` is a modified copy of the
framework's BinaryFormatter internals. It parses a stream into [MS-NRBF] RECORDS
and writes records back out. It never enters the object-creation path, so it
reads and rewrites a hostile payload without firing it.

That property is the point of this skill. Everything below depends on it.

## 0. Never deserialize a payload to look at it

Do not call `BinaryFormatter.Deserialize` on a gadget payload to find out what is
inside. On this project's payloads that executes the chain on the build machine.

Use `AdvancedBinaryFormatterParser.StreamToJson` instead. It answers the same
question and runs nothing.

The one exception is a payload you built yourself from known-benign values, and
even then prefer the parser.

## 1. Know what the JSON actually is

It is a record transcript, not an object graph. Each entry looks like:

```json
{"Id": 6, "TypeName": "BinaryArray", "Data": {"$type": "BinaryArray", "objectId": 6, ...}}
```

- `$type` names ysonet's OWN record class: `BinaryObjectWithMapTyped`,
  `MemberReference`, `ArraySinglePrimitive`, `BinaryArray`, `MessageEnd`, and so on.
- `$type` NEVER names a payload type.
- The payload's real type names and assembly identities live in the record FIELDS
  and in `ArrayBytes`.

So when the task is "change the assembly version" or "spoof the type", you edit
those field strings. Editing `$type` edits ysonet's own plumbing and leaves the
names on the wire untouched, while still producing a stream that looks plausible.

## 2. Dump a stream to JSON

```csharp
string json = AdvancedBinaryFormatterParser.StreamToJson(stream, false, true, true);
// (stream, ignoreErrors, enableIndent, keepInfoFields)
```

Use `(false, true, true)` when reading by hand: indented, with the informational
fields kept. Pass `ignoreErrors: true` only for a truncated or malformed stream
you are trying to read anyway, and say so in your report.

To get a TEMPLATE from a live object instead of an existing blob, let the
framework write one and dump it:

```csharp
string json = SerializersHelper.BinaryFormatter_serialize_ToJson(someBenignObject);
```

Build the shape with benign values, dump it, then swap the values in the JSON.
This is how to learn a record layout without guessing at the wire format.

## 3. Edit the JSON, respecting four traps

**Trap 1 - keep every `$type` a bare class name.** `JsonToStream` re-adds the
namespace and assembly with this regex:

```
([""']\$type[""']:\s*[""'])([^\""'\.\[\] ,=]+)([\""'])
```

It matches only a value with no dot, space, comma, bracket or `=`. A `$type` you
pasted from elsewhere in an already-qualified form is silently skipped, and
Json.NET then cannot resolve it. Never qualify `$type` yourself.

**Trap 2 - nested payloads are opaque base64.** An array record carries its bytes
in `ArrayBytes`, written after the record. When those bytes are themselves a BF
stream, the whole inner payload is one base64 string. A search and replace over
the outer JSON misses all of it. See section 5.

**Trap 3 - assembly identity is a string in a field, not a version number you can
bump in isolation.** A type name and its assembly name appear in several records
and inside nested blobs. Change all of them or none; a half-renamed stream still
generates cleanly and fails only at the target.

**Trap 4 - two different kinds of id, do not confuse them.** The outer `Id` is a
transcript ordinal, assigned sequentially on parse and rebuilt on the way out. The
ids that carry MEANING are inside `Data`: `objectId` on a record, and `idRef` on a
`MemberReference` pointing at it. Edit those as a matched pair, and remember that
record ORDER still matters, because a back-reference has to follow the record it
refers to.

## 4. Re-emit the bytes

```csharp
MemoryStream ms = AdvancedBinaryFormatterParser.JsonToStream(json);
```

`AdvancedBinaryFormatterObjectToStream` fixes up one thing for you: a repeated
`ObjectWithMapTypedAssemId` assemId is forced to 0, so duplicating or reordering
records does not emit a dangling assembly reference. Do not hand-maintain
`assemId` around that.

For a payload that must go into a gadget, follow the self-containment rule in
`ysonet/Generators/README.md`: the JSON template lives in the gadget's own file as
a readable verbatim string, and the gadget calls `JsonToStream` at generation time.
Do not put a base64 blob in the source in place of the readable document.
`ClaimsPrincipal`, `GenericIdentity`, `DataSetOldBehaviour` and
`TypeConfuseDelegate` are the worked examples.

## 5. Nested BF streams need their own pass

To edit a payload inside `ArrayBytes`:

1. Base64-decode the `ArrayBytes` value into a `MemoryStream`.
2. `StreamToJson` that stream.
3. Edit the inner JSON by the same rules.
4. `JsonToStream` it back.
5. Base64-encode the result and write it into the outer `ArrayBytes`.

The `TypeConfuseDelegate` dump in `ysonet/Helpers/TestingArena/TestingArenaHome.cs`
is a real example of this shape.

## 6. Where to run it

Two sanctioned places, in order of preference:

- A real test in `ysonet.Tests`, run through the normal Debug build. This is the
  preferred route. `CLAUDE.md` explains why: ad-hoc compile-and-run probes get
  blocked by the safety classifier, a test does not.
- `ysonet.exe --runmytest`, which runs `TestingArenaHome.Start()`. This is the
  project's scratch area and already holds dump, minify and assembly-spoof
  examples. Good for exploration; move anything that must keep working into a test.

## 7. Verify the result

A re-emitted stream that parses is not a verified payload.

- Round-trip check: `StreamToJson` the re-emitted bytes and diff against the JSON
  you wrote. Anything that moved is a bug in your edit or a fixup you did not
  expect.
- Byte-identity check when you intended NO semantic change: parse and re-emit
  with no edit at all, and assert the bytes match the input.
- Effect check: a payload is only finished when a focused test proves it fires
  against a test-owned sink. Follow "Gadget/plugin development test order" in
  `CLAUDE.md`. Generation evidence is not effect evidence.

## 8. What this technique cannot do

**It cannot port a chain to modern .NET.** Do not accept a task framed as "rewrite
the versions so it works on .NET 5+".

- Where the target type exists on .NET 5+, no rewrite is needed: modern .NET ships
  `mscorlib` and `System` as facade assemblies full of type forwarders, so the
  .NET Framework-qualified name usually already resolves. Renaming to
  `System.Private.CoreLib` is more likely to break it.
- Where a chain fails, the type is ABSENT, and no rename fixes that. .NET Core
  dropped serialization of delegates and reflection objects, so
  `System.DelegateSerializationHolder` and
  `System.Reflection.MemberInfoSerializationHolder` have no counterpart. The whole
  delegate family goes with them.
- BinaryFormatter is obsolete from .NET 5, throws by default in .NET 8 without the
  opt-in switch, and is out of the .NET 9+ runtime.

Say this plainly rather than producing a renamed payload nobody can verify. The
repository has no modern .NET target to fire against: `ysonet.Tests/Runner/RuntimeBuild.cs`
maps only `net-fx-4.5` through `net-fx-4.8.1`, which is why the two modern gadgets
are marked "documented rather than fired". A template-based Json.NET or MessagePack
gadget is the productive modern-.NET path.

## Reference

| Call | Purpose |
|---|---|
| `AdvancedBinaryFormatterParser.StreamToJson(s, ignoreErrors, enableIndent, keepInfoFields)` | Stream to readable JSON, no deserialization |
| `AdvancedBinaryFormatterParser.JsonToStream(json)` | JSON back to BF bytes |
| `AdvancedBinaryFormatterParser.Parse(s)` | Stream to the record list, for programmatic edits |
| `AdvancedBinaryFormatterParser.AdvancedBinaryFormatterObjectToStream(list)` | Record list back to bytes |
| `SerializersHelper.BinaryFormatter_serialize_ToJson(obj)` | Serialize a live object straight to the JSON form |
| `BinaryFormatterMinifier` | The same round trip with type/assembly shortening in the middle |
| `SimpleBinaryFormatterParser` | Raw `typeBytes`/`valueBytes` per record. Its own header calls it a quick fix. Prefer the Advanced parser. |

Related skills: `ysonet-dev-create-gadget` when the result becomes a new gadget,
`ysonet-categorize-gadget` and `ysonet-audit-gadget-metadata` for its metadata.
