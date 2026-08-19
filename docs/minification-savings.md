# Minification savings - example comparison

This page is a worked example that shows how much the `--minify` option shrinks a
payload. For every gadget (across its formatters) and every minify-capable plugin
mode, it lists the payload size without `--minify`, the size with `--minify`, and the
percentage saved.

It is a snapshot for illustration only. The exact byte counts move a little between
releases and with different commands, so treat the percentages as the takeaway and
the live tool as the source of truth.

## What `--minify` does

`--minify` rewrites the serialized payload to be smaller while keeping it valid and
functional. It does not change which command runs. Depending on the format it:

- dedupes and drops unused XML namespaces and strips whitespace (Soap, Net/DataContract, XmlSerializer, XAML),
- shortens type and assembly-qualified names, dropping `Version`/`Culture`/`PublicKeyToken` where the short form still resolves,
- collapses JSON and YAML text,
- for some gadgets, switches to a more compact structure (for example one base64 string instead of a per-byte array).

## How this was measured

- Tool: ysonet **v2026.8.1**, Debug build. Every number below comes from one
  measuring pass on that build, so the table is internally consistent.
- Size = the number of bytes the tool writes for the payload, in its default output
  encoding for that gadget or formatter (base64 for BinaryFormatter and similar, raw
  text for XML/JSON/XAML). The same encoding is used with and without `--minify`, so
  the percentage reflects the payload shrink, not an encoding change.
- Each gadget was built with its **default variant** and no other options, and each
  plugin mode with the minimum options that mode needs.
- Saved % = (without - with) / without.
- Absolute byte counts scale with the command string and inputs; the percentages are
  the stable result.

The `-c` value follows what the gadget accepts, and the same short value is used
everywhere so a reader can reproduce a row. The pass runs from the tool's own
directory, so the file fixtures are plain relative names:

| Accepted input | Value used |
|---|---|
| Command (or an ignored input) | `calc.exe` |
| Remote URL | `http://localhost/x` |
| Target path | `C:\Windows\Temp\x.txt` |
| Local file / source code file | `x.cs`, a one-line fixture beside the tool |
| Assembly file | the bundled `E.dll` |
| UNC path | `\\ysonet-nonexistent-host\s\x.dll` (never resolved, target data only) |
| Host name or IP | `127.0.0.1` |

A gadget that accepts several of those gets the first one in that order, except where
the gadget's own contract needs something else. Those exceptions are all visible in
the tool's own error messages, and each one is a real rule rather than a preference:

- **`BootstrapperBuilder` and `FileSystemProxyCurrentDirectory`** take a DIRECTORY, so
  both use `C:\Windows\Temp`.
- **`AssemblyInstallerLoad`** refuses a bare file name on purpose - it would be resolved
  against whatever directory the target process happens to be in - so it uses
  `C:\Windows\Temp\x.dll`.
- **`DataSetXxe` and `XmlDocumentSurrogateXxe`** are measured on their default variant,
  which takes the URL the external entity points at, so both use `http://localhost/x`
  even though each also accepts a target path for its other variant.
- **`TypeConfuseDelegateFileOperations`** takes a compound `-c` of
  `<target path>;<local content file>`, and the content has to sort ordinally below the
  target path, so it uses `zz_target.txt;aa_content.txt`. The content fixture is a single
  whitespace-free word: with whitespace in it, the gadget REFUSES `--minify` on
  NetDataContractSerializer rather than let the XML minifier rewrite text content it must
  deliver byte for byte.

Four modules are deliberately not in the tables:

- **`WSManPluginInstance`** (13 gadget/formatter cells) and **`HashPEFileHandle`**
  (2 cells) are denial-of-service gadgets. Building one needs `--i-understand-dos`, and
  this snapshot does not build DoS payloads.
- **`ActivatorUrl`** has no `--minify` option: it makes a live remoting call and
  returns a status string rather than emitting a payload.
- **`Clipboard`** does expose `--minify`, but generating writes the OS clipboard on an
  STA thread, which is not something a bulk measuring pass should do. Measure it
  by hand if you need the number.

## What keeps this page honest

The numbers come from a measuring pass, but the COVERAGE does not depend on anyone
remembering this page. A test in `ysonet.Tests` reads it on every Debug build and
compares it with the live catalogue: every gadget and formatter the tool offers needs a
row here, every plugin that exposes `--minify` needs at least one, and the two summary
counts below have to match the tables further down. A module with no row must be named
in the list just above, which is where the test reads the exclusions from.

Three shapes on this page are therefore load-bearing. Keep them when editing: the
exclusion bullets name their module as **`Name`**, each table starts with its
`| Gadget | Formatter |` or `| Plugin | Mode |` header row and leaves the first column
blank to mean "same as the row above", and the two summary sentences below keep the
form "across N gadget x formatter combinations (M gadgets)" and "across N
minify-capable plugin modes (M plugins)".

## Summary

- **Gadgets:** across 272 gadget x formatter combinations (60 gadgets), `--minify`
  shrinks 238 of them. The average cut is about **18%** (median 15.7%), up to
  **90.9%**. Thirty-four combinations do not shrink, and one of those thirty-four
  actually grows by 8 bytes
  (see [Where it does little](#where-minification-does-little)).
- **Plugins:** across 27 minify-capable plugin modes (12 plugins), the average cut is
  about **20.6%** (median 18%), ranging from 0% up to **57.1%**.

## Highlights

- **GetterSettingsPropertyValue, Xaml: 35,562 -> 3,236 bytes (90.9%).** The biggest
  single win by a wide margin. The default XAML emits the inner BinaryFormatter blob
  as a per-byte `<Byte>` array; `--minify` passes it as one base64 string, so about
  32 KB disappears.
- **SoapFormatter payloads shrink the most** among the XML formatters, because their
  namespaces are verbose: FileSystemInfo Soap 56.8%, ObjRef Soap 54%, PSObject Soap
  53%, TextFormattingRunProperties Soap 52.4%.
- **XAML carriers shrink well when the document has structure to strip:** PictureBox
  Xaml 48.9%, InfiniteProgressPage Xaml 47.1%, ObjectDataProvider Xaml 42.6%. A XAML
  payload that is already one element does not (ResourceDictionary Xaml is 118 bytes
  and 0%, XamlTypeConverterFetch Xaml is 114 bytes and 0%).
- **Plugins that wrap a smaller inner gadget shrink a lot:** Altserialization
  SessionStateItemCollection 57.1%, ViewState with TypeConfuseDelegate 55.5%,
  ApplicationTrust 44.6%, SharePoint CVE-2024-38018 39.3%.

## Gadgets

Every gadget and every formatter in this snapshot, minify off vs on.

| Gadget | Formatter | Without `--minify` | With `--minify` | Saved | Saved % |
|---|---|--:|--:|--:|--:|
| ActivitySurrogateDisableTypeCheck | BinaryFormatter | 5,152 | 4,232 | 920 | 17.9% |
|  | LosFormatter | 5,160 | 4,240 | 920 | 17.8% |
|  | NetDataContractSerializer | 5,936 | 5,097 | 839 | 14.1% |
|  | SoapFormatter | 6,482 | 5,389 | 1,093 | 16.9% |
| ActivitySurrogateSelector | BinaryFormatter | 15,200 | 14,064 | 1,136 | 7.5% |
|  | LosFormatter | 15,208 | 14,068 | 1,140 | 7.5% |
|  | SoapFormatter | 15,719 | 14,538 | 1,181 | 7.5% |
| ActivitySurrogateSelectorFromFile | BinaryFormatter | 14,520 | 13,380 | 1,140 | 7.9% |
|  | LosFormatter | 14,524 | 13,388 | 1,136 | 7.8% |
|  | SoapFormatter | 15,035 | 13,854 | 1,181 | 7.9% |
| AssemblyCatalogLoad | Xaml | 344 | 326 | 18 | 5.2% |
| AssemblyInstallerLoad | FastJson | 473 | 363 | 110 | 23.3% |
|  | JavaScriptSerializer | 416 | 338 | 78 | 18.8% |
|  | Json.NET | 414 | 336 | 78 | 18.8% |
|  | MessagePackTypeless | 432 | 432 | 0 | 0% |
|  | MessagePackTypelessLz4 | 320 | 320 | 0 | 0% |
|  | SharpSerializerBinary | 592 | 592 | 0 | 0% |
|  | SharpSerializerXml | 837 | 667 | 170 | 20.3% |
|  | Xaml | 306 | 303 | 3 | 1% |
|  | YamlDotNet | 372 | 324 | 48 | 12.9% |
| AxHostState | BinaryFormatter | 1,444 | 972 | 472 | 32.7% |
|  | LosFormatter | 1,448 | 976 | 472 | 32.6% |
|  | NetDataContractSerializer | 1,688 | 1,103 | 585 | 34.7% |
|  | SoapFormatter | 1,959 | 1,190 | 769 | 39.3% |
| BaseActivationFactory | Json.NET | 197 | 171 | 26 | 13.2% |
| BootstrapperBuilder | DataContractJsonSerializer | 35 | 28 | 7 | 20% |
|  | DataContractSerializer | 399 | 342 | 57 | 14.3% |
|  | FastJson | 249 | 214 | 35 | 14.1% |
|  | JavaScriptSerializer | 212 | 196 | 16 | 7.5% |
|  | Json.NET | 211 | 195 | 16 | 7.6% |
|  | MessagePackTypeless | 252 | 252 | 0 | 0% |
|  | MessagePackTypelessLz4 | 228 | 228 | 0 | 0% |
|  | NetDataContractSerializer | 462 | 406 | 56 | 12.1% |
|  | SharpSerializerBinary | 272 | 272 | 0 | 0% |
|  | SharpSerializerXml | 368 | 347 | 21 | 5.7% |
|  | Xaml | 150 | 149 | 1 | 0.7% |
|  | YamlDotNet | 195 | 188 | 7 | 3.6% |
| ClaimsIdentity | BinaryFormatter | 1,704 | 1,080 | 624 | 36.6% |
|  | DataContractJsonSerializer | 1,209 | 741 | 468 | 38.7% |
|  | DataContractSerializer | 1,524 | 992 | 532 | 34.9% |
|  | LosFormatter | 1,708 | 1,084 | 624 | 36.5% |
|  | NetDataContractSerializer | 1,529 | 1,003 | 526 | 34.4% |
|  | SoapFormatter | 1,787 | 957 | 830 | 46.4% |
| ClaimsPrincipal | BinaryFormatter | 4,128 | 3,392 | 736 | 17.8% |
|  | DataContractJsonSerializer | 3,027 | 2,475 | 552 | 18.2% |
|  | DataContractSerializer | 3,355 | 2,739 | 616 | 18.4% |
|  | LosFormatter | 4,136 | 3,400 | 736 | 17.8% |
|  | NetDataContractSerializer | 3,360 | 2,750 | 610 | 18.2% |
|  | SoapFormatter | 3,617 | 2,703 | 914 | 25.3% |
| ColorConvertedBitmapExtension | Xaml | 414 | 414 | 0 | 0% |
| DataSet | BinaryFormatter | 1,848 | 1,376 | 472 | 25.5% |
|  | LosFormatter | 1,852 | 1,380 | 472 | 25.5% |
|  | SoapFormatter | 2,575 | 1,633 | 942 | 36.6% |
| DataSetOldBehaviour | BinaryFormatter | 4,348 | 2,972 | 1,376 | 31.6% |
|  | LosFormatter | 4,356 | 2,980 | 1,376 | 31.6% |
| DataSetOldBehaviourFromFile | BinaryFormatter | 63,576 | 62,444 | 1,132 | 1.8% |
|  | LosFormatter | 63,588 | 62,456 | 1,132 | 1.8% |
| DataSetTypeSpoof | BinaryFormatter | 1,980 | 1,484 | 496 | 25.1% |
|  | LosFormatter | 1,984 | 1,488 | 496 | 25% |
|  | SoapFormatter | 2,741 | 1,971 | 770 | 28.1% |
| DataSetXxe | BinaryFormatter | 324 | 320 | 4 | 1.2% |
|  | FsPickler | 1,042 | 742 | 300 | 28.8% |
|  | Json.NET | 239 | 218 | 21 | 8.8% |
|  | LosFormatter | 328 | 324 | 4 | 1.2% |
|  | SoapFormatter | 798 | 449 | 349 | 43.7% |
| DataTable | BinaryFormatter | 5,400 | 5,020 | 380 | 7% |
|  | LosFormatter | 5,408 | 5,028 | 380 | 7% |
|  | SoapFormatter | 8,582 | 6,363 | 2,219 | 25.9% |
| DataTableTypeSpoof | BinaryFormatter | 5,584 | 5,208 | 376 | 6.7% |
|  | LosFormatter | 5,592 | 5,212 | 380 | 6.8% |
|  | SoapFormatter | 8,652 | 6,848 | 1,804 | 20.9% |
| DataViewManagerXxe | FastJson | 348 | 306 | 42 | 12.1% |
|  | JavaScriptSerializer | 308 | 288 | 20 | 6.5% |
|  | SharpSerializerBinary | 396 | 396 | 0 | 0% |
|  | SharpSerializerXml | 399 | 373 | 26 | 6.5% |
|  | Xaml | 270 | 269 | 1 | 0.4% |
| DynamicUpdateMapExtension | Xaml | 4,337 | 3,998 | 339 | 7.8% |
| FileLogTraceListener | DataContractJsonSerializer | 55 | 45 | 10 | 18.2% |
|  | FastJson | 254 | 212 | 42 | 16.5% |
|  | JavaScriptSerializer | 214 | 194 | 20 | 9.3% |
|  | Json.NET | 213 | 193 | 20 | 9.4% |
|  | MessagePackTypeless | 248 | 248 | 0 | 0% |
|  | MessagePackTypelessLz4 | 240 | 240 | 0 | 0% |
|  | SharpSerializerXml | 276 | 250 | 26 | 9.4% |
|  | Xaml | 313 | 218 | 95 | 30.4% |
|  | YamlDotNet | 196 | 186 | 10 | 5.1% |
| FileSystemInfo | BinaryFormatter | 160 | 160 | 0 | 0% |
|  | DataContractJsonSerializer | 119 | 107 | 12 | 10.1% |
|  | DataContractSerializer | 475 | 471 | 4 | 0.8% |
|  | Json.NET | 235 | 214 | 21 | 8.9% |
|  | LosFormatter | 164 | 164 | 0 | 0% |
|  | NetDataContractSerializer | 580 | 525 | 55 | 9.5% |
|  | SoapFormatter | 636 | 275 | 361 | 56.8% |
| FileSystemInfoTimeSetter | Xaml | 414 | 379 | 35 | 8.5% |
| FileSystemProxyCurrentDirectory | DataContractJsonSerializer | 47 | 40 | 7 | 14.9% |
|  | DataContractSerializer | 328 | 324 | 4 | 1.2% |
|  | Json.NET | 202 | 186 | 16 | 7.9% |
|  | MessagePackTypeless | 240 | 240 | 0 | 0% |
|  | MessagePackTypelessLz4 | 232 | 232 | 0 | 0% |
|  | NetDataContractSerializer | 452 | 388 | 64 | 14.2% |
| FormsIdentity | BinaryFormatter | 1,912 | 1,288 | 624 | 32.6% |
|  | DataContractJsonSerializer | 1,224 | 756 | 468 | 38.2% |
|  | DataContractSerializer | 1,613 | 1,128 | 485 | 30.1% |
|  | LosFormatter | 1,920 | 1,296 | 624 | 32.5% |
|  | NetDataContractSerializer | 1,692 | 1,210 | 482 | 28.5% |
|  | SoapFormatter | 1,950 | 1,147 | 803 | 41.2% |
| GenericIdentity | BinaryFormatter | 1,764 | 1,140 | 624 | 35.4% |
|  | DataContractJsonSerializer | 1,237 | 769 | 468 | 37.8% |
|  | DataContractSerializer | 1,652 | 1,162 | 490 | 29.7% |
|  | LosFormatter | 1,772 | 1,148 | 624 | 35.2% |
|  | NetDataContractSerializer | 1,657 | 1,173 | 484 | 29.2% |
|  | SoapFormatter | 1,894 | 1,022 | 872 | 46% |
| GenericPrincipal | BinaryFormatter | 4,792 | 4,056 | 736 | 15.4% |
|  | DataContractJsonSerializer | 3,060 | 2,508 | 552 | 18% |
|  | DataContractSerializer | 3,488 | 2,914 | 574 | 16.5% |
|  | LosFormatter | 4,800 | 4,064 | 736 | 15.3% |
|  | NetDataContractSerializer | 3,493 | 2,925 | 568 | 16.3% |
|  | SoapFormatter | 3,768 | 2,894 | 874 | 23.2% |
| GetterCompilerResults | Json.NET | 419 | 323 | 96 | 22.9% |
| GetterSecurityException | Json.NET | 3,713 | 2,915 | 798 | 21.5% |
| GetterSettingsPropertyValue | Json.NET | 3,522 | 2,769 | 753 | 21.4% |
|  | MessagePackTypeless | 3,492 | 2,936 | 556 | 15.9% |
|  | MessagePackTypelessLz4 | 1,400 | 1,408 | -8 | -0.6% |
|  | Xaml | 35,562 | 3,236 | 32,326 | 90.9% |
| InfiniteProgressPage | FastJson | 269 | 227 | 42 | 15.6% |
|  | JavaScriptSerializer | 229 | 209 | 20 | 8.7% |
|  | Json.NET | 228 | 208 | 20 | 8.8% |
|  | SharpSerializerXml | 294 | 268 | 26 | 8.8% |
|  | Xaml | 308 | 163 | 145 | 47.1% |
|  | YamlDotNet | 211 | 201 | 10 | 4.7% |
| ObjectDataProvider | DataContractSerializer | 1,624 | 1,224 | 400 | 24.6% |
|  | FastJson | 649 | 493 | 156 | 24% |
|  | FsPickler | 1,582 | 1,056 | 526 | 33.2% |
|  | JavaScriptSerializer | 560 | 461 | 99 | 17.7% |
|  | Json.NET | 515 | 449 | 66 | 12.8% |
|  | MessagePackTypeless | 428 | 428 | 0 | 0% |
|  | MessagePackTypelessLz4 | 372 | 372 | 0 | 0% |
|  | SharpSerializerBinary | 484 | 484 | 0 | 0% |
|  | SharpSerializerXml | 668 | 532 | 136 | 20.4% |
|  | Xaml | 666 | 382 | 284 | 42.6% |
|  | XmlSerializer | 1,627 | 1,306 | 321 | 19.7% |
|  | YamlDotNet | 500 | 429 | 71 | 14.2% |
| ObjRef | BinaryFormatter | 216 | 216 | 0 | 0% |
|  | LosFormatter | 220 | 220 | 0 | 0% |
|  | SoapFormatter | 702 | 323 | 379 | 54% |
| PictureBox | FastJson | 250 | 202 | 48 | 19.2% |
|  | JavaScriptSerializer | 218 | 186 | 32 | 14.7% |
|  | Json.NET | 217 | 185 | 32 | 14.7% |
|  | MessagePackTypeless | 228 | 228 | 0 | 0% |
|  | MessagePackTypelessLz4 | 224 | 224 | 0 | 0% |
|  | SharpSerializerXml | 396 | 360 | 36 | 9.1% |
|  | Xaml | 272 | 139 | 133 | 48.9% |
|  | YamlDotNet | 191 | 175 | 16 | 8.4% |
| PSObject | BinaryFormatter | 3,836 | 2,552 | 1,284 | 33.5% |
|  | LosFormatter | 3,844 | 2,560 | 1,284 | 33.4% |
|  | NetDataContractSerializer | 4,249 | 2,283 | 1,966 | 46.3% |
|  | SoapFormatter | 4,483 | 2,106 | 2,377 | 53% |
| ResourceDictionary | Xaml | 118 | 118 | 0 | 0% |
| ResourceSet | BinaryFormatter | 2,648 | 2,648 | 0 | 0% |
|  | LosFormatter | 2,656 | 2,656 | 0 | 0% |
|  | NetDataContractSerializer | 3,233 | 3,212 | 21 | 0.6% |
| ResXFileRef | Xaml | 223 | 219 | 4 | 1.8% |
|  | YamlDotNet | 252 | 246 | 6 | 2.4% |
| RolePrincipal | BinaryFormatter | 1,844 | 1,216 | 628 | 34.1% |
|  | DataContractSerializer | 1,654 | 1,155 | 499 | 30.2% |
|  | Json.NET | 1,420 | 884 | 536 | 37.7% |
|  | LosFormatter | 1,852 | 1,224 | 628 | 33.9% |
|  | NetDataContractSerializer | 1,729 | 1,144 | 585 | 33.8% |
|  | SoapFormatter | 1,931 | 1,080 | 851 | 44.1% |
| SessionSecurityToken | BinaryFormatter | 2,188 | 1,560 | 628 | 28.7% |
|  | DataContractSerializer | 2,420 | 1,724 | 696 | 28.8% |
|  | Json.NET | 2,130 | 1,436 | 694 | 32.6% |
|  | LosFormatter | 2,196 | 1,568 | 628 | 28.6% |
|  | NetDataContractSerializer | 2,339 | 1,593 | 746 | 31.9% |
|  | SoapFormatter | 2,697 | 1,772 | 925 | 34.3% |
| SessionViewStateHistoryItem | BinaryFormatter | 1,864 | 1,236 | 628 | 33.7% |
|  | DataContractSerializer | 1,739 | 1,199 | 540 | 31.1% |
|  | Json.NET | 1,372 | 834 | 538 | 39.2% |
|  | LosFormatter | 1,872 | 1,244 | 628 | 33.5% |
|  | NetDataContractSerializer | 1,628 | 1,038 | 590 | 36.2% |
|  | SoapFormatter | 1,936 | 1,096 | 840 | 43.4% |
| TempFileCollection | BinaryFormatter | 640 | 636 | 4 | 0.6% |
|  | DataContractSerializer | 786 | 691 | 95 | 12.1% |
|  | LosFormatter | 648 | 644 | 4 | 0.6% |
|  | NetDataContractSerializer | 1,241 | 1,145 | 96 | 7.7% |
|  | SoapFormatter | 1,340 | 974 | 366 | 27.3% |
| TextFormattingRunProperties | BinaryFormatter | 1,184 | 716 | 468 | 39.5% |
|  | DataContractSerializer | 1,098 | 697 | 401 | 36.5% |
|  | Json.NET | 904 | 583 | 321 | 35.5% |
|  | LosFormatter | 1,192 | 724 | 468 | 39.3% |
|  | NetDataContractSerializer | 1,350 | 865 | 485 | 35.9% |
|  | SoapFormatter | 1,615 | 768 | 847 | 52.4% |
| ToolboxItemContainer | BinaryFormatter | 3,000 | 2,528 | 472 | 15.7% |
|  | LosFormatter | 3,008 | 2,536 | 472 | 15.7% |
|  | SoapFormatter | 3,420 | 2,435 | 985 | 28.8% |
| TypeConfuseDelegate | BinaryFormatter | 2,992 | 2,440 | 552 | 18.4% |
|  | LosFormatter | 3,000 | 2,444 | 556 | 18.5% |
|  | NetDataContractSerializer | 4,024 | 3,709 | 315 | 7.8% |
|  | SoapFormatter | 4,678 | 3,999 | 679 | 14.5% |
| TypeConfuseDelegateFileOperations | BinaryFormatter | 2,760 | 2,212 | 548 | 19.9% |
|  | LosFormatter | 2,768 | 2,220 | 548 | 19.8% |
|  | NetDataContractSerializer | 3,841 | 3,532 | 309 | 8% |
|  | SoapFormatter | 4,489 | 3,816 | 673 | 15% |
| TypeConfuseDelegateMono | BinaryFormatter | 2,632 | 2,152 | 480 | 18.2% |
|  | LosFormatter | 2,640 | 2,160 | 480 | 18.2% |
|  | NetDataContractSerializer | 3,262 | 3,020 | 242 | 7.4% |
| TypeConfuseDelegateNetFx35 | BinaryFormatter | 4,384 | 3,628 | 756 | 17.2% |
|  | LosFormatter | 4,392 | 3,632 | 760 | 17.3% |
|  | SoapFormatter | 6,041 | 5,103 | 938 | 15.5% |
| TypeConfuseDelegateNetFx40 | BinaryFormatter | 3,828 | 3,168 | 660 | 17.2% |
|  | LosFormatter | 3,832 | 3,172 | 660 | 17.2% |
|  | SoapFormatter | 5,717 | 4,858 | 859 | 15% |
| TypeConfuseDelegatePowerShell | BinaryFormatter | 6,448 | 5,004 | 1,444 | 22.4% |
|  | LosFormatter | 6,452 | 5,008 | 1,444 | 22.4% |
| WbemClassObjectUnmarshal | BinaryFormatter | 396 | 392 | 4 | 1% |
|  | DataContractSerializer | 571 | 567 | 4 | 0.7% |
|  | FsPickler | 1,108 | 673 | 435 | 39.3% |
|  | Json.NET | 301 | 285 | 16 | 5.3% |
|  | LosFormatter | 400 | 396 | 4 | 1% |
|  | NetDataContractSerializer | 769 | 653 | 116 | 15.1% |
|  | SoapFormatter | 911 | 610 | 301 | 33% |
| WindowsClaimsIdentity | BinaryFormatter | 1,880 | 1,168 | 712 | 37.9% |
|  | DataContractSerializer | 1,699 | 1,202 | 497 | 29.3% |
|  | Json.NET | 1,427 | 894 | 533 | 37.4% |
|  | LosFormatter | 1,888 | 1,172 | 716 | 37.9% |
|  | NetDataContractSerializer | 1,601 | 1,060 | 541 | 33.8% |
|  | SoapFormatter | 1,975 | 1,221 | 754 | 38.2% |
| WindowsIdentity | BinaryFormatter | 1,732 | 1,108 | 624 | 36% |
|  | DataContractSerializer | 1,658 | 1,159 | 499 | 30.1% |
|  | Json.NET | 1,420 | 884 | 536 | 37.7% |
|  | LosFormatter | 1,740 | 1,116 | 624 | 35.9% |
|  | NetDataContractSerializer | 1,595 | 1,050 | 545 | 34.2% |
|  | SoapFormatter | 1,943 | 1,189 | 754 | 38.8% |
| WindowsPrincipal | BinaryFormatter | 4,384 | 3,880 | 504 | 11.5% |
|  | DataContractJsonSerializer | 4,349 | 3,845 | 504 | 11.6% |
|  | DataContractSerializer | 4,793 | 4,203 | 590 | 12.3% |
|  | Json.NET | 4,689 | 4,039 | 650 | 13.9% |
|  | LosFormatter | 4,392 | 3,884 | 508 | 11.6% |
|  | NetDataContractSerializer | 4,941 | 4,329 | 612 | 12.4% |
|  | SoapFormatter | 5,215 | 4,289 | 926 | 17.8% |
| WorkflowDesigner | FastJson | 830 | 788 | 42 | 5.1% |
|  | JavaScriptSerializer | 790 | 770 | 20 | 2.5% |
|  | Json.NET | 789 | 769 | 20 | 2.5% |
|  | MessagePackTypeless | 1,004 | 1,004 | 0 | 0% |
|  | MessagePackTypelessLz4 | 700 | 700 | 0 | 0% |
|  | SharpSerializerBinary | 1,020 | 1,020 | 0 | 0% |
|  | SharpSerializerXml | 979 | 953 | 26 | 2.7% |
|  | Xaml | 849 | 849 | 0 | 0% |
| XamlAssemblyLoadFromFile | BinaryFormatter | 8,056 | 6,704 | 1,352 | 16.8% |
|  | LosFormatter | 8,068 | 6,708 | 1,360 | 16.9% |
|  | NetDataContractSerializer | 8,469 | 6,950 | 1,519 | 17.9% |
|  | SoapFormatter | 8,879 | 7,234 | 1,645 | 18.5% |
| XamlImageInfo | Json.NET | 403 | 365 | 38 | 9.4% |
| XamlTypeConverterFetch | JavaScriptSerializer | 178 | 162 | 16 | 9% |
|  | Json.NET | 177 | 161 | 16 | 9% |
|  | Xaml | 114 | 114 | 0 | 0% |
|  | YamlDotNet | 161 | 154 | 7 | 4.3% |
| XmlDocumentSurrogateXxe | BinaryFormatter | 416 | 412 | 4 | 1% |
|  | DataContractJsonSerializer | 92 | 92 | 0 | 0% |
|  | DataContractSerializer | 512 | 496 | 16 | 3.1% |
|  | FsPickler | 556 | 433 | 123 | 22.1% |
|  | LosFormatter | 424 | 420 | 4 | 0.9% |
|  | NetDataContractSerializer | 585 | 560 | 25 | 4.3% |
|  | SoapFormatter | 899 | 502 | 397 | 44.2% |
| XmlDocumentXxe | FastJson | 254 | 219 | 35 | 13.8% |
|  | JavaScriptSerializer | 217 | 201 | 16 | 7.4% |
|  | MessagePackTypeless | 260 | 260 | 0 | 0% |
|  | MessagePackTypelessLz4 | 264 | 264 | 0 | 0% |
|  | SharpSerializerBinary | 280 | 280 | 0 | 0% |
|  | SharpSerializerXml | 307 | 286 | 21 | 6.8% |
|  | Xaml | 183 | 182 | 1 | 0.5% |
|  | YamlDotNet | 200 | 193 | 7 | 3.5% |

## Where minification does little

Some payloads are already compact, or are dominated by binary or opaque data the
text minifier cannot touch:

- **Binary and compact serializers usually have nothing to strip.** Thirty-three cells
  come out byte for byte identical, and twenty-two of those are SharpSerializerBinary,
  MessagePackTypeless or MessagePackTypelessLz4. The FileSystemInfo, ObjRef and ResourceSet
  BinaryFormatter/LosFormatter cells are 0% for the same reason: the graph carries no
  text the minifier can shorten.
- **The exception shows what the flag really reaches.**
  GetterSettingsPropertyValue with MessagePackTypeless saves 15.9%, because its
  payload carries an inner BinaryFormatter blob and `--minify` shrinks that blob
  before MessagePack wraps it. With the Lz4 variant the same case gets 8 bytes
  *bigger* (1,400 -> 1,408, -0.6%, reproducibly): the smaller inner payload happens to
  compress slightly worse. That is the only cell in the table where `--minify` costs
  bytes.
- **A payload that is already one element cannot shrink.** ResourceDictionary Xaml is
  118 bytes at 0%, XamlTypeConverterFetch Xaml is 114 bytes at 0% and WorkflowDesigner
  Xaml is 849 bytes at 0%; AssemblyInstallerLoad Xaml, DataViewManagerXxe Xaml and
  XmlDocumentXxe Xaml each save 1 to 3 bytes. For these the `-c` value is most of the
  payload.
- **A gadget may REFUSE `--minify` rather than risk the payload.**
  TypeConfuseDelegateFileOperations with NetDataContractSerializer refuses when the
  content it must deliver contains whitespace, because the XML minifier rewrites
  whitespace inside text content and the target would receive different bytes. The row
  in the table above uses whitespace-free content, so it minifies; with whitespace, the
  honest answer from the tool is a refusal and an explanation, not a smaller payload
  that writes the wrong file.
- **Assembly-embedding gadgets** are dominated by the embedded compiled assembly
  (base64), which `--minify` does not compress. DataSetOldBehaviourFromFile, for
  example, is only 1.8% smaller with `--minify`. For these, use `--compressed`, which
  gzips the embedded assembly (and stacks with `--minify`):

  | DataSetOldBehaviourFromFile (LosFormatter) | Bytes | vs default |
  |---|--:|--:|
  | default | 63,580 | - |
  | `--minify` | 62,460 | 1.8% |
  | `--compressed` | 8,056 | 87.3% |
  | `--compressed --minify` | 6,556 | 89.7% |

## Plugins

Every plugin mode that exposes a `--minify` option, minify off vs on. Each row is
built the way the suite's own plugin matrix builds it, with the minimum options that
mode needs.

| Plugin | Mode | Without `--minify` | With `--minify` | Saved | Saved % |
|---|---|--:|--:|--:|--:|
| Altserialization | HttpStaticObjectsCollection | 895 | 544 | 351 | 39.2% |
|  | SessionStateItemCollection | 2,258 | 968 | 1,290 | 57.1% |
| ApplicationTrust | (default) | 2,101 | 1,163 | 938 | 44.6% |
| DotNetNuke | read_file | 817 | 783 | 34 | 4.2% |
|  | write_file | 875 | 837 | 38 | 4.3% |
|  | run_command | 2,093 | 1,606 | 487 | 23.3% |
| GetterCallGadgets | PropertyGrid | 193 | 153 | 40 | 20.7% |
| MachineKeySessionSecurityTokenHandler | (default) | 976 | 700 | 276 | 28.3% |
| Resx | indirect_resx_file | 2,617 | 2,290 | 327 | 12.5% |
|  | CompiledDotResources | 1,284 | 933 | 351 | 27.3% |
|  | BinaryFormatter | 3,683 | 2,893 | 790 | 21.4% |
|  | SoapFormatter | 22,540 | 20,642 | 1,898 | 8.4% |
| SessionSecurityTokenHandler | (default) | 1,216 | 936 | 280 | 23% |
| SharePoint | CVE-2026-50522 | 1,862 | 1,658 | 204 | 11% |
|  | CVE-2025-53770 | 2,941 | 2,437 | 504 | 17.1% |
|  | CVE-2025-49704 | 2,954 | 2,422 | 532 | 18% |
|  | CVE-2024-38018 | 4,376 | 2,656 | 1,720 | 39.3% |
|  | CVE-2020-1147 | 5,311 | 3,591 | 1,720 | 32.4% |
|  | CVE-2019-0604 | 6,485 | 6,485 | 0 | 0% |
|  | CVE-2018-8421 | 1,757 | 1,757 | 0 | 0% |
| ThirdPartyGadgets | GetterActiveMQObjectMessage | 4,074 | 3,670 | 404 | 9.9% |
| TransactionManagerReenlist | (default) | 893 | 542 | 351 | 39.3% |
| ViewState | TypeConfuseDelegate | 3,246 | 1,444 | 1,802 | 55.5% |
| Xps | fdseq | 2,143 | 2,061 | 82 | 3.8% |
|  | fdoc | 2,144 | 2,062 | 82 | 3.8% |
|  | fpage | 2,148 | 2,068 | 80 | 3.7% |
|  | all | 2,703 | 2,459 | 244 | 9% |

Notes on the plugin rows:

- The two handler plugins (MachineKeySessionSecurityTokenHandler,
  SessionSecurityTokenHandler) wrap the payload in an encrypted and encoded envelope.
  The reduction there comes from the smaller inner payload passing through a
  size-preserving transform, so it is a real cut even though the outer bytes are
  opaque. The same is true of ViewState, which signs the payload.
- SharePoint `--minify` reaches the BinaryFormatter and LosFormatter gadget CVEs.
  CVE-2019-0604 and CVE-2018-8421 carry a XAML or URL payload the flag does not
  touch, so both are 0%.
- Resx CompiledDotResources is the one row measured on the FILE it writes rather than
  on standard output: that mode emits the payload through `-of` and prints a status
  line, so measuring the console would report the status message and wrongly show 0%.
- Xps output is a deflate-compressed OPC package. `--minify` does reach the inner
  ObjectDataProvider XAML, but a smaller inner document does not have to make a much
  smaller ZIP, which is why the saving is a few percent.
- The key-taking plugins (MachineKeySessionSecurityTokenHandler and ViewState here,
  plus SessionSecurityTokenHandler which needs none) used the harmless demo keys
  printed by `ysonet.exe -p ViewState --examples`. GetterCallGadgets read a `{}`
  inner-gadget file.

## Reproduce

Each number comes from running the tool twice for the same case, once without and
once with `--minify`, and comparing the length of the emitted payload. For a single
case:

```
ysonet.exe -g TextFormattingRunProperties -f SoapFormatter -c calc.exe          > raw.txt
ysonet.exe -g TextFormattingRunProperties -f SoapFormatter -c calc.exe --minify > min.txt
```

List a gadget's supported formatters with `ysonet.exe --list formatters -g <gadget>`,
and all gadgets or plugins with `ysonet.exe --list gadgets` or `ysonet.exe --list plugins`.
