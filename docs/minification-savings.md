# Minification savings - example comparison

This page is a worked example that shows how much the `--minify` option shrinks a
payload. For every gadget (across its formatters) and every minify-capable plugin,
it lists the payload size without `--minify`, the size with `--minify`, and the
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

- Tool: ysonet **v2026.7.6**, Debug build.
- Size = the number of bytes the tool writes for the payload, in its default output
  encoding for that gadget or formatter (base64 for BinaryFormatter and similar, raw
  text for XML/JSON/XAML). The same encoding is used with and without `--minify`, so
  the percentage reflects the payload shrink, not an encoding change.
- Command for shell-command gadgets and plugins: `calc.exe`. Gadgets that take a
  file, DLL, or URL used a tiny compiled C# fixture, the bundled `E.dll`, or
  `http://localhost/x`. The crypto plugins used the demo keys from the usage docs.
- Saved % = (without - with) / without.
- Absolute byte counts scale with the command string and inputs; the percentages are
  the stable result.

## Summary

- **Gadgets:** across 116 gadget x formatter combinations, `--minify` shrinks 109 of
  them. The typical cut is about **29%** (median 30%), up to **91.8%**. Seven
  combinations do not shrink (see [Where it does little](#where-minification-does-little)).
- **Plugins:** across 13 minify-capable plugin modes, the average cut is about
  **34%**, ranging from 9.9% up to **57.1%**.

## Highlights

- **GetterSettingsPropertyValue, Xaml: 35,562 -> 2,920 bytes (91.8%).** The biggest
  single win. The default XAML emits the inner BinaryFormatter blob as a per-byte
  `<Byte>` array; `--minify` passes it as one base64 string, so about 33 KB disappears.
- **SoapFormatter payloads shrink the most** among the XML formatters, because their
  namespaces are verbose: ObjRef Soap 54%, TextFormattingRunProperties Soap 53.5%,
  PSObject Soap 53%.
- **Plugins that wrap a smaller inner gadget shrink a lot:** ViewState with
  TypeConfuseDelegate 56.3%, Altserialization Session 57.1%, ApplicationTrust 46.4%.

## Gadgets

Every gadget and every formatter it supports, minify off vs on. Rows marked `n/a`
are a variant plus formatter pair the gadget cannot produce (see the note below the table).

| Gadget | Formatter | Without `--minify` | With `--minify` | Saved | Saved % |
|---|---|--:|--:|--:|--:|
| ActivitySurrogateDisableTypeCheck | BinaryFormatter | 5,152 | 4,008 | 1,144 | 22.2% |
|  | LosFormatter | 5,160 | 4,016 | 1,144 | 22.2% |
|  | NetDataContractSerializer | 5,936 | 5,097 | 839 | 14.1% |
|  | SoapFormatter | n/a | n/a | n/a | n/a |
| ActivitySurrogateSelector | BinaryFormatter | 15,200 | 12,312 | 2,888 | 19% |
|  | LosFormatter | 15,208 | 12,316 | 2,892 | 19% |
|  | SoapFormatter | 15,719 | 12,786 | 2,933 | 18.7% |
| ActivitySurrogateSelectorFromFile | BinaryFormatter | 14,520 | 11,628 | 2,892 | 19.9% |
|  | LosFormatter | 14,524 | 11,636 | 2,888 | 19.9% |
|  | SoapFormatter | 15,035 | 12,102 | 2,933 | 19.5% |
| AxHostState | BinaryFormatter | 1,480 | 972 | 508 | 34.3% |
|  | LosFormatter | 1,488 | 976 | 512 | 34.4% |
|  | NetDataContractSerializer | 1,728 | 1,103 | 625 | 36.2% |
|  | SoapFormatter | 1,999 | 1,190 | 809 | 40.5% |
| BaseActivationFactory | Json.NET | 265 | 239 | 26 | 9.8% |
| ClaimsIdentity | BinaryFormatter | 1,756 | 1,080 | 676 | 38.5% |
|  | LosFormatter | 1,764 | 1,084 | 680 | 38.5% |
|  | SoapFormatter | 1,827 | 957 | 870 | 47.6% |
| ClaimsPrincipal | BinaryFormatter | 4,128 | 2,972 | 1,156 | 28% |
|  | LosFormatter | 4,136 | 2,976 | 1,160 | 28% |
|  | SoapFormatter | 3,617 | 2,387 | 1,230 | 34% |
| DataSet | BinaryFormatter | 1,884 | 1,376 | 508 | 27% |
|  | LosFormatter | 1,892 | 1,380 | 512 | 27.1% |
|  | SoapFormatter | 2,615 | 1,633 | 982 | 37.6% |
| DataSetOldBehaviour | BinaryFormatter | 4,404 | 2,972 | 1,432 | 32.5% |
|  | LosFormatter | 4,408 | 2,980 | 1,428 | 32.4% |
| DataSetOldBehaviourFromFile | BinaryFormatter | 63,576 | 62,440 | 1,136 | 1.8% |
|  | LosFormatter | 63,568 | 62,432 | 1,136 | 1.8% |
| DataSetTypeSpoof | BinaryFormatter | 2,016 | 1,484 | 532 | 26.4% |
|  | LosFormatter | 2,024 | 1,488 | 536 | 26.5% |
|  | SoapFormatter | 2,781 | 1,971 | 810 | 29.1% |
| GenericPrincipal | BinaryFormatter | 4,792 | 3,636 | 1,156 | 24.1% |
|  | LosFormatter | 4,800 | 3,644 | 1,156 | 24.1% |
| GetterCompilerResults | Json.NET | 487 | 391 | 96 | 19.7% |
| GetterSecurityException | Json.NET | 3,713 | 2,599 | 1,114 | 30% |
| GetterSettingsPropertyValue | Json.NET | 3,522 | 2,453 | 1,069 | 30.4% |
|  | MessagePackTypeless | 3,492 | 2,624 | 868 | 24.9% |
|  | MessagePackTypelessLz4 | 1,400 | 1,376 | 24 | 1.7% |
|  | Xaml | 35,562 | 2,920 | 32,642 | 91.8% |
| ObjectDataProvider | DataContractSerializer | 1,624 | 1,224 | 400 | 24.6% |
|  | FastJson | 649 | 493 | 156 | 24% |
|  | FsPickler | 1,582 | 1,056 | 526 | 33.2% |
|  | JavaScriptSerializer | 560 | 461 | 99 | 17.7% |
|  | Json.NET | 515 | 449 | 66 | 12.8% |
|  | MessagePackTypeless | 428 | 428 | 0 | 0% |
|  | MessagePackTypelessLz4 | 372 | 372 | 0 | 0% |
|  | SharpSerializerBinary | 484 | 484 | 0 | 0% |
|  | SharpSerializerXml | 668 | 532 | 136 | 20.4% |
|  | Xaml | 695 | 382 | 313 | 45% |
|  | XmlSerializer | 1,627 | 1,306 | 321 | 19.7% |
|  | YamlDotNet | 500 | 429 | 71 | 14.2% |
| ObjRef | BinaryFormatter | 216 | 216 | 0 | 0% |
|  | LosFormatter | 220 | 220 | 0 | 0% |
|  | SoapFormatter | 702 | 323 | 379 | 54% |
| PSObject | BinaryFormatter | 3,836 | 2,552 | 1,284 | 33.5% |
|  | LosFormatter | 3,844 | 2,560 | 1,284 | 33.4% |
|  | NetDataContractSerializer | 4,249 | 2,283 | 1,966 | 46.3% |
|  | SoapFormatter | 4,483 | 2,106 | 2,377 | 53% |
| ResourceSet | BinaryFormatter | 2,648 | 2,648 | 0 | 0% |
|  | LosFormatter | 2,656 | 2,656 | 0 | 0% |
|  | NetDataContractSerializer | 3,233 | 3,212 | 21 | 0.6% |
| RolePrincipal | BinaryFormatter | 1,900 | 1,216 | 684 | 36% |
|  | DataContractSerializer | 1,694 | 1,155 | 539 | 31.8% |
|  | Json.NET | 1,460 | 884 | 576 | 39.5% |
|  | LosFormatter | 1,904 | 1,224 | 680 | 35.7% |
|  | NetDataContractSerializer | 1,769 | 1,144 | 625 | 35.3% |
|  | SoapFormatter | 1,971 | 1,080 | 891 | 45.2% |
| SessionSecurityToken | BinaryFormatter | 2,240 | 1,560 | 680 | 30.4% |
|  | DataContractSerializer | 2,476 | 1,724 | 752 | 30.4% |
|  | Json.NET | 2,186 | 1,436 | 750 | 34.3% |
|  | LosFormatter | 2,248 | 1,568 | 680 | 30.2% |
|  | NetDataContractSerializer | 2,395 | 1,593 | 802 | 33.5% |
|  | SoapFormatter | 2,753 | 1,772 | 981 | 35.6% |
| SessionViewStateHistoryItem | BinaryFormatter | 1,916 | 1,236 | 680 | 35.5% |
|  | DataContractSerializer | 1,779 | 1,199 | 580 | 32.6% |
|  | Json.NET | 1,412 | 834 | 578 | 40.9% |
|  | LosFormatter | 1,924 | 1,244 | 680 | 35.3% |
|  | NetDataContractSerializer | 1,668 | 1,038 | 630 | 37.8% |
|  | SoapFormatter | 1,976 | 1,096 | 880 | 44.5% |
| TextFormattingRunProperties | BinaryFormatter | 1,224 | 716 | 508 | 41.5% |
|  | DataContractSerializer | 1,127 | 697 | 430 | 38.2% |
|  | Json.NET | 904 | 583 | 321 | 35.5% |
|  | LosFormatter | 1,232 | 724 | 508 | 41.2% |
|  | NetDataContractSerializer | 1,379 | 865 | 514 | 37.3% |
|  | SoapFormatter | 1,652 | 768 | 884 | 53.5% |
| ToolboxItemContainer | BinaryFormatter | 3,040 | 2,528 | 512 | 16.8% |
|  | LosFormatter | 3,048 | 2,536 | 512 | 16.8% |
|  | SoapFormatter | 3,460 | 2,435 | 1,025 | 29.6% |
| TypeConfuseDelegate | BinaryFormatter | 2,992 | 2,124 | 868 | 29% |
|  | LosFormatter | 3,000 | 2,132 | 868 | 28.9% |
|  | NetDataContractSerializer | 4,024 | 3,709 | 315 | 7.8% |
| TypeConfuseDelegateMono | BinaryFormatter | 2,632 | 1,944 | 688 | 26.1% |
|  | LosFormatter | 2,640 | 1,948 | 692 | 26.2% |
|  | NetDataContractSerializer | 3,262 | 3,020 | 242 | 7.4% |
| WindowsClaimsIdentity | BinaryFormatter | 2,040 | 1,272 | 768 | 37.6% |
|  | DataContractSerializer | 1,739 | 1,202 | 537 | 30.9% |
|  | Json.NET | 1,467 | 894 | 573 | 39.1% |
|  | LosFormatter | 2,044 | 1,280 | 764 | 37.4% |
|  | NetDataContractSerializer | 1,817 | 1,243 | 574 | 31.6% |
|  | SoapFormatter | 2,015 | 1,221 | 794 | 39.4% |
| WindowsIdentity | BinaryFormatter | 1,784 | 1,108 | 676 | 37.9% |
|  | DataContractSerializer | 1,698 | 1,159 | 539 | 31.7% |
|  | Json.NET | 1,460 | 884 | 576 | 39.5% |
|  | LosFormatter | 1,792 | 1,116 | 676 | 37.7% |
|  | NetDataContractSerializer | 1,635 | 1,050 | 585 | 35.8% |
|  | SoapFormatter | 1,983 | 1,189 | 794 | 40% |
| WindowsPrincipal | BinaryFormatter | 4,432 | 3,880 | 552 | 12.5% |
|  | DataContractJsonSerializer | 4,397 | 3,845 | 552 | 12.6% |
|  | DataContractSerializer | 4,841 | 4,203 | 638 | 13.2% |
|  | Json.NET | 4,737 | 4,039 | 698 | 14.7% |
|  | LosFormatter | 4,440 | 3,884 | 556 | 12.5% |
|  | NetDataContractSerializer | 4,989 | 4,329 | 660 | 13.2% |
|  | SoapFormatter | 5,263 | 4,289 | 974 | 18.5% |
| XamlAssemblyLoadFromFile | BinaryFormatter | 8,056 | 6,484 | 1,572 | 19.5% |
|  | LosFormatter | 8,068 | 6,484 | 1,584 | 19.6% |
|  | NetDataContractSerializer | 8,461 | 6,954 | 1,507 | 17.8% |
|  | SoapFormatter | n/a | n/a | n/a | n/a |
| XamlImageInfo | Json.NET | 547 | 509 | 38 | 6.9% |

The two `n/a` rows (ActivitySurrogateDisableTypeCheck and XamlAssemblyLoadFromFile
with SoapFormatter) are not a minify limitation: the default variant of each is a
TypeConfuseDelegate wrapper built on a generic `SortedSet`, which SoapFormatter
cannot serialize, so that one variant plus formatter pair is never produced.

## Where minification does little

Some payloads are already compact, or are dominated by binary or opaque data the
text minifier cannot touch:

- **Binary and compact serializers have nothing to strip:** ObjectDataProvider with
  MessagePackTypeless, MessagePackTypelessLz4, or SharpSerializerBinary; ObjRef with
  BinaryFormatter or LosFormatter; ResourceSet with BinaryFormatter or LosFormatter.
  All report 0%.
- **Assembly-embedding gadgets** are dominated by the embedded compiled assembly
  (base64), which `--minify` does not compress. DataSetOldBehaviourFromFile, for
  example, is only 1.8% smaller with `--minify`. For these, use `--compressed`, which
  gzips the embedded assembly (and stacks with `--minify`):

  | DataSetOldBehaviourFromFile (LosFormatter) | Bytes | vs default |
  |---|--:|--:|
  | default | 63,576 | - |
  | `--minify` | 62,448 | 1.8% |
  | `--compressed` | 8,056 | 87.3% |
  | `--compressed --minify` | 6,552 | 89.7% |

## Plugins

Every plugin mode that exposes a `--minify` option, minify off vs on.

| Plugin | Mode | Without `--minify` | With `--minify` | Saved | Saved % |
|---|---|--:|--:|--:|--:|
| Altserialization | HttpStaticObjectsCollection | 924 | 544 | 380 | 41.1% |
| Altserialization | SessionStateItemCollection | 2,258 | 968 | 1,290 | 57.1% |
| ApplicationTrust | (default) | 2,171 | 1,163 | 1,008 | 46.4% |
| DotNetNuke | run_command | 2,133 | 1,606 | 527 | 24.7% |
| GetterCallGadgets | PropertyGrid | 193 | 153 | 40 | 20.7% |
| MachineKeySessionSecurityTokenHandler | (default) | 1,000 | 700 | 300 | 30% |
| NetNonRceGadgets | PictureBox Json.NET | 217 | 185 | 32 | 14.7% |
| NetNonRceGadgets | PictureBox Xaml | 272 | 139 | 133 | 48.9% |
| Resx | BinaryFormatter | 3,787 | 2,893 | 894 | 23.6% |
| SessionSecurityTokenHandler | (default) | 1,236 | 936 | 300 | 24.3% |
| ThirdPartyGadgets | GetterActiveMQObjectMessage | 4,074 | 3,670 | 404 | 9.9% |
| TransactionManagerReenlist | (default) | 922 | 542 | 380 | 41.2% |
| ViewState | TypeConfuseDelegate | 3,242 | 1,418 | 1,824 | 56.3% |

The crypto plugins (MachineKeySessionSecurityTokenHandler,
SessionSecurityTokenHandler) wrap the payload in an encrypted and encoded envelope.
The reduction there comes from the smaller inner payload passing through a
size-preserving transform, so it is a real cut even though the outer bytes are opaque.

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
