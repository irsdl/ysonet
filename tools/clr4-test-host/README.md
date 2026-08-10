# CLR 4 test host

`ysonet.Clr4TestHost.exe` is a deliberately unsafe, one-shot deserialization victim for
the installed .NET Framework 4.x runtime (CLR 4). It fires a payload locally so you can
confirm it works on CLR 4. It is built beside `ysonet.exe` and is a developer/operator
tool, not a product self-test feature.

Unlike `ysonet.Net40TestHost.exe`, it does NOT require the exact .NET Framework 4.0 shape.
It runs on whatever 4.x is installed (4.7.2, 4.8, 4.8.1, ...), which is what a normal
machine has. Use the net40 host only when you specifically need a genuine 4.0 victim (an
isolated 4.0 VM), for a gadget such as `TypeConfuseDelegateNet40Workflow` that only fires
on true 4.0.

## Usage

```text
--probe
    Print the runtime this process is on and exit 0.

--deserialize FORMATTER FILE [--input auto|raw|base64]
    Deserialize FILE with FORMATTER on this CLR 4 runtime.
    FORMATTER is BinaryFormatter, SoapFormatter or LosFormatter (case-insensitive).
    FILE is a path, or - to read the payload from stdin.
```

`--input` says how `FILE` is read. The default `auto` detects base64 vs raw from the bytes:
a base64-looking `BinaryFormatter` or `SoapFormatter` file is decoded, raw bytes are used
as-is, and `LosFormatter` is always read raw because its payload is itself a base64 string
that the formatter consumes directly. So a payload made with
`ysonet.exe -g <gadget> -f <formatter> -c <cmd>` reads correctly with or without `-o`.

Example (fires calc on the installed CLR 4):

```text
ysonet.exe -g TypeConfuseDelegate -f BinaryFormatter -c calc > bf.b64
ysonet.Clr4TestHost.exe --deserialize BinaryFormatter bf.b64
```

## ViewState

An UNENCRYPTED `__VIEWSTATE` is a `LosFormatter` string, so read it with `LosFormatter`
(the default `auto` keeps it raw). An ENCRYPTED or MAC-protected `__VIEWSTATE` must first be
unwrapped with the target's machine keys (validation/decryption key and algorithms) to
recover the plain `ObjectStateFormatter` string. This host does not hold those keys and
does not perform that step; that path belongs to the ViewState workflow that has the keys.

## Safety

This executable intentionally deserializes untrusted `BinaryFormatter`, `SoapFormatter`,
and `LosFormatter` data on the live runtime, which runs the payload. Only feed it payloads
you are willing to execute on this machine, and prefer a disposable environment.
