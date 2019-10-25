using System.IO;
using System.Text;
using System.Text.Json;

namespace Myvas.AspNetCore.Authentication.WeixinAuth.Internal
{
    internal static class JsonDocumentAuthExtensions
    {
        public static string GetString(this JsonElement element, string key)
        {
            if (element.TryGetProperty(key, out var property) && property.ValueKind != JsonValueKind.Null)
            {
                return property.ToString();
            }

            return null;
        }

        public static string GetString(this JsonDocument doc, string key)
        {
            return doc.RootElement.GetString(key);
        }

        public static int GetInt32(this JsonElement element, string key, int defaultValue = 0)
        {
            var s = element.GetString(key);
            try { return int.Parse(s); } catch { return defaultValue; }
        }

        public static string[] GetStringArray(this JsonElement element, string key)
        {
            var s = element.GetString(key);
            try { return s.Split(',', System.StringSplitOptions.RemoveEmptyEntries); } catch { return null; }
        }

        public static JsonDocument AppendElement(this JsonDocument doc, string name, string value)
        {
            using (var ms = new MemoryStream())
            {
                using (var writer = new Utf8JsonWriter(ms))
                {
                    writer.WriteStartObject();

                    foreach (var existElement in doc.RootElement.EnumerateObject())
                    {
                        existElement.WriteTo(writer);
                    }

                    // Append new element
                    writer.WritePropertyName(name);
                    writer.WriteStringValue(value);

                    writer.WriteEndObject();
                }

                var resultJson = Encoding.UTF8.GetString(ms.ToArray());
                return JsonDocument.Parse(resultJson);
            }
        }
        public static JsonDocument AppendElement(this JsonDocument doc, JsonElement element)
        {
            using (var ms = new MemoryStream())
            {
                using (var writer = new Utf8JsonWriter(ms))
                {
                    writer.WriteStartObject();

                    foreach (var existElement in doc.RootElement.EnumerateObject())
                    {
                        existElement.WriteTo(writer);
                    }

                    element.WriteTo(writer);

                    writer.WriteEndObject();
                }

                var resultJson = Encoding.UTF8.GetString(ms.ToArray());
                return JsonDocument.Parse(resultJson);
            }
        }
    }
}
