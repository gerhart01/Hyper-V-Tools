/*
 * File: Configuration/AppJsonContext.cs
 * Project: Extract.Hvcalls GUI v2.0.20250.102
 * Namespace: HvcallGui.Views
 *
 * Description: Source-generated JSON serializer context for trimming/AOT compatibility
 * Author: Gerhart
 * License: GPL3
 */

using System.Text.Json;
using System.Text.Json.Serialization;

namespace HvcallGui.Views
{
    [JsonSourceGenerationOptions(
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        WriteIndented = true)]
    [JsonSerializable(typeof(ConfigFile))]
    [JsonSerializable(typeof(Dictionary<string, object>))]
    [JsonSerializable(typeof(Dictionary<string, string>))]
    internal partial class AppJsonContext : JsonSerializerContext
    {
    }
}
