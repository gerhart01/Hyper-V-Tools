/*
 * File: Core/HyperVCallProcessor.cs
 * Project: Extract.Hvcalls GUI v2.0.20250.102
 * Namespace: HvcallGui.Core
 * 
 * Description: Integrated hypervisor call processor with IDA automation and JSON processing
 * Author: Gerhart
 * License: GPL3
 * 
 * Change Log:
 * - v2.0.20250.102: Integrated HypervisorCallModule.cs functionality, removed Python dependency
 */

using System.Diagnostics;
using System.Text.Json;

namespace HvcallGui.Views
{
    #region Configuration and Constants
    
    /// <summary>
    /// Configuration constants for hypervisor call processing
    /// </summary>
    public static class HypervisorConstants
    {
        public const string JSON_OUTPUT_DIRECTORY = "hvcalls_json_files";
        public const string RESULTS_DIRECTORY = "result";
        public const string UNKNOWN_DIRECTORY = "unknown";
        public const string JSON_EXTENSION = "*.json";
        
        public const string OUTPUT_RESULTS_FILE = "hvcalls_results.json";
        public const string OUTPUT_DUPLICATES_FILE = "hvcalls_results_with_duplicates.json";
        public const string OUTPUT_UNKNOWN_FILE = "hvcalls_unknown.json";
        
        public const string DEFAULT_SCRIPT_NAME = "extract_hvcalls.py";
        
        public const int PARAMETER_MASK = 0xFFF;
        public const int PARAMETER_THRESHOLD = 0x1000;
        
        public static readonly Dictionary<string, string> NAME_REPLACEMENTS = new()
        {
            { "WinHvp", "HvCall" },
            { "WinHv", "HvCall" },
            { "Shvl", "HvCall" },
            { "Skhal", "HvCall" },
            { "Hvlp", "HvCall" },
            { "Hvl", "HvCall" },
            { "Sk", "HvCall" },
            { "Ium", "HvCallIum" }
        };
    }

    #endregion

    #region JSON Processing Core

    /// <summary>
    /// Core JSON file processor for hypervisor call data
    /// </summary>
    internal sealed class JsonFileProcessor
    {
        private readonly Action<string> _logger;
        private readonly JsonSerializerOptions _jsonOptions;

        public JsonFileProcessor(Action<string> logger)
        {
            _logger = logger;
            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                ReadCommentHandling = JsonCommentHandling.Skip,
                WriteIndented = true,
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            };
        }

        public async Task<Dictionary<string, object>> LoadJsonFileAsync(string filePath, CancellationToken ct = default)
        {
            if (!File.Exists(filePath))
            {
                _logger($"Warning: File not found: {filePath}");
                return new Dictionary<string, object>();
            }

            try
            {
                var content = await File.ReadAllTextAsync(filePath, ct);
                if (string.IsNullOrWhiteSpace(content))
                    return new Dictionary<string, object>();

                var data = JsonSerializer.Deserialize<Dictionary<string, object>>(content, _jsonOptions);
                return data ?? new Dictionary<string, object>();
            }
            catch (JsonException ex)
            {
                _logger($"JSON error in {Path.GetFileName(filePath)}: {ex.Message}");
                return new Dictionary<string, object>();
            }
        }

        public async Task SaveJsonFileAsync<T>(string filePath, Dictionary<string, T> data, CancellationToken ct = default)
        {
            if (data == null || !data.Any())
                return;

            var directory = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                Directory.CreateDirectory(directory);

            var content = JsonSerializer.Serialize(data, _jsonOptions);
            await File.WriteAllTextAsync(filePath, content, ct);
            _logger($"Saved: {Path.GetFileName(filePath)} ({data.Count} entries)");
        }

        public Dictionary<int, string> ConvertToIntKeys(Dictionary<string, object> data)
        {
            var result = new Dictionary<int, string>();
            
            foreach (var kvp in data)
            {
                if (TryParseHexKey(kvp.Key, out var intKey))
                    result[intKey] = kvp.Value?.ToString() ?? string.Empty;
            }

            return result;
        }

        private static bool TryParseHexKey(string key, out int result)
        {
            if (int.TryParse(key, out result))
                return true;

            if (key.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                return int.TryParse(key[2..], System.Globalization.NumberStyles.HexNumber, null, out result);

            return int.TryParse(key, System.Globalization.NumberStyles.HexNumber, null, out result);
        }
    }

    /// <summary>
    /// Processes hypervisor call data with duplicate detection and parameter removal
    /// </summary>
    internal sealed class HypervisorDataProcessor
    {
        private readonly JsonFileProcessor _fileProcessor;
        private readonly Action<string> _logger;

        public HypervisorDataProcessor(JsonFileProcessor fileProcessor, Action<string> logger)
        {
            _fileProcessor = fileProcessor;
            _logger = logger;
        }

        public async Task<Dictionary<int, string>> ProcessStandardFilesAsync(string inputDir, CancellationToken ct)
        {
            var combined = new Dictionary<string, object>();
            var files = Directory.GetFiles(inputDir, HypervisorConstants.JSON_EXTENSION);

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                
                var data = await _fileProcessor.LoadJsonFileAsync(file, ct);
                if (!data.Any())
                    continue;

                _logger($"Processing {Path.GetFileName(file)}... ({data.Count} calls)");
                
                FindDuplicates(combined, data);
                MergeDictionaries(combined, data);
            }

            var intDict = _fileProcessor.ConvertToIntKeys(combined);
            var cleaned = RemoveParameterVariants(intDict);
            ApplyNameCorrections(cleaned);

            return cleaned;
        }

        public async Task<Dictionary<int, List<string>>> ProcessWithDuplicatesAsync(string inputDir, CancellationToken ct)
        {
            var result = new Dictionary<int, List<string>>();
            var files = Directory.GetFiles(inputDir, HypervisorConstants.JSON_EXTENSION);

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                
                var data = await _fileProcessor.LoadJsonFileAsync(file, ct);
                if (!data.Any())
                    continue;

                var fileName = Path.GetFileName(file);
                var intData = _fileProcessor.ConvertToIntKeys(data);
                MergeWithDuplicateTracking(result, intData, fileName);
            }

            return result;
        }

        private void FindDuplicates(Dictionary<string, object> dict1, Dictionary<string, object> dict2)
        {
            var duplicateKeys = dict1.Keys.Intersect(dict2.Keys).ToList();
            if (duplicateKeys.Any())
                _logger($"  Found {duplicateKeys.Count} duplicate keys");
        }

        private static void MergeDictionaries(Dictionary<string, object> target, Dictionary<string, object> source)
        {
            foreach (var kvp in source)
                target[kvp.Key] = kvp.Value;
        }

        private Dictionary<int, string> RemoveParameterVariants(Dictionary<int, string> calls)
        {
            var result = new Dictionary<int, string>();
            var removed = 0;

            foreach (var kvp in calls)
            {
                var baseKey = kvp.Key & HypervisorConstants.PARAMETER_MASK;

                if (calls.ContainsKey(baseKey) && kvp.Key > HypervisorConstants.PARAMETER_THRESHOLD)
                {
                    removed++;
                }
                else
                {
                    result[baseKey] = kvp.Value;
                }
            }

            if (removed > 0)
                _logger($"Removed {removed} parameter variants");

            return result;
        }

        private static void ApplyNameCorrections(Dictionary<int, string> calls)
        {
            var keys = calls.Keys.ToList();
            
            foreach (var key in keys)
            {
                var name = calls[key];
                foreach (var replacement in HypervisorConstants.NAME_REPLACEMENTS)
                    name = name.Replace(replacement.Key, replacement.Value);
                
                calls[key] = name;
            }
        }

        private void MergeWithDuplicateTracking(Dictionary<int, List<string>> target, 
            Dictionary<int, string> source, string fileName)
        {
            foreach (var kvp in source)
            {
                var key = kvp.Key;
                var value = $"{kvp.Value}_{fileName}";
                var baseKey = key & HypervisorConstants.PARAMETER_MASK;

                if (!target.ContainsKey(key))
                    target[key] = new List<string>();

                if (!target[key].Contains(value))
                    target[key].Add(value);
            }
        }

        public static Dictionary<string, T> ConvertToHexKeys<T>(Dictionary<int, T> data)
        {
            return data.OrderBy(x => x.Key)
                      .ToDictionary(x => $"0x{x.Key:X}", x => x.Value);
        }
    }

    #endregion

    #region Main Processor

    /// <summary>
    /// Complete hypervisor call extraction and processing pipeline
    /// </summary>
    public sealed class IntegratedHyperVCallProcessor
    {
        private readonly Action<string> _logger;
        private readonly JsonFileProcessor _fileProcessor;
        private readonly HypervisorDataProcessor _dataProcessor;

        public IntegratedHyperVCallProcessor(Action<string> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _fileProcessor = new JsonFileProcessor(_logger);
            _dataProcessor = new HypervisorDataProcessor(_fileProcessor, _logger);
        }

        /// <summary>
        /// Executes complete extraction pipeline: IDA processing + JSON merging
        /// </summary>
        public async Task ProcessHyperVCallsAsync(
            string binaryDirectory,
            string idaPath,
            string scriptDirectory,
            string outputDirectory,
            bool processIdbFiles,
            CancellationToken ct = default)
        {
            ValidateInputs(binaryDirectory, idaPath, scriptDirectory);

            var jsonOutputDir = Path.Combine(scriptDirectory, HypervisorConstants.JSON_OUTPUT_DIRECTORY);
            EnsureDirectoryExists(jsonOutputDir);

            _logger("=== Starting IDA Pro processing ===");
            await RunIdaProcessingAsync(binaryDirectory, idaPath, scriptDirectory, processIdbFiles, ct);
            
            _logger("=== IDA processing complete ===");
            _logger("=== Starting JSON file processing ===");
            
            await ProcessJsonFilesAsync(jsonOutputDir, outputDirectory, ct);
            
            _logger("=== Processing complete ===");
        }

        /// <summary>
        /// Copies Windows Hyper-V system binaries to target directory
        /// </summary>
        public void CopySystemBinaries(string targetDirectory)
        {
            EnsureDirectoryExists(targetDirectory);

            var systemDir = Environment.GetFolderPath(Environment.SpecialFolder.System);
            var files = AppConstants.HV_FILES;
            var copied = 0;

            foreach (var file in files)
            {
                var sourcePath = file.EndsWith(AppConstants.SYS_EXTENSION)
                    ? Path.Combine(systemDir, AppConstants.DRIVERS_SUBDIR, file)
                    : Path.Combine(systemDir, file);

                var destPath = Path.Combine(targetDirectory, file);

                try
                {
                    if (!File.Exists(sourcePath))
                    {
                        _logger($"Not found: {file}");
                        continue;
                    }

                    if (File.Exists(destPath))
                    {
                        _logger($"Already exists: {file}");
                        continue;
                    }

                    File.Copy(sourcePath, destPath);
                    _logger($"Copied: {file}");
                    copied++;
                }
                catch (Exception ex)
                {
                    _logger($"Error copying {file}: {ex.Message}");
                }
            }

            _logger($"Binary copy completed: {copied} files copied");
        }

        #region Private Methods

        private void ValidateInputs(string binaryDir, string idaPath, string scriptDir)
        {
            if (!Directory.Exists(binaryDir))
                throw new DirectoryNotFoundException($"Binary directory not found: {binaryDir}");

            if (!File.Exists(idaPath))
                throw new FileNotFoundException($"IDA executable not found: {idaPath}");

            if (!Directory.Exists(scriptDir))
                throw new DirectoryNotFoundException($"Script directory not found: {scriptDir}");
        }

        private void EnsureDirectoryExists(string path)
        {
            if (!Directory.Exists(path))
            {
                Directory.CreateDirectory(path);
                _logger($"Created directory: {path}");
            }
        }

        private async Task RunIdaProcessingAsync(string binaryDir, string idaPath, 
            string scriptDir, bool processIdb, CancellationToken ct)
        {
            var scriptPath = Path.Combine(scriptDir, AppConstants.EXTRACT_SCRIPT);
            if (!File.Exists(scriptPath))
                throw new FileNotFoundException($"Script not found: {scriptPath}");

            var executableFiles = Directory.GetFiles(binaryDir, "*.*")
                .Where(f => f.EndsWith(AppConstants.SYS_EXTENSION) || f.EndsWith(AppConstants.EXE_EXTENSION));

            var tasks = new List<Task>();

            foreach (var file in executableFiles)
            {
                ct.ThrowIfCancellationRequested();
                
                var args = BuildIdaArguments(file, scriptPath, processIdb);
                _logger($"Processing: {Path.GetFileName(file)}");
                
                tasks.Add(RunIdaProcessAsync(idaPath, args, ct));
            }

            await Task.WhenAll(tasks);
        }

        private string BuildIdaArguments(string binaryPath, string scriptPath, bool processIdb)
        {
            var quotedScript = $"\"{scriptPath}\"";
            var idbPath = binaryPath + AppConstants.I64_EXTENSION;

            if (File.Exists(idbPath))
                return $"-A -S{quotedScript} \"{idbPath}\"";

            var mode = processIdb ? "-c -A" : "-c -B";
            return $"{mode} -S{quotedScript} \"{binaryPath}\"";
        }

        private async Task RunIdaProcessAsync(string idaPath, string arguments, CancellationToken ct)
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = idaPath,
                    Arguments = arguments,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                }
            };

            process.Start();
            await process.WaitForExitAsync(ct);

            if (process.ExitCode != 0)
            {
                var error = await process.StandardError.ReadToEndAsync(ct);
                _logger($"IDA warning: {error}");
            }
        }

        private async Task ProcessJsonFilesAsync(string inputDir, string outputDir, CancellationToken ct)
        {
            EnsureDirectoryExists(outputDir);

            if (!Directory.Exists(inputDir) || !Directory.GetFiles(inputDir, HypervisorConstants.JSON_EXTENSION).Any())
            {
                _logger("No JSON files found to process");
                return;
            }

            // Process standard files
            var standardData = await _dataProcessor.ProcessStandardFilesAsync(inputDir, ct);
            if (standardData.Any())
            {
                var resultsPath = Path.Combine(outputDir, HypervisorConstants.OUTPUT_RESULTS_FILE);
                var hexData = HypervisorDataProcessor.ConvertToHexKeys(standardData);
                await _fileProcessor.SaveJsonFileAsync(resultsPath, hexData, ct);
            }

            // Process with duplicates
            var duplicatesData = await _dataProcessor.ProcessWithDuplicatesAsync(inputDir, ct);
            if (duplicatesData.Any())
            {
                var duplicatesPath = Path.Combine(outputDir, HypervisorConstants.OUTPUT_DUPLICATES_FILE);
                var hexData = HypervisorDataProcessor.ConvertToHexKeys(duplicatesData);
                await _fileProcessor.SaveJsonFileAsync(duplicatesPath, hexData, ct);
            }

            // Process unknown files
            var unknownDir = Path.Combine(inputDir, HypervisorConstants.UNKNOWN_DIRECTORY);
            if (Directory.Exists(unknownDir))
            {
                var unknownData = await _dataProcessor.ProcessStandardFilesAsync(unknownDir, ct);
                if (unknownData.Any())
                {
                    var unknownPath = Path.Combine(outputDir, HypervisorConstants.OUTPUT_UNKNOWN_FILE);
                    var hexData = HypervisorDataProcessor.ConvertToHexKeys(unknownData);
                    await _fileProcessor.SaveJsonFileAsync(unknownPath, hexData, ct);
                }
            }
        }

        #endregion
    }

    #endregion
}
