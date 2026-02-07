/*
 * File: Core/HyperVCallExtractor.cs
 * Project: Extract.Hvcalls GUI v2.0.20250.101
 * Namespace: HvcallGui.Core
 * 
 * Description: Core business logic for extracting Hyper-V system calls using IDA Pro
 * Author: Gerhart
 * License: GPL3
 * 
 * Change Log:
 * - v2.0.20250.100: Refactored main extraction logic, improved validation, modernized async patterns
 * - v2.0.20250.101: Fixed ambiguous method calls, ensured single class definition
 */

using System.Diagnostics;

namespace HvcallGui.Views
{
    /// <summary>
    /// Parameters required for hypercall extraction process
    /// </summary>
    /// <param name="BinaryDirectory">Directory containing Hyper-V binaries</param>
    /// <param name="IdaPath">Full path to IDA Pro executable</param>
    /// <param name="ScriptDirectory">Directory containing Python scripts</param>
    /// <param name="ScriptName">Name of the extraction script</param>
    /// <param name="UnionScriptName">Name of the merge script</param>
    /// <param name="ProcessIdbFiles">Whether to process existing IDB files</param>
    public record ExtractionParameters(
        string BinaryDirectory,
        string IdaPath,
        string ScriptDirectory,
        string ScriptName,
        string UnionScriptName,
        bool ProcessIdbFiles
    );

    /// <summary>
    /// Main class responsible for extracting Hyper-V system calls using IDA Pro and Python scripts
    /// </summary>
    public sealed class HyperVCallExtractor
    {
        #region Private Fields
        private readonly Action<string> _logger;
        #endregion

        #region Constructor
        /// <summary>
        /// Initializes a new instance of the HyperVCallExtractor
        /// </summary>
        /// <param name="logger">Callback for logging extraction progress</param>
        /// <exception cref="ArgumentNullException">Thrown when logger is null</exception>
        public HyperVCallExtractor(Action<string> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Performs the complete hypercall extraction process asynchronously
        /// </summary>
        /// <param name="parameters">Extraction configuration parameters</param>
        /// <returns>A task representing the asynchronous operation</returns>
        public async Task ExtractHyperVCalls(ExtractionParameters parameters)
        {
            ValidateExtractionParameters(parameters);

            var scriptArguments = PrepareScriptArguments(parameters);
            await ProcessManager.RunParallelProcesses(parameters.IdaPath, scriptArguments);

            _logger(AppConstants.SUCCESS_PROCESSING_COMPLETE);

            ExecuteMergeScript(parameters);
            _logger(AppConstants.SUCCESS_FILES_MERGED);
        }

        /// <summary>
        /// Copies Hyper-V system binaries from the current Windows installation
        /// </summary>
        /// <param name="targetDirectory">Directory to copy binaries to</param>
        public void CopySystemBinaries(string targetDirectory)
        {
            FileOperations.CopyHyperVBinaries(AppConstants.HV_FILES, targetDirectory, _logger);
        }
        #endregion

        #region Private Helper Methods
        /// <summary>
        /// Validates that all required extraction parameters are valid
        /// </summary>
        /// <param name="parameters">Parameters to validate</param>
        private void ValidateExtractionParameters(ExtractionParameters parameters)
        {
            ArgumentNullException.ThrowIfNull(parameters);

            if (!Directory.Exists(parameters.BinaryDirectory))
                throw new DirectoryNotFoundException(AppConstants.ERROR_SPECIFY_BINARY_DIR);

            if (!File.Exists(parameters.IdaPath))
                throw new FileNotFoundException(AppConstants.ERROR_SPECIFY_IDA_PATH);

            if (!Directory.Exists(parameters.ScriptDirectory))
                throw new DirectoryNotFoundException(AppConstants.ERROR_SPECIFY_SCRIPT_DIR);
        }

        /// <summary>
        /// Prepares command line arguments for IDA Pro script execution
        /// </summary>
        /// <param name="parameters">Extraction parameters</param>
        /// <returns>List of command line arguments for each binary file</returns>
        private List<string> PrepareScriptArguments(ExtractionParameters parameters)
        {
            var scriptArguments = new List<string>();
            var hvFiles = FileOperations.GetExecutableFiles(parameters.BinaryDirectory);

            foreach (var filePath in hvFiles)
            {
                var argument = BuildIdaArgument(filePath, parameters);
                scriptArguments.Add(argument);
                LogFileProcessing(filePath);
            }

            return scriptArguments;
        }

        /// <summary>
        /// Builds IDA Pro command line argument for a specific binary file
        /// </summary>
        /// <param name="filePath">Path to the binary file to process</param>
        /// <param name="parameters">Extraction parameters</param>
        /// <returns>IDA Pro command line argument string</returns>
        private string BuildIdaArgument(string filePath, ExtractionParameters parameters)
        {
            var scriptPath = Path.Combine(parameters.ScriptDirectory, parameters.ScriptName);
            var quotedScriptPath = $"\"{scriptPath}\"";
            var idbPath = $"{filePath}{AppConstants.I64_EXTENSION}";

            if (File.Exists(idbPath))
            {
                return $"-A -S{quotedScriptPath} \"{idbPath}\"";
            }

            var processingFlag = parameters.ProcessIdbFiles ? "-c -A" : "-c -B";
            var quotedFilePath = $"\"{filePath}\"";

            return $"{processingFlag} -S{quotedScriptPath} {quotedFilePath}";
        }

        /// <summary>
        /// Logs the processing status for a specific file
        /// </summary>
        /// <param name="filePath">Path to the file being processed</param>
        private void LogFileProcessing(string filePath)
        {
            var fileVersion = FileVersionInfo.GetVersionInfo(filePath);
            var fileName = Path.GetFileName(filePath);
            var version = fileVersion.FileVersion ?? "Unknown";

            var idbPath = $"{filePath}{AppConstants.I64_EXTENSION}";
            var message = File.Exists(idbPath)
                ? string.Format(AppConstants.PROCESSING_I64_FILE, Path.GetFileNameWithoutExtension(filePath) + AppConstants.I64_EXTENSION, version)
                : string.Format(AppConstants.PROCESSING_FILE, fileName, version);

            _logger(message);
        }

        /// <summary>
        /// Executes the Python merge script to combine extraction results
        /// </summary>
        /// <param name="parameters">Extraction parameters containing script paths</param>
        private void ExecuteMergeScript(ExtractionParameters parameters)
        {
            var pythonPath = PythonPathResolver.GetPythonPath();
            var scriptPath = Path.Combine(parameters.ScriptDirectory, parameters.UnionScriptName);

            ProcessManager.ExecuteScript(pythonPath, scriptPath);
        }
        #endregion
    }
}