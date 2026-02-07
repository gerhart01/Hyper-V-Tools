/*
 * File: Processing/ProcessManager.cs
 * Project: Extract.Hvcalls GUI v2.0.20250.101
 * Namespace: HvcallGui.Processing
 * 
 * Description: Process management for running IDA Pro and Python scripts
 * Author: Gerhart
 * License: GPL3
 * 
 * Change Log:
 * - v2.0.20250.100: Extracted process management, improved parallel execution, added validation
 * - v2.0.20250.101: Added proper async process execution and error handling
 */

using System.Diagnostics;

namespace HvcallGui.Views
{
    /// <summary>
    /// Manages external process execution for IDA Pro and Python scripts
    /// </summary>
    public static class ProcessManager
    {
        #region Public Methods
        /// <summary>
        /// Runs multiple processes in parallel with the same executable and different arguments
        /// </summary>
        /// <param name="executablePath">Path to the executable to run</param>
        /// <param name="arguments">Collection of argument strings for each process</param>
        /// <returns>A task that completes when all processes finish</returns>
        /// <exception cref="ArgumentException">Thrown when executablePath is invalid</exception>
        /// <exception cref="ArgumentNullException">Thrown when arguments is null</exception>
        /// <exception cref="FileNotFoundException">Thrown when executable is not found</exception>
        public static async Task RunParallelProcesses(string executablePath, IEnumerable<string> arguments)
        {
            ValidateParameters(executablePath, arguments);

            var tasks = arguments.Select(arg => ExecuteProcessAsync(executablePath, arg));
            await Task.WhenAll(tasks);
        }

        /// <summary>
        /// Executes a script (typically Python) with the specified interpreter
        /// </summary>
        /// <param name="interpreterPath">Path to the script interpreter (e.g., python.exe)</param>
        /// <param name="scriptPath">Path to the script file to execute</param>
        /// <exception cref="ArgumentException">Thrown when paths are invalid</exception>
        /// <exception cref="FileNotFoundException">Thrown when script file is not found</exception>
        public static void ExecuteScript(string interpreterPath, string scriptPath)
        {
            ValidateScriptParameters(interpreterPath, scriptPath);
            
            var processInfo = CreateProcessStartInfo(interpreterPath, scriptPath);
            Process.Start(processInfo);
        }
        #endregion

        #region Private Helper Methods
        /// <summary>
        /// Validates parameters for parallel process execution
        /// </summary>
        /// <param name="executablePath">Path to executable</param>
        /// <param name="arguments">Collection of arguments</param>
        /// <exception cref="ArgumentException">Thrown when executablePath is invalid</exception>
        /// <exception cref="ArgumentNullException">Thrown when arguments is null</exception>
        /// <exception cref="FileNotFoundException">Thrown when executable is not found</exception>
        private static void ValidateParameters(string executablePath, IEnumerable<string> arguments)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
            ArgumentNullException.ThrowIfNull(arguments);
            
            if (!File.Exists(executablePath))
                throw new FileNotFoundException($"Executable not found: {executablePath}");
        }

        /// <summary>
        /// Executes a single process asynchronously
        /// </summary>
        /// <param name="executablePath">Path to the executable</param>
        /// <param name="arguments">Command line arguments</param>
        /// <returns>A task that completes when the process exits</returns>
        private static async Task ExecuteProcessAsync(string executablePath, string arguments)
        {
            var processInfo = CreateProcessStartInfo(executablePath, arguments);
            
            using var process = new Process { StartInfo = processInfo };
            process.Start();
            await process.WaitForExitAsync();
        }

        /// <summary>
        /// Creates a ProcessStartInfo object with standard configuration
        /// </summary>
        /// <param name="executablePath">Path to the executable</param>
        /// <param name="arguments">Command line arguments</param>
        /// <returns>Configured ProcessStartInfo object</returns>
        private static ProcessStartInfo CreateProcessStartInfo(string executablePath, string arguments)
        {
            return new ProcessStartInfo
            {
                FileName = executablePath,
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true
            };
        }

        /// <summary>
        /// Validates parameters for script execution
        /// </summary>
        /// <param name="interpreterPath">Path to script interpreter</param>
        /// <param name="scriptPath">Path to script file</param>
        /// <exception cref="ArgumentException">Thrown when paths are invalid</exception>
        /// <exception cref="FileNotFoundException">Thrown when script file is not found</exception>
        private static void ValidateScriptParameters(string interpreterPath, string scriptPath)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(interpreterPath);
            ArgumentException.ThrowIfNullOrWhiteSpace(scriptPath);
            
            if (!File.Exists(scriptPath))
                throw new FileNotFoundException($"Script not found: {scriptPath}");
        }
        #endregion
    }
}