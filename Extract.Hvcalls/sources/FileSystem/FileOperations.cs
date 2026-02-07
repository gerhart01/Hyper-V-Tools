/*
 * File: FileSystem/FileOperations.cs
 * Project: Extract.Hvcalls GUI v2.0.20250.101
 * Namespace: HvcallGui.FileSystem
 * 
 * Description: File system operations for copying Hyper-V binaries and managing executable files
 * Author: Gerhart
 * License: GPL3
 * 
 * Change Log:
 * - v2.0.20250.100: Extracted file operations, improved error handling, added validation
 * - v2.0.20250.101: Added proper error handling and file enumeration
 */

using System.Diagnostics;

namespace HvcallGui.Views
{
    /// <summary>
    /// Provides file system operations for Hyper-V binary management
    /// </summary>
    public static class FileOperations
    {
        #region Public Methods
        /// <summary>
        /// Copies Hyper-V system binaries from Windows system directories to target directory
        /// </summary>
        /// <param name="hvFiles">Array of Hyper-V file names to copy</param>
        /// <param name="targetDirectory">Destination directory for copied files</param>
        /// <param name="logger">Callback for logging copy operations</param>
        /// <exception cref="ArgumentNullException">Thrown when parameters are null</exception>
        /// <exception cref="ArgumentException">Thrown when targetDirectory is invalid</exception>
        public static void CopyHyperVBinaries(string[] hvFiles, string targetDirectory, Action<string> logger)
        {
            ValidateParameters(hvFiles, targetDirectory, logger);
            
            EnsureDirectoryExists(targetDirectory, logger);
            var systemDirectory = Environment.GetFolderPath(Environment.SpecialFolder.System);

            foreach (var fileName in hvFiles)
            {
                ProcessHyperVFile(fileName, systemDirectory, targetDirectory, logger);
            }
        }

        /// <summary>
        /// Gets all executable files (.sys and .exe) from the specified directory
        /// </summary>
        /// <param name="directory">Directory to search for executable files</param>
        /// <returns>Enumerable of executable file paths</returns>
        public static IEnumerable<string> GetExecutableFiles(string directory)
        {
            if (!Directory.Exists(directory))
                return Enumerable.Empty<string>();

            var supportedExtensions = new[] { AppConstants.SYS_EXTENSION, AppConstants.EXE_EXTENSION };
            
            return Directory.EnumerateFiles(directory, "*.*", SearchOption.TopDirectoryOnly)
                .Where(file => supportedExtensions.Any(file.EndsWith));
        }
        #endregion

        #region Private Helper Methods
        /// <summary>
        /// Validates input parameters for file operations
        /// </summary>
        /// <param name="hvFiles">Array of file names</param>
        /// <param name="targetDirectory">Target directory path</param>
        /// <param name="logger">Logger callback</param>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null</exception>
        /// <exception cref="ArgumentException">Thrown when targetDirectory is invalid</exception>
        private static void ValidateParameters(string[] hvFiles, string targetDirectory, Action<string> logger)
        {
            ArgumentNullException.ThrowIfNull(hvFiles);
            ArgumentException.ThrowIfNullOrWhiteSpace(targetDirectory);
            ArgumentNullException.ThrowIfNull(logger);
        }

        /// <summary>
        /// Ensures the target directory exists, creating it if necessary
        /// </summary>
        /// <param name="directory">Directory path to ensure exists</param>
        /// <param name="logger">Logger for status messages</param>
        private static void EnsureDirectoryExists(string directory, Action<string> logger)
        {
            if (Directory.Exists(directory)) 
                return;

            logger(string.Format(AppConstants.ERROR_DIRECTORY_NOT_FOUND, directory));
            Directory.CreateDirectory(directory);
        }

        /// <summary>
        /// Processes a single Hyper-V file for copying
        /// </summary>
        /// <param name="fileName">Name of the file to copy</param>
        /// <param name="systemDirectory">Windows system directory</param>
        /// <param name="targetDirectory">Destination directory</param>
        /// <param name="logger">Logger for status messages</param>
        private static void ProcessHyperVFile(string fileName, string systemDirectory, 
            string targetDirectory, Action<string> logger)
        {
            var sourceFile = BuildSourcePath(fileName, systemDirectory);
            var destinationFile = Path.Combine(targetDirectory, fileName);

            if (!File.Exists(sourceFile))
            {
                logger(string.Format(AppConstants.ERROR_FILE_NOT_FOUND, fileName));
                return;
            }

            if (File.Exists(destinationFile))
            {
                logger(string.Format(AppConstants.ERROR_FILE_EXISTS, destinationFile));
                return;
            }

            File.Copy(sourceFile, destinationFile);
            logger(string.Format(AppConstants.SUCCESS_FILE_COPIED, sourceFile, destinationFile));
        }

        /// <summary>
        /// Builds the full source path for a Hyper-V system file
        /// </summary>
        /// <param name="fileName">Name of the file</param>
        /// <param name="systemDirectory">Windows system directory</param>
        /// <returns>Full path to the source file</returns>
        private static string BuildSourcePath(string fileName, string systemDirectory)
        {
            var subdirectory = fileName.EndsWith(AppConstants.SYS_EXTENSION) ? 
                AppConstants.DRIVERS_SUBDIR : string.Empty;
            
            return Path.Combine(systemDirectory, subdirectory, fileName);
        }
        #endregion
    }
}
