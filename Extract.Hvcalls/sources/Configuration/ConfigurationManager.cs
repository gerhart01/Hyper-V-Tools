/*
 * File: Configuration/ConfigurationManager.cs
 * Project: Extract.Hvcalls GUI v2.0.20250.101
 * Namespace: HvcallGui.Configuration
 * 
 * Description: Configuration file management with JSON serialization and validation
 * Author: Gerhart
 * License: GPL3
 * 
 * Change Log:
 * - v2.0.20250.100: Extracted configuration logic, added validation, improved error handling
 * - v2.0.20250.101: Added proper C# documentation and error handling
 */

using System.Text.Json;

namespace HvcallGui.Views
{
    /// <summary>
    /// Represents configuration settings loaded from JSON file
    /// </summary>
    /// <param name="IdaPath">Full path to IDA Pro executable</param>
    /// <param name="WindowsBinaryPath">Directory containing Windows system binaries</param>
    /// <param name="ScriptPath">Directory containing Python extraction scripts</param>
    public record ConfigFile(string IdaPath, string WindowsBinaryPath, string ScriptPath, string ResultPath);
    
    /// <summary>
    /// Manages application configuration loading, validation, and default value creation
    /// </summary>
    public static class ConfigurationManager
    {
        #region Public Methods
        /// <summary>
        /// Reads configuration from the specified JSON file path
        /// </summary>
        /// <param name="configPath">Full path to the configuration file</param>
        /// <returns>Configuration object or default configuration if file is invalid</returns>
        public static ConfigFile? ReadConfiguration(string configPath)
        {
            if (!ValidateConfigurationPath(configPath))
                return CreateDefaultConfiguration();

            try
            {
                var jsonString = File.ReadAllText(configPath);
                var config = JsonSerializer.Deserialize<ConfigFile>(jsonString);
                return config ?? CreateDefaultConfiguration();
            }
            catch (JsonException)
            {
                // Return default configuration if JSON is malformed
                return CreateDefaultConfiguration();
            }
            catch (IOException)
            {
                // Return default configuration if file cannot be read
                return CreateDefaultConfiguration();
            }
        }

        /// <summary>
        /// Gets the standard configuration file path in the application directory
        /// </summary>
        /// <returns>Full path to config.json file</returns>
        public static string GetConfigurationPath()
        {
            return Path.Combine(Directory.GetCurrentDirectory(), AppConstants.CONFIG_FILE);
        }
        #endregion

        #region Private Helper Methods
        /// <summary>
        /// Validates that the configuration file path exists and is accessible
        /// </summary>
        /// <param name="configPath">Path to validate</param>
        /// <returns>True if path is valid and file exists</returns>
        private static bool ValidateConfigurationPath(string configPath)
        {
            return !string.IsNullOrWhiteSpace(configPath) && File.Exists(configPath);
        }

        /// <summary>
        /// Creates a default configuration with placeholder paths
        /// </summary>
        /// <returns>Default configuration object</returns>
        private static ConfigFile CreateDefaultConfiguration()
        {
            return new ConfigFile(
                $"C:\\PathToIda\\{AppConstants.IDA_EXECUTABLE}",
                "C:\\Windows\\system32\\",
                "C:\\PathToPythonScript",
                "C:\\PathToResultSaveDir"
            );
        }
        #endregion
    }
}