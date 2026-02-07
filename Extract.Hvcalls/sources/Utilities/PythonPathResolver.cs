/*
 * File: Utilities/PythonPathResolver.cs
 * Project: Extract.Hvcalls GUI v2.0.20250.101
 * Namespace: HvcallGui.Utilities
 * 
 * Description: Registry-based Python installation discovery and version selection
 * Author: Gerhart
 * License: GPL3
 * 
 * Change Log:
 * - v2.0.20250.100: Extracted Python path resolution, improved registry handling, added version validation
 * - v2.0.20250.101: Added proper error handling and registry key management
 */

using Microsoft.Win32;

namespace HvcallGui.Views
{
    /// <summary>
    /// Resolves Python installation paths from Windows registry
    /// </summary>
    public static class PythonPathResolver
    {
        #region Private Constants
        private static readonly string[] PythonRegistryPaths = {
            AppConstants.HKLM_PYTHON_PATH,
            AppConstants.HKCU_PYTHON_PATH,
            AppConstants.WOW64_PYTHON_PATH
        };
        #endregion

        #region Public Methods
        /// <summary>
        /// Gets the best available Python installation path
        /// </summary>
        /// <param name="requiredVersion">Minimum required Python version (optional)</param>
        /// <param name="maxVersion">Maximum allowed Python version (optional)</param>
        /// <returns>Path to Python executable, or empty string if not found</returns>
        public static string GetPythonPath(string requiredVersion = "", string maxVersion = "")
        {
            var pythonLocations = DiscoverPythonInstallations();
            return SelectBestPythonVersion(pythonLocations, requiredVersion, maxVersion);
        }
        #endregion

        #region Private Helper Methods
        /// <summary>
        /// Discovers all Python installations from Windows registry
        /// </summary>
        /// <returns>Dictionary mapping version strings to executable paths</returns>
        private static Dictionary<string, string> DiscoverPythonInstallations()
        {
            var pythonLocations = new Dictionary<string, string>();

            foreach (var registryPath in PythonRegistryPaths)
            {
                try
                {
                    ProcessRegistryPath(registryPath, pythonLocations);
                }
                catch (Exception)
                {
                    // Continue to next registry path if one fails
                    continue;
                }
            }

            return pythonLocations;
        }

        /// <summary>
        /// Processes a single registry path for Python installations
        /// </summary>
        /// <param name="registryPath">Registry path to process</param>
        /// <param name="pythonLocations">Dictionary to add found installations to</param>
        private static void ProcessRegistryPath(string registryPath, Dictionary<string, string> pythonLocations)
        {
            var (registryKey, actualPath) = ParseRegistryPath(registryPath);
            if (registryKey == null) return;

            using var pathKey = registryKey.OpenSubKey(actualPath);
            if (pathKey == null) return;

            foreach (var versionKey in pathKey.GetSubKeyNames())
            {
                ProcessVersionKey(pathKey, versionKey, pythonLocations);
            }
        }

        /// <summary>
        /// Parses a registry path string into registry key and subpath
        /// </summary>
        /// <param name="registryPath">Full registry path string</param>
        /// <returns>Tuple of registry key and actual path</returns>
        private static (RegistryKey?, string) ParseRegistryPath(string registryPath)
        {
            var parts = registryPath.Split('\\', 2);
            if (parts.Length < 2) return (null, string.Empty);

            var registryHive = parts[0];
            var actualPath = parts[1];
            
            var baseKey = registryHive switch
            {
                "HKLM" => Registry.LocalMachine,
                "HKCU" => Registry.CurrentUser,
                _ => null
            };

            return (baseKey, actualPath);
        }

        /// <summary>
        /// Processes a single Python version key from the registry
        /// </summary>
        /// <param name="pathKey">Parent registry key</param>
        /// <param name="versionKey">Version key name</param>
        /// <param name="pythonLocations">Dictionary to add found installations to</param>
        private static void ProcessVersionKey(RegistryKey pathKey, string versionKey, Dictionary<string, string> pythonLocations)
        {
            try
            {
                using var productKey = pathKey.OpenSubKey(versionKey);
                if (productKey == null) return;

                using var installPathKey = productKey.OpenSubKey(AppConstants.INSTALL_PATH_KEY);
                if (installPathKey == null) return;

                var pythonPath = installPathKey.GetValue(AppConstants.EXECUTABLE_PATH_KEY)?.ToString();
                if (!string.IsNullOrEmpty(pythonPath))
                {
                    pythonLocations.TryAdd(versionKey, pythonPath);
                }
            }
            catch (Exception)
            {
                // Skip this version if registry access fails
            }
        }

        /// <summary>
        /// Selects the best Python version from available installations
        /// </summary>
        /// <param name="pythonLocations">Dictionary of available Python installations</param>
        /// <param name="requiredVersion">Minimum required version</param>
        /// <param name="maxVersion">Maximum allowed version</param>
        /// <returns>Path to best Python executable</returns>
        private static string SelectBestPythonVersion(Dictionary<string, string> pythonLocations, 
            string requiredVersion, string maxVersion)
        {
            if (pythonLocations.Count == 0)
                return string.Empty;

            var minVersion = new Version(string.IsNullOrEmpty(requiredVersion) ? 
                AppConstants.MIN_PYTHON_VERSION : requiredVersion);
            var maxVersionObj = new Version(string.IsNullOrEmpty(maxVersion) ? 
                AppConstants.MAX_PYTHON_VERSION : maxVersion);

            string bestPath = string.Empty;
            Version? bestVersion = null;

            foreach (var (versionString, path) in pythonLocations)
            {
                if (!TryParseVersionString(versionString, out var version))
                    continue;

                if (IsVersionInRange(version, minVersion, maxVersionObj) && 
                    (bestVersion == null || version > bestVersion))
                {
                    bestVersion = version;
                    bestPath = path;
                }
            }

            return bestPath;
        }

        /// <summary>
        /// Tries to parse a version string, handling Python-specific formatting
        /// </summary>
        /// <param name="versionString">Version string from registry</param>
        /// <param name="version">Parsed version object</param>
        /// <returns>True if parsing succeeded</returns>
        private static bool TryParseVersionString(string versionString, out Version version)
        {
            // Handle version strings like "3.9-32" by removing architecture suffix
            var dashIndex = versionString.IndexOf('-');
            var formattedVersion = dashIndex > 0 ? versionString[..dashIndex] : versionString;
            return Version.TryParse(formattedVersion, out version!);
        }

        /// <summary>
        /// Checks if a version is within the specified range
        /// </summary>
        /// <param name="version">Version to check</param>
        /// <param name="minVersion">Minimum allowed version</param>
        /// <param name="maxVersion">Maximum allowed version</param>
        /// <returns>True if version is in range</returns>
        private static bool IsVersionInRange(Version version, Version minVersion, Version maxVersion)
        {
            return version >= minVersion && version <= maxVersion;
        }
        #endregion
    }
}