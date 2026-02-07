/*
 * File: Controllers/ApplicationController.cs
 * Project: Extract.Hvcalls GUI v2.0.20250.101
 * Namespace: HvcallGui.Controllers
 * 
 * Description: MVC Controller layer managing business logic and coordination between Model and View
 * Author: Gerhart
 * License: GPL3
 * 
 * Change Log:
 * - v2.0.20250.100: Created MVC Controller layer, centralized business logic and event handling
 * - v2.0.20250.101: Standardized C# comment formatting
 */

namespace HvcallGui.Views
{
    /// <summary>
    /// Main application controller implementing MVC pattern
    /// Coordinates between the UI (View) and data (Model) layers
    /// Handles all business logic and external service interactions
    /// </summary>
    public class ApplicationController
    {
        #region Private Fields
        private readonly ApplicationModel _model;
        private readonly HyperVCallExtractor _extractor;
        private readonly Action<string> _logAction;
        #endregion

        #region Constructor
        /// <summary>
        /// Initializes a new instance of the ApplicationController
        /// </summary>
        /// <param name="model">Application data model</param>
        /// <param name="logAction">Callback for logging messages to the UI</param>
        /// <exception cref="ArgumentNullException">Thrown when model or logAction is null</exception>
        public ApplicationController(ApplicationModel model, Action<string> logAction)
        {
            _model = model ?? throw new ArgumentNullException(nameof(model));
            _logAction = logAction ?? throw new ArgumentNullException(nameof(logAction));
            _extractor = new HyperVCallExtractor(_logAction);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Starts the asynchronous hypercall extraction process
        /// Validates the model before beginning extraction
        /// </summary>
        /// <returns>A task representing the asynchronous operation</returns>
        public async Task StartExtractionAsync()
        {
            try
            {
                if (!_model.IsValid())
                {
                    _logAction("Please fill all required fields with valid paths.");
                    return;
                }

                var parameters = new ExtractionParameters(
                    _model.BinaryDirectory,
                    _model.IdaPath,
                    _model.ScriptDirectory,
                    AppConstants.EXTRACT_SCRIPT,
                    AppConstants.UNION_SCRIPT,
                    _model.ProcessIdbFiles
                );

                await _extractor.ExtractHyperVCalls(parameters);
            }
            catch (Exception ex)
            {
                _logAction($"Error: {ex.Message}");
            }
        }

        /// <summary>
        /// Copies Hyper-V system binaries from the current Windows installation
        /// to the specified binary directory
        /// </summary>
        public void CopySystemBinaries()
        {
            try
            {
                if (string.IsNullOrWhiteSpace(_model.BinaryDirectory))
                {
                    _logAction("Please specify binary directory first.");
                    return;
                }

                _extractor.CopySystemBinaries(_model.BinaryDirectory);
            }
            catch (Exception ex)
            {
                _logAction($"Error copying binaries: {ex.Message}");
            }
        }

        /// <summary>
        /// Loads configuration from the default config.json file
        /// and updates the model properties
        /// </summary>
        public void LoadConfiguration()
        {
            var configPath = ConfigurationManager.GetConfigurationPath();
            
            if (!File.Exists(configPath))
            {
                _logAction(AppConstants.ERROR_CONFIG_NOT_FOUND);
                return;
            }

            var config = ConfigurationManager.ReadConfiguration(configPath);
            if (config == null) return;

            // Update model with configuration values
            _model.BinaryDirectory = config.WindowsBinaryPath;
            _model.IdaPath = config.IdaPath;
            _model.ScriptDirectory = config.ScriptPath;
        }

        /// <summary>
        /// Validates and corrects the IDA path by appending ida64.exe if needed
        /// </summary>
        public void ValidateIdaPath()
        {
            if (!string.IsNullOrEmpty(_model.IdaPath) && 
                !_model.IdaPath.Contains(AppConstants.IDA_EXECUTABLE))
            {
                _model.IdaPath = Path.Combine(_model.IdaPath, AppConstants.IDA_EXECUTABLE);
            }
        }
        #endregion
    }
}