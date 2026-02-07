/*
 * File: Constants.cs
 * Project: Extract.Hvcalls GUI v2.0.20250.102
 * Artifact: hvcall-gui-refactored in claude.ai
 * 
 * Description: Application constants and UI styling definitions
 * Author: Gerhart
 * License: GPL3
 * 
 * Change Log:
 * - v2.0.20250.100: Added centralized constants, improved parameter validation
 * - v2.0.20250.101: Fixed version format and standardized C# comments
 * - v2.0.20250.102: Updated for integrated C# processor version
 */

namespace HvcallGui.Views
{
    /// <summary>
    /// Contains application-wide constants for configuration, file extensions, and messages
    /// </summary>
    public static class AppConstants
    {
        #region Application Information
        /// <summary>
        /// Application title displayed in the main window
        /// </summary>
        public const string APP_TITLE = "Extract.Hvcalls GUI v2.0.20250.102 - Integrated C# Processor";
        
        /// <summary>
        /// Current application version
        /// </summary>
        public const string APP_VERSION = "2.0.20250.102";
        #endregion

        #region File Extensions
        /// <summary>
        /// System driver file extension
        /// </summary>
        public const string SYS_EXTENSION = ".sys";
        
        /// <summary>
        /// Executable file extension
        /// </summary>
        public const string EXE_EXTENSION = ".exe";
        
        /// <summary>
        /// IDA Pro 64-bit database extension
        /// </summary>
        public const string I64_EXTENSION = ".i64";
        
        /// <summary>
        /// IDA Pro database extension
        /// </summary>
        public const string IDB_EXTENSION = ".idb";
        #endregion

        #region Script and Configuration Files
        /// <summary>
        /// Python script name for extracting hypercalls (still needed for IDA automation)
        /// </summary>
        public const string EXTRACT_SCRIPT = "extract_hvcalls.py";
        
        /// <summary>
        /// Python script name for merging hypercall results (NO LONGER USED - replaced by C# processor)
        /// </summary>
        [Obsolete("Python merge script replaced by integrated C# processor")]
        public const string UNION_SCRIPT = "hvcalls_merge.py";
        
        /// <summary>
        /// Configuration file name
        /// </summary>
        public const string CONFIG_FILE = "config.json";
        
        /// <summary>
        /// IDA Pro 64-bit executable filename
        /// </summary>
        public const string IDA_EXECUTABLE = "ida64.exe";
        #endregion

        #region Registry Paths for Python Discovery
        /// <summary>
        /// Registry path for Python installations in HKEY_LOCAL_MACHINE
        /// NOTE: Python registry paths kept for future compatibility, but Python is no longer required for JSON processing
        /// </summary>
        public const string HKLM_PYTHON_PATH = @"HKLM\SOFTWARE\Python\PythonCore\";
        
        /// <summary>
        /// Registry path for Python installations in HKEY_CURRENT_USER
        /// </summary>
        public const string HKCU_PYTHON_PATH = @"HKCU\SOFTWARE\Python\PythonCore\";
        
        /// <summary>
        /// Registry path for Python installations in WOW64 node
        /// </summary>
        public const string WOW64_PYTHON_PATH = @"HKLM\SOFTWARE\Wow6432Node\Python\PythonCore\";
        #endregion

        #region System Path Constants
        /// <summary>
        /// Subdirectory name for system drivers
        /// </summary>
        public const string DRIVERS_SUBDIR = "drivers";
        
        /// <summary>
        /// Registry key name for Python installation path
        /// </summary>
        public const string INSTALL_PATH_KEY = "InstallPath";
        
        /// <summary>
        /// Registry value name for Python executable path
        /// </summary>
        public const string EXECUTABLE_PATH_KEY = "ExecutablePath";
        #endregion

        #region Hyper-V System Files
        /// <summary>
        /// Array of Hyper-V related system files to extract
        /// </summary>
        public static readonly string[] HV_FILES = {
            "winhvr.sys",           // Windows Hypervisor
            "winhv.sys",            // Windows Hypervisor Platform
            "securekernel.exe",     // Secure Kernel 
            "ntoskrnl.exe",         // NT Operating System Kernel
            "ntkrla57.exe",         // NT Kernel (ARM64)
            "securekernella57.exe"  // Secure Kernel (ARM64)
        };
        #endregion

        #region File Dialog Settings
        /// <summary>
        /// File filter for IDA Pro executable selection dialog
        /// </summary>
        public const string IDA_FILTER = "Ida PRO 64 (*.exe)|*.exe";
        
        /// <summary>
        /// Default initial directory for file dialogs
        /// </summary>
        public const string INITIAL_DIRECTORY = "c:\\";
        #endregion

        #region Error Messages
        /// <summary>
        /// Error message when specified directory doesn't exist
        /// </summary>
        public const string ERROR_DIRECTORY_NOT_FOUND = "Directory {0} is not presented. Try to create it";
        
        /// <summary>
        /// Error message when destination file already exists
        /// </summary>
        public const string ERROR_FILE_EXISTS = "file {0} already presented. Please, clear directory before copy file";
        
        /// <summary>
        /// Error message when source file is not found
        /// </summary>
        public const string ERROR_FILE_NOT_FOUND = "File {0} is not found";
        
        /// <summary>
        /// Error message for missing binary directory specification
        /// </summary>
        public const string ERROR_SPECIFY_BINARY_DIR = "Specify the directory with Hyper-V binaries";
        
        /// <summary>
        /// Error message for missing IDA path specification
        /// </summary>
        public const string ERROR_SPECIFY_IDA_PATH = "Specify the IDA PRO executable (file ida64.exe)";
        
        /// <summary>
        /// Error message for missing script directory specification
        /// </summary>
        public const string ERROR_SPECIFY_SCRIPT_DIR = "Specify the directory with hvcall_path.py";
        
        /// <summary>
        /// Error message when configuration file is not found
        /// </summary>
        public const string ERROR_CONFIG_NOT_FOUND = "Configuration file config.json is not found";
        #endregion

        #region Success Messages
        /// <summary>
        /// Success message when file is copied successfully
        /// </summary>
        public const string SUCCESS_FILE_COPIED = "file {0} was copied to {1}";
        
        /// <summary>
        /// Message indicating processing completion
        /// </summary>
        public const string SUCCESS_PROCESSING_COMPLETE = "IDA processing complete. Starting JSON file merging...";
        
        /// <summary>
        /// Message indicating successful file merge
        /// </summary>
        public const string SUCCESS_FILES_MERGED = "JSON files merged successfully using integrated C# processor.";
        #endregion

        #region Processing Status Messages
        /// <summary>
        /// Status message for processing IDA database files
        /// </summary>
        public const string PROCESSING_I64_FILE = "processing .i64[.idb] file: {0}...  {1}";
        
        /// <summary>
        /// Status message for processing binary files
        /// </summary>
        public const string PROCESSING_FILE = "processing file {0}...  {1}";
        #endregion

        #region Python Version Constraints (kept for compatibility, but Python no longer required for JSON processing)
        /// <summary>
        /// Minimum acceptable Python version (fallback)
        /// </summary>
        public const string MIN_PYTHON_VERSION = "0.0.1";
        
        /// <summary>
        /// Maximum acceptable Python version (fallback)
        /// </summary>
        public const string MAX_PYTHON_VERSION = "999.999.999";
        
        /// <summary>
        /// Default minimum Python version for this application
        /// </summary>
        public const string DEFAULT_PYTHON_MIN = "3.1";
        
        /// <summary>
        /// Default maximum Python version for this application
        /// </summary>
        public const string DEFAULT_PYTHON_MAX = "3.14";
        #endregion
    }

    /// <summary>
    /// UI-specific constants for styling, layout, and DPI scaling
    /// </summary>
    public static class UIConstants
    {
        #region DPI and Scaling Configuration
        /// <summary>
        /// Base DPI for scaling calculations (96 DPI = 100% scaling)
        /// </summary>
        public const int BASE_DPI = 96;
        
        /// <summary>
        /// Default scale factor for UI elements
        /// </summary>
        public const float SCALE_FACTOR = 1.0f;
        #endregion

        #region Layout Spacing Constants
        /// <summary>
        /// Standard margin around form edges
        /// </summary>
        public const int MARGIN = 12;
        
        /// <summary>
        /// Spacing between related controls
        /// </summary>
        public const int CONTROL_SPACING = 8;
        
        /// <summary>
        /// Spacing between different sections
        /// </summary>
        public const int SECTION_SPACING = 16;
        
        /// <summary>
        /// Spacing between buttons in button groups
        /// </summary>
        public const int BUTTON_SPACING = 6;
        #endregion

        #region Control Dimensions
        /// <summary>
        /// Standard height for label controls
        /// </summary>
        public const int LABEL_HEIGHT = 23;
        
        /// <summary>
        /// Standard height for text box controls
        /// </summary>
        public const int TEXTBOX_HEIGHT = 29;
        
        /// <summary>
        /// Standard height for button controls
        /// </summary>
        public const int BUTTON_HEIGHT = 32;
        
        /// <summary>
        /// Standard height for checkbox controls
        /// </summary>
        public const int CHECKBOX_HEIGHT = 24;
        #endregion

        #region Control Widths
        /// <summary>
        /// Standard width for labels
        /// </summary>
        public const int LABEL_WIDTH = 220;
        
        /// <summary>
        /// Standard width for text boxes
        /// </summary>
        public const int TEXTBOX_WIDTH = 400;
        
        /// <summary>
        /// Standard width for buttons
        /// </summary>
        public const int BUTTON_WIDTH = 140;
        
        /// <summary>
        /// Minimum form width to prevent UI overlap
        /// </summary>
        public const int FORM_MIN_WIDTH = 900;
        
        /// <summary>
        /// Minimum form height to prevent control clipping
        /// </summary>
        public const int FORM_MIN_HEIGHT = 750;
        #endregion

        #region Modern Metallic Color Scheme
        /// <summary>
        /// Light metallic background color for the main form
        /// </summary>
        public static readonly Color FORM_BACKGROUND = Color.FromArgb(240, 240, 240);
        
        /// <summary>
        /// Dark text color for labels and static text
        /// </summary>
        public static readonly Color LABEL_FOREGROUND = Color.FromArgb(32, 32, 32);
        
        /// <summary>
        /// Dark background for text input controls
        /// </summary>
        public static readonly Color TEXTBOX_BACKGROUND = Color.FromArgb(45, 45, 48);
        
        /// <summary>
        /// Light text color for dark text boxes
        /// </summary>
        public static readonly Color TEXTBOX_FOREGROUND = Color.FromArgb(220, 220, 220);
        
        /// <summary>
        /// Gray metallic background for buttons
        /// </summary>
        public static readonly Color BUTTON_BACKGROUND = Color.FromArgb(150, 150, 150);
        
        /// <summary>
        /// Dark text color for button text
        /// </summary>
        public static readonly Color BUTTON_FOREGROUND = Color.FromArgb(32, 32, 32);
        
        /// <summary>
        /// Lighter gray for button hover state
        /// </summary>
        public static readonly Color BUTTON_HOVER = Color.FromArgb(170, 170, 170);
        
        /// <summary>
        /// Very dark background for rich text output
        /// </summary>
        public static readonly Color RICHTEXT_BACKGROUND = Color.FromArgb(30, 30, 30);
        
        /// <summary>
        /// Light text color for rich text output
        /// </summary>
        public static readonly Color RICHTEXT_FOREGROUND = Color.FromArgb(220, 220, 220);
        #endregion
    }
}
