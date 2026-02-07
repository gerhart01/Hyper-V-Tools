/*
 * File: Models/ApplicationModel.cs
 * Project: Extract.Hvcalls GUI v2.0.20250.101
 * Namespace: HvcallGui.Models
 * 
 * Description: MVC Model layer containing application state and data binding
 * Author: Gerhart
 * License: GPL3
 * 
 * Change Log:
 * - v2.0.20250.100: Created MVC Model layer, added property validation and change notifications
 * - v2.0.20250.101: Standardized C# comment formatting
 */

using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace HvcallGui.Views
{
    /// <summary>
    /// Application data model implementing INotifyPropertyChanged for automatic UI updates
    /// Contains all user settings and configuration paths for the hypercall extraction process
    /// </summary>
    public class ApplicationModel : INotifyPropertyChanged
    {
        #region Private Fields
        private string _binaryDirectory = string.Empty;
        private string _idaPath = string.Empty;
        private string _scriptDirectory = string.Empty;
        private string _parserResultsDirectory = string.Empty;
        private bool _processIdbFiles = false;
        private bool _makeBuildDir = false;
        #endregion

        #region Public Properties
        /// <summary>
        /// Gets or sets the directory containing Hyper-V binary files to analyze
        /// </summary>
        public string BinaryDirectory
        {
            get => _binaryDirectory;
            set => SetProperty(ref _binaryDirectory, value);
        }

        /// <summary>
        /// Gets or sets the full path to IDA Pro executable (ida64.exe)
        /// </summary>
        public string IdaPath
        {
            get => _idaPath;
            set => SetProperty(ref _idaPath, value);
        }

        /// <summary>
        /// Gets or sets the directory containing Python extraction scripts
        /// </summary>
        public string ScriptDirectory
        {
            get => _scriptDirectory;
            set => SetProperty(ref _scriptDirectory, value);
        }

        /// <summary>
        /// Gets or sets the directory for storing parsing results
        /// </summary>
        public string ParserResultsDirectory
        {
            get => _parserResultsDirectory;
            set => SetProperty(ref _parserResultsDirectory, value);
        }

        /// <summary>
        /// Gets or sets whether to process existing .i64 files in autonomous mode
        /// </summary>
        public bool ProcessIdbFiles
        {
            get => _processIdbFiles;
            set => SetProperty(ref _processIdbFiles, value);
        }

        /// <summary>
        /// Gets or sets whether to create a separate build directory for output files
        /// </summary>
        public bool MakeBuildDir
        {
            get => _makeBuildDir;
            set => SetProperty(ref _makeBuildDir, value);
        }
        #endregion

        #region INotifyPropertyChanged Implementation
        /// <summary>
        /// Occurs when a property value changes
        /// </summary>
        public event PropertyChangedEventHandler? PropertyChanged;

        /// <summary>
        /// Raises the PropertyChanged event for the specified property
        /// </summary>
        /// <param name="propertyName">Name of the property that changed</param>
        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        /// <summary>
        /// Sets a property value and raises PropertyChanged if the value actually changed
        /// </summary>
        /// <typeparam name="T">Type of the property</typeparam>
        /// <param name="field">Reference to the backing field</param>
        /// <param name="value">New value to set</param>
        /// <param name="propertyName">Name of the property (automatically inferred)</param>
        /// <returns>True if the value was changed, false if it was the same</returns>
        protected bool SetProperty<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
        {
            if (EqualityComparer<T>.Default.Equals(field, value))
                return false;

            field = value;
            OnPropertyChanged(propertyName);
            return true;
        }
        #endregion

        #region Validation Methods
        /// <summary>
        /// Validates that all required properties are set with valid values
        /// </summary>
        /// <returns>True if the model is valid for processing, false otherwise</returns>
        public bool IsValid()
        {
            return !string.IsNullOrWhiteSpace(BinaryDirectory) &&
                   !string.IsNullOrWhiteSpace(IdaPath) &&
                   !string.IsNullOrWhiteSpace(ScriptDirectory) &&
                   Directory.Exists(BinaryDirectory) &&
                   File.Exists(IdaPath) &&
                   Directory.Exists(ScriptDirectory);
        }
        #endregion
    }
}