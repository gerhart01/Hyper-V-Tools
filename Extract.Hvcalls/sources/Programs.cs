/*
 * File: Program.cs
 * Project: Extract.Hvcalls GUI v2.0.20250.101
 * Namespace: HvcallGui
 * 
 * Description: Application entry point with high DPI configuration and proper resource disposal
 * Author: Gerhart
 * License: GPL3
 * 
 * Change Log:
 * - v2.0.20250.100: Updated to use MVC Views namespace, improved DPI configuration
 * - v2.0.20250.101: Fixed CA2000 warning with proper form disposal
 */

using HvcallGui.Views;

namespace HvcallGui.Views
{
    /// <summary>
    /// Main program class containing the application entry point
    /// </summary>
    internal static class Program
    {
        /// <summary>
        /// The main entry point for the application
        /// Configures high DPI support and starts the main form
        /// </summary>
        [STAThread]
        static void Main()
        {
            // Initialize the application configuration
            // (reads HighDpiMode, DefaultFont, VisualStyles from project settings)
            ApplicationConfiguration.Initialize();

            // Start the main application form with proper disposal
            using var mainForm = new frmForm01();
            Application.Run(mainForm);
        }
    }
}