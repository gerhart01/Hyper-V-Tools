/*
 * File: Views/frmForm01.cs
 * Project: Extract.Hvcalls GUI v2.0.20250.102
 * Namespace: HvcallGui.Views
 * 
 * Description: Main application form with integrated C# hypervisor call processor
 * Author: Gerhart
 * License: GPL3
 * 
 * Change Log:
 * - v2.0.20250.102: Integrated C# processor, removed Python dependency
 */

using System;
using System.ComponentModel;
using System.Drawing;
using System.IO;
using System.Threading;
using System.Windows.Forms;

namespace HvcallGui.Views
{
    /// <summary>
    /// Main application form with integrated hypervisor call processing
    /// </summary>
    public partial class frmForm01 : Form
    {
        #region Private Fields
        
        private IntegratedHyperVCallProcessor? _processor;
        private CancellationTokenSource? _cancellationTokenSource;
        
        #endregion

        #region Constructor
        
        public frmForm01()
        {
            InitializeComponent();

            if (LicenseManager.UsageMode != LicenseUsageMode.Designtime)
                InitializeForm();
        }
        
        #endregion

        #region Initialization
        
        private void InitializeForm()
        {
            ApplyStyling();
            LogMessage("Application started. Ready to extract Hyper-V hypercalls.");
            LoadSettings();
        }

        private void ApplyStyling()
        {
            this.BackColor = UIConstants.FORM_BACKGROUND;

            ApplyButtonStyle(btnBinaries);
            ApplyButtonStyle(btnIda);
            ApplyButtonStyle(btnScripts);
            ApplyButtonStyle(btnResults);
            ApplyButtonStyle(btnGetBinaries);
            ApplyStartButtonStyle(btnStart);

            //ApplyTextBoxStyle(txtBinaries);
            //ApplyTextBoxStyle(txtIda);
            //ApplyTextBoxStyle(txtScripts);
            //ApplyTextBoxStyle(txtResults);

            ApplyCheckBoxStyle(chkProcessIDB);
            ApplyCheckBoxStyle(chkBuildDir);

            //txtOutput.BackColor = UIConstants.RICHTEXT_BACKGROUND;
            //txtOutput.ForeColor = UIConstants.RICHTEXT_FOREGROUND;
        }

        private void LoadSettings()
        {
            try
            {
                var configPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, AppConstants.CONFIG_FILE);
                
                if (!File.Exists(configPath))
                {
                    LogMessage("Configuration file not found. Using defaults.");
                    return;
                }

                var config = ConfigurationManager.ReadConfiguration(configPath);
                if (config == null)
                    return;

                txtBinaries.Text = config.WindowsBinaryPath;
                txtIda.Text = config.IdaPath;

                txtScripts.Text = Path.GetDirectoryName(Application.ExecutablePath) + Path.DirectorySeparatorChar + config.ScriptPath; // it is relative path to current module

                txtResults.Text = config.ResultPath;

                LogMessage("Configuration loaded successfully.");
            }
            catch (Exception ex)
            {
                LogMessage($"Could not load settings: {ex.Message}");
            }
        }
        
        #endregion

        #region Event Handlers
        
        private void btnBinaries_Click(object sender, EventArgs e)
        {
            SelectFolder("Select directory with Hyper-V binaries", txtBinaries);
        }

        private void btnIda_Click(object sender, EventArgs e)
        {
            SelectIdaFile();
        }

        private void btnScripts_Click(object sender, EventArgs e)
        {
            SelectFolder("Select directory with Python scripts", txtScripts);
        }

        private void btnResults_Click(object sender, EventArgs e)
        {
            SelectFolder("Select directory for parsing results", txtResults);
        }

        private async void btnStart_Click(object sender, EventArgs e)
        {
            await StartProcessingAsync();
        }

        private void btnGetBinaries_Click(object sender, EventArgs e)
        {
            CopyWindowsBinaries();
        }

        private void txtIda_TextChanged(object sender, EventArgs e)
        {
            ValidateIdaPath();
        }
        
        #endregion

        #region Helper Methods
        
        private void SelectFolder(string description, TextBox targetTextBox)
        {
            using var dialog = new FolderBrowserDialog
            {
                Description = description,
                SelectedPath = targetTextBox.Text,
                ShowNewFolderButton = true
            };

            if (dialog.ShowDialog() == DialogResult.OK)
            {
                targetTextBox.Text = dialog.SelectedPath;
                LogMessage($"Selected: {dialog.SelectedPath}");
            }
        }

        private void SelectIdaFile()
        {
            using var dialog = new OpenFileDialog
            {
                Filter = AppConstants.IDA_FILTER,
                Title = "Select IDA Pro 64-bit executable",
                FileName = txtIda.Text,
                CheckFileExists = true
            };

            if (dialog.ShowDialog() == DialogResult.OK)
            {
                txtIda.Text = dialog.FileName;
                LogMessage($"IDA Pro selected: {dialog.FileName}");
            }
        }

        private void ValidateIdaPath()
        {
            var path = txtIda.Text;
            if (string.IsNullOrEmpty(path) || path.EndsWith(AppConstants.IDA_EXECUTABLE))
                return;

            var dir = Path.GetDirectoryName(path);
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir))
                return;

            var idaPath = Path.Combine(dir, AppConstants.IDA_EXECUTABLE);
            if (File.Exists(idaPath))
                txtIda.Text = idaPath;
        }

        private void LogMessage(string message)
        {
            if (InvokeRequired)
            {
                Invoke(new Action<string>(LogMessage), message);
                return;
            }

            var time = DateTime.Now.ToString("HH:mm:ss");
            txtOutput.AppendText($"[{time}] {message}\r\n");
            txtOutput.ScrollToCaret();
        }

        private bool ValidateInputs()
        {
            if (string.IsNullOrWhiteSpace(txtBinaries.Text))
            {
                LogMessage("ERROR: Please select binaries directory");
                MessageBox.Show(AppConstants.ERROR_SPECIFY_BINARY_DIR, "Validation Error", 
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }

            if (string.IsNullOrWhiteSpace(txtIda.Text))
            {
                LogMessage("ERROR: Please select IDA Pro executable");
                MessageBox.Show(AppConstants.ERROR_SPECIFY_IDA_PATH, "Validation Error", 
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }

            if (string.IsNullOrWhiteSpace(txtScripts.Text))
            {
                LogMessage("ERROR: Please select scripts directory");
                MessageBox.Show(AppConstants.ERROR_SPECIFY_SCRIPT_DIR, "Validation Error", 
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }

            if (!Directory.Exists(txtBinaries.Text))
            {
                LogMessage("ERROR: Binaries directory does not exist");
                return false;
            }

            if (!File.Exists(txtIda.Text))
            {
                LogMessage("ERROR: IDA Pro executable not found");
                return false;
            }

            if (!Directory.Exists(txtScripts.Text))
            {
                LogMessage("ERROR: Scripts directory does not exist");
                return false;
            }

            var scriptPath = Path.Combine(txtScripts.Text, AppConstants.EXTRACT_SCRIPT);
            if (!File.Exists(scriptPath))
            {
                LogMessage($"ERROR: Python script not found: {AppConstants.EXTRACT_SCRIPT}");
                MessageBox.Show($"Required script not found: {AppConstants.EXTRACT_SCRIPT}\nPlease ensure it exists in the scripts directory.", 
                    "Script Missing", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }

            return true;
        }
        
        #endregion

        #region Processing Methods
        
        private async Task StartProcessingAsync()
        {
            if (!ValidateInputs())
                return;

            btnStart.Enabled = false;
            btnGetBinaries.Enabled = false;
            var originalText = btnStart.Text;
            btnStart.Text = "Processing...";

            _cancellationTokenSource = new CancellationTokenSource();

            try
            {
                LogMessage("=== Starting Hyper-V Hypercall extraction ===");
                LogMessage($"Binaries: {txtBinaries.Text}");
                LogMessage($"IDA: {txtIda.Text}");
                LogMessage($"Scripts: {txtScripts.Text}");
                LogMessage($"Results: {txtResults.Text}");
                LogMessage($"Process IDB: {chkProcessIDB.Checked}");
                LogMessage($"Build directory: {chkBuildDir.Checked}");
                LogMessage("");

                _processor = new IntegratedHyperVCallProcessor(LogMessage);

                var outputDir = string.IsNullOrWhiteSpace(txtResults.Text) 
                    ? Path.Combine(txtScripts.Text, HypervisorConstants.RESULTS_DIRECTORY)
                    : txtResults.Text;

                await _processor.ProcessHyperVCallsAsync(
                    txtBinaries.Text,
                    txtIda.Text,
                    txtScripts.Text,
                    outputDir,
                    chkProcessIDB.Checked,
                    _cancellationTokenSource.Token
                );

                LogMessage("");
                LogMessage("=== Extraction complete ===");
                LogMessage($"Results saved to: {outputDir}");

                MessageBox.Show(
                    "Hyper-V hypercalls extraction completed successfully!\n\n" +
                    $"Results are saved in:\n{outputDir}", 
                    "Success", 
                    MessageBoxButtons.OK, 
                    MessageBoxIcon.Information);
            }
            catch (OperationCanceledException)
            {
                LogMessage("Processing was cancelled by user");
                MessageBox.Show("Processing was cancelled.", "Cancelled", 
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                LogMessage($"ERROR: {ex.Message}");
                LogMessage($"Stack trace: {ex.StackTrace}");
                
                MessageBox.Show(
                    $"An error occurred during processing:\n\n{ex.Message}", 
                    "Error", 
                    MessageBoxButtons.OK, 
                    MessageBoxIcon.Error);
            }
            finally
            {
                btnStart.Text = originalText;
                btnStart.Enabled = true;
                btnGetBinaries.Enabled = true;
                
                _cancellationTokenSource?.Dispose();
                _cancellationTokenSource = null;
            }
        }

        private void CopyWindowsBinaries()
        {
            try
            {
                if (string.IsNullOrWhiteSpace(txtBinaries.Text))
                {
                    MessageBox.Show(AppConstants.ERROR_SPECIFY_BINARY_DIR, "Error", 
                        MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                LogMessage("=== Copying Windows system binaries ===");

                _processor = new IntegratedHyperVCallProcessor(LogMessage);
                _processor.CopySystemBinaries(txtBinaries.Text);

                LogMessage("=== Binary copy completed ===");
            }
            catch (UnauthorizedAccessException)
            {
                LogMessage("ERROR: Access denied. Run as administrator to copy system files.");
                MessageBox.Show(
                    "Access denied when copying system files.\n\n" +
                    "Please run this application as Administrator to copy Hyper-V binaries.", 
                    "Access Denied", 
                    MessageBoxButtons.OK, 
                    MessageBoxIcon.Error);
            }
            catch (Exception ex)
            {
                LogMessage($"ERROR copying binaries: {ex.Message}");
                MessageBox.Show($"Error copying binaries:\n\n{ex.Message}", "Error", 
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
        
        #endregion

        #region Styling Methods
        
        private void ApplyButtonStyle(Button button)
        {
            button.FlatStyle = FlatStyle.Flat;
            button.FlatAppearance.BorderSize = 1;
            button.FlatAppearance.BorderColor = Color.FromArgb(100, 100, 100);
            button.BackColor = UIConstants.BUTTON_BACKGROUND;
            button.ForeColor = UIConstants.BUTTON_FOREGROUND;
            button.Cursor = Cursors.Hand;

            button.MouseEnter += (s, e) => button.BackColor = UIConstants.BUTTON_HOVER;
            button.MouseLeave += (s, e) => button.BackColor = UIConstants.BUTTON_BACKGROUND;
        }

        private void ApplyStartButtonStyle(Button button)
        {
            button.FlatStyle = FlatStyle.Flat;
            button.FlatAppearance.BorderSize = 1;
            button.FlatAppearance.BorderColor = Color.FromArgb(40, 80, 120);
            button.BackColor = Color.FromArgb(70, 130, 180);
            button.ForeColor = Color.White;
            button.Font = new Font(button.Font, FontStyle.Bold);
            button.Cursor = Cursors.Hand;

            button.MouseEnter += (s, e) => button.BackColor = Color.FromArgb(100, 150, 200);
            button.MouseLeave += (s, e) => button.BackColor = Color.FromArgb(70, 130, 180);
        }

        private void ApplyTextBoxStyle(TextBox textBox)
        {
            textBox.BackColor = UIConstants.TEXTBOX_BACKGROUND;
            textBox.ForeColor = UIConstants.TEXTBOX_FOREGROUND;
            textBox.BorderStyle = BorderStyle.FixedSingle;
        }

        private void ApplyCheckBoxStyle(CheckBox checkBox)
        {
            checkBox.ForeColor = UIConstants.LABEL_FOREGROUND;
            checkBox.BackColor = Color.Transparent;
        }
        
        #endregion

        #region Form Cleanup

        /* Dispose is in frmForm01.Designer.cs (required by WinForms Designer) */

        #endregion
    }
}
