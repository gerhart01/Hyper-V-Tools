/*
 * File: Views/frmForm01.Designer.cs
 * Project: Extract.Hvcalls GUI v2.0.20250.102
 * 
 * Description: Designer file with fixed layout - no overlapping controls
 * Author: Gerhart (Designer)
 * License: GPL3
 */

namespace HvcallGui.Views
{
    partial class frmForm01
    {
        private System.ComponentModel.IContainer components = null;

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _cancellationTokenSource?.Cancel();
                _cancellationTokenSource?.Dispose();
                components?.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        private void InitializeComponent()
        {
            lblBinaries = new Label();
            txtBinaries = new TextBox();
            btnBinaries = new Button();
            lblIda = new Label();
            txtIda = new TextBox();
            btnIda = new Button();
            lblScripts = new Label();
            txtScripts = new TextBox();
            btnScripts = new Button();
            lblResults = new Label();
            txtResults = new TextBox();
            btnResults = new Button();
            chkProcessIDB = new CheckBox();
            chkBuildDir = new CheckBox();
            btnStart = new Button();
            btnGetBinaries = new Button();
            txtOutput = new RichTextBox();
            SuspendLayout();
            // 
            // lblBinaries
            // 
            lblBinaries.AutoSize = true;
            lblBinaries.Location = new Point(12, 15);
            lblBinaries.Name = "lblBinaries";
            lblBinaries.Size = new Size(170, 20);
            lblBinaries.TabIndex = 0;
            lblBinaries.Text = "Path to Hyper-V binaries";
            // 
            // txtBinaries
            // 
            txtBinaries.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            txtBinaries.BackColor = SystemColors.Window;
            txtBinaries.Location = new Point(252, 12);
            txtBinaries.Name = "txtBinaries";
            txtBinaries.Size = new Size(518, 27);
            txtBinaries.TabIndex = 1;
            // 
            // btnBinaries
            // 
            btnBinaries.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            btnBinaries.Location = new Point(780, 11);
            btnBinaries.Name = "btnBinaries";
            btnBinaries.Size = new Size(90, 30);
            btnBinaries.TabIndex = 2;
            btnBinaries.Text = "Browse...";
            btnBinaries.UseVisualStyleBackColor = true;
            btnBinaries.Click += btnBinaries_Click;
            // 
            // lblIda
            // 
            lblIda.AutoSize = true;
            lblIda.Location = new Point(12, 55);
            lblIda.Name = "lblIda";
            lblIda.Size = new Size(217, 20);
            lblIda.TabIndex = 3;
            lblIda.Text = "Path to IDA PRO executable file";
            // 
            // txtIda
            // 
            txtIda.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            txtIda.Location = new Point(252, 52);
            txtIda.Name = "txtIda";
            txtIda.Size = new Size(518, 27);
            txtIda.TabIndex = 4;
            txtIda.TextChanged += txtIda_TextChanged;
            // 
            // btnIda
            // 
            btnIda.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            btnIda.Location = new Point(780, 51);
            btnIda.Name = "btnIda";
            btnIda.Size = new Size(90, 30);
            btnIda.TabIndex = 5;
            btnIda.Text = "Browse...";
            btnIda.UseVisualStyleBackColor = true;
            btnIda.Click += btnIda_Click;
            // 
            // lblScripts
            // 
            lblScripts.AutoSize = true;
            lblScripts.Location = new Point(12, 95);
            lblScripts.Name = "lblScripts";
            lblScripts.Size = new Size(101, 20);
            lblScripts.TabIndex = 6;
            lblScripts.Text = "Path to scripts";
            // 
            // txtScripts
            // 
            txtScripts.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            txtScripts.Location = new Point(252, 92);
            txtScripts.Name = "txtScripts";
            txtScripts.Size = new Size(518, 27);
            txtScripts.TabIndex = 7;
            // 
            // btnScripts
            // 
            btnScripts.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            btnScripts.Location = new Point(780, 91);
            btnScripts.Name = "btnScripts";
            btnScripts.Size = new Size(90, 30);
            btnScripts.TabIndex = 8;
            btnScripts.Text = "Browse...";
            btnScripts.UseVisualStyleBackColor = true;
            btnScripts.Click += btnScripts_Click;
            // 
            // lblResults
            // 
            lblResults.AutoSize = true;
            lblResults.Location = new Point(12, 135);
            lblResults.Name = "lblResults";
            lblResults.Size = new Size(154, 20);
            lblResults.TabIndex = 9;
            lblResults.Text = "Path to parsing results";
            // 
            // txtResults
            // 
            txtResults.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            txtResults.Location = new Point(252, 132);
            txtResults.Name = "txtResults";
            txtResults.Size = new Size(518, 27);
            txtResults.TabIndex = 10;
            // 
            // btnResults
            // 
            btnResults.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            btnResults.Location = new Point(780, 131);
            btnResults.Name = "btnResults";
            btnResults.Size = new Size(90, 30);
            btnResults.TabIndex = 11;
            btnResults.Text = "Browse...";
            btnResults.UseVisualStyleBackColor = true;
            btnResults.Click += btnResults_Click;
            // 
            // chkProcessIDB
            // 
            chkProcessIDB.AutoSize = true;
            chkProcessIDB.Location = new Point(12, 180);
            chkProcessIDB.Name = "chkProcessIDB";
            chkProcessIDB.Size = new Size(284, 24);
            chkProcessIDB.TabIndex = 12;
            chkProcessIDB.Text = "Process .i64 files in autonomous mode";
            chkProcessIDB.UseVisualStyleBackColor = true;
            // 
            // chkBuildDir
            // 
            chkBuildDir.AutoSize = true;
            chkBuildDir.Location = new Point(12, 210);
            chkBuildDir.Name = "chkBuildDir";
            chkBuildDir.Size = new Size(344, 24);
            chkBuildDir.TabIndex = 13;
            chkBuildDir.Text = "Make separate build directory for resulting files";
            chkBuildDir.UseVisualStyleBackColor = true;
            // 
            // btnStart
            // 
            btnStart.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            btnStart.Font = new Font("Segoe UI", 10F, FontStyle.Bold);
            btnStart.Location = new Point(430, 175);
            btnStart.Name = "btnStart";
            btnStart.Size = new Size(150, 50);
            btnStart.TabIndex = 14;
            btnStart.Text = "Start";
            btnStart.UseVisualStyleBackColor = true;
            btnStart.Click += btnStart_Click;
            // 
            // btnGetBinaries
            // 
            btnGetBinaries.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            btnGetBinaries.Location = new Point(770, 175);
            btnGetBinaries.Name = "btnGetBinaries";
            btnGetBinaries.Size = new Size(100, 50);
            btnGetBinaries.TabIndex = 15;
            btnGetBinaries.Text = "Get binaries";
            btnGetBinaries.UseVisualStyleBackColor = true;
            btnGetBinaries.Click += btnGetBinaries_Click;
            // 
            // txtOutput
            // 
            txtOutput.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            txtOutput.BackColor = Color.LightSlateGray;
            txtOutput.Font = new Font("Consolas", 9F);
            txtOutput.ForeColor = Color.White;
            txtOutput.Location = new Point(12, 245);
            txtOutput.Name = "txtOutput";
            txtOutput.ReadOnly = true;
            txtOutput.ScrollBars = RichTextBoxScrollBars.Vertical;
            txtOutput.Size = new Size(858, 470);
            txtOutput.TabIndex = 16;
            txtOutput.Text = "";
            // 
            // frmForm01
            // 
            AutoScaleDimensions = new SizeF(8F, 20F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(882, 727);
            Controls.Add(txtOutput);
            Controls.Add(btnGetBinaries);
            Controls.Add(btnStart);
            Controls.Add(chkBuildDir);
            Controls.Add(chkProcessIDB);
            Controls.Add(btnResults);
            Controls.Add(txtResults);
            Controls.Add(lblResults);
            Controls.Add(btnScripts);
            Controls.Add(txtScripts);
            Controls.Add(lblScripts);
            Controls.Add(btnIda);
            Controls.Add(txtIda);
            Controls.Add(lblIda);
            Controls.Add(btnBinaries);
            Controls.Add(txtBinaries);
            Controls.Add(lblBinaries);
            MaximizeBox = false;
            MinimumSize = new Size(900, 750);
            Name = "frmForm01";
            StartPosition = FormStartPosition.CenterScreen;
            Text = "Extract.Hvcalls GUI v2.0.20260204";
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion

        private Label lblBinaries;
        private TextBox txtBinaries;
        private Button btnBinaries;
        private Label lblIda;
        private TextBox txtIda;
        private Button btnIda;
        private Label lblScripts;
        private TextBox txtScripts;
        private Button btnScripts;
        private Label lblResults;
        private TextBox txtResults;
        private Button btnResults;
        private CheckBox chkProcessIDB;
        private CheckBox chkBuildDir;
        private Button btnStart;
        private Button btnGetBinaries;
        private RichTextBox txtOutput;
    }
}
