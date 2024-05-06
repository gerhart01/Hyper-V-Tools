namespace HvcallGui
{
    partial class frmForm01
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            txtPathToHvcallBins = new TextBox();
            richTextBox1 = new RichTextBox();
            btnHvcallBins = new Button();
            btnPathToIda = new Button();
            txtPathToIda = new TextBox();
            folderBrowserDialog1 = new FolderBrowserDialog();
            btnStart = new Button();
            chkBoxProcessIDB = new CheckBox();
            button2 = new Button();
            txtScriptPath = new TextBox();
            lblPathToBinaries = new Label();
            label1 = new Label();
            label2 = new Label();
            btnPathToScripts = new Button();
            SuspendLayout();
            // 
            // txtPathToHvcallBins
            // 
            txtPathToHvcallBins.Location = new Point(168, 15);
            txtPathToHvcallBins.Name = "txtPathToHvcallBins";
            txtPathToHvcallBins.Size = new Size(816, 31);
            txtPathToHvcallBins.TabIndex = 1;
            // 
            // richTextBox1
            // 
            richTextBox1.Location = new Point(12, 221);
            richTextBox1.Name = "richTextBox1";
            richTextBox1.Size = new Size(1330, 476);
            richTextBox1.TabIndex = 2;
            richTextBox1.Text = "";
            // 
            // btnHvcallBins
            // 
            btnHvcallBins.Location = new Point(1009, 13);
            btnHvcallBins.Name = "btnHvcallBins";
            btnHvcallBins.Size = new Size(333, 34);
            btnHvcallBins.TabIndex = 3;
            btnHvcallBins.Text = "Select";
            btnHvcallBins.UseVisualStyleBackColor = true;
            btnHvcallBins.Click += btnSelectHvBins_Click;
            // 
            // btnPathToIda
            // 
            btnPathToIda.Location = new Point(1007, 64);
            btnPathToIda.Name = "btnPathToIda";
            btnPathToIda.Size = new Size(335, 30);
            btnPathToIda.TabIndex = 4;
            btnPathToIda.Text = "Select";
            btnPathToIda.UseVisualStyleBackColor = true;
            btnPathToIda.Click += btnPathToIda_Click;
            // 
            // txtPathToIda
            // 
            txtPathToIda.Location = new Point(169, 61);
            txtPathToIda.Name = "txtPathToIda";
            txtPathToIda.Size = new Size(815, 31);
            txtPathToIda.TabIndex = 5;
            txtPathToIda.TextChanged += txtPathToIda_TextChanged;
            // 
            // btnStart
            // 
            btnStart.Location = new Point(614, 164);
            btnStart.Name = "btnStart";
            btnStart.Size = new Size(112, 34);
            btnStart.TabIndex = 6;
            btnStart.Text = "Start";
            btnStart.UseVisualStyleBackColor = true;
            btnStart.Click += btnStart_Click;
            // 
            // chkBoxProcessIDB
            // 
            chkBoxProcessIDB.AutoSize = true;
            chkBoxProcessIDB.Location = new Point(12, 169);
            chkBoxProcessIDB.Name = "chkBoxProcessIDB";
            chkBoxProcessIDB.Size = new Size(345, 29);
            chkBoxProcessIDB.TabIndex = 8;
            chkBoxProcessIDB.Text = "Process .i64 files in autonomous mode";
            chkBoxProcessIDB.UseVisualStyleBackColor = true;
            // 
            // button2
            // 
            button2.Location = new Point(1005, 164);
            button2.Name = "button2";
            button2.Size = new Size(337, 34);
            button2.TabIndex = 9;
            button2.Text = "Get binaries from current Windows";
            button2.UseVisualStyleBackColor = true;
            button2.Click += button2_Click;
            // 
            // txtScriptPath
            // 
            txtScriptPath.Location = new Point(168, 109);
            txtScriptPath.Name = "txtScriptPath";
            txtScriptPath.Size = new Size(816, 31);
            txtScriptPath.TabIndex = 10;
            // 
            // lblPathToBinaries
            // 
            lblPathToBinaries.AutoSize = true;
            lblPathToBinaries.Location = new Point(12, 21);
            lblPathToBinaries.Name = "lblPathToBinaries";
            lblPathToBinaries.Size = new Size(134, 25);
            lblPathToBinaries.TabIndex = 11;
            lblPathToBinaries.Text = "Path to binaries";
            // 
            // label1
            // 
            label1.AutoSize = true;
            label1.Location = new Point(12, 67);
            label1.Name = "label1";
            label1.Size = new Size(143, 25);
            label1.TabIndex = 12;
            label1.Text = "Path to IDA PRO";
            // 
            // label2
            // 
            label2.AutoSize = true;
            label2.Location = new Point(12, 112);
            label2.Name = "label2";
            label2.Size = new Size(124, 25);
            label2.TabIndex = 13;
            label2.Text = "Path to scripts";
            // 
            // btnPathToScripts
            // 
            btnPathToScripts.Location = new Point(1007, 112);
            btnPathToScripts.Name = "btnPathToScripts";
            btnPathToScripts.Size = new Size(335, 30);
            btnPathToScripts.TabIndex = 14;
            btnPathToScripts.Text = "Select";
            btnPathToScripts.UseVisualStyleBackColor = true;
            btnPathToScripts.Click += btnPathToScripts_Click;
            // 
            // frmForm01
            // 
            AutoScaleDimensions = new SizeF(10F, 25F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(1354, 709);
            Controls.Add(btnPathToScripts);
            Controls.Add(label2);
            Controls.Add(label1);
            Controls.Add(lblPathToBinaries);
            Controls.Add(txtScriptPath);
            Controls.Add(button2);
            Controls.Add(chkBoxProcessIDB);
            Controls.Add(btnStart);
            Controls.Add(txtPathToIda);
            Controls.Add(btnPathToIda);
            Controls.Add(btnHvcallBins);
            Controls.Add(richTextBox1);
            Controls.Add(txtPathToHvcallBins);
            Name = "frmForm01";
            Text = "Extract.Hvcalls GUI v1.0.20240505";
            Load += frmForm01_Load;
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion
        private TextBox txtPathToHvcallBins;
        private RichTextBox richTextBox1;
        private Button btnHvcallBins;
        private Button btnPathToIda;
        private TextBox txtPathToIda;
        private FolderBrowserDialog folderBrowserDialog1;
        private Button btnStart;
        private CheckBox chkBoxProcessIDB;
        private Button button2;
        private TextBox txtScriptPath;
        private Label lblPathToBinaries;
        private Label label1;
        private Label label2;
        private Button btnPathToScripts;
    }
}