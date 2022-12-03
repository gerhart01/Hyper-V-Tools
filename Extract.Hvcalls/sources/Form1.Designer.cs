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
            this.txtPathToHvcallBins = new System.Windows.Forms.TextBox();
            this.richTextBox1 = new System.Windows.Forms.RichTextBox();
            this.btnHvcallBins = new System.Windows.Forms.Button();
            this.btnPathToIda = new System.Windows.Forms.Button();
            this.txtPathToIda = new System.Windows.Forms.TextBox();
            this.folderBrowserDialog1 = new System.Windows.Forms.FolderBrowserDialog();
            this.btnStart = new System.Windows.Forms.Button();
            this.button1 = new System.Windows.Forms.Button();
            this.chkBoxProcessIDB = new System.Windows.Forms.CheckBox();
            this.button2 = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // txtPathToHvcallBins
            // 
            this.txtPathToHvcallBins.Location = new System.Drawing.Point(12, 29);
            this.txtPathToHvcallBins.Name = "txtPathToHvcallBins";
            this.txtPathToHvcallBins.Size = new System.Drawing.Size(480, 31);
            this.txtPathToHvcallBins.TabIndex = 1;
            // 
            // richTextBox1
            // 
            this.richTextBox1.Location = new System.Drawing.Point(12, 247);
            this.richTextBox1.Name = "richTextBox1";
            this.richTextBox1.Size = new System.Drawing.Size(1006, 311);
            this.richTextBox1.TabIndex = 2;
            this.richTextBox1.Text = "";
            // 
            // btnHvcallBins
            // 
            this.btnHvcallBins.Location = new System.Drawing.Point(685, 12);
            this.btnHvcallBins.Name = "btnHvcallBins";
            this.btnHvcallBins.Size = new System.Drawing.Size(333, 34);
            this.btnHvcallBins.TabIndex = 3;
            this.btnHvcallBins.Text = "Path to binaries";
            this.btnHvcallBins.UseVisualStyleBackColor = true;
            this.btnHvcallBins.Click += new System.EventHandler(this.btnSelectHvBins_Click);
            // 
            // btnPathToIda
            // 
            this.btnPathToIda.Location = new System.Drawing.Point(683, 63);
            this.btnPathToIda.Name = "btnPathToIda";
            this.btnPathToIda.Size = new System.Drawing.Size(335, 34);
            this.btnPathToIda.TabIndex = 4;
            this.btnPathToIda.Text = "Select path to IDA PRO";
            this.btnPathToIda.UseVisualStyleBackColor = true;
            this.btnPathToIda.Click += new System.EventHandler(this.btnPathToIda_Click);
            // 
            // txtPathToIda
            // 
            this.txtPathToIda.Location = new System.Drawing.Point(13, 94);
            this.txtPathToIda.Name = "txtPathToIda";
            this.txtPathToIda.Size = new System.Drawing.Size(479, 31);
            this.txtPathToIda.TabIndex = 5;
            this.txtPathToIda.TextChanged += new System.EventHandler(this.txtPathToIda_TextChanged);
            // 
            // btnStart
            // 
            this.btnStart.Location = new System.Drawing.Point(503, 180);
            this.btnStart.Name = "btnStart";
            this.btnStart.Size = new System.Drawing.Size(112, 34);
            this.btnStart.TabIndex = 6;
            this.btnStart.Text = "Start";
            this.btnStart.UseVisualStyleBackColor = true;
            this.btnStart.Click += new System.EventHandler(this.btnStart_Click);
            // 
            // button1
            // 
            this.button1.Location = new System.Drawing.Point(683, 121);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(335, 37);
            this.button1.TabIndex = 7;
            this.button1.Text = "Get python path";
            this.button1.UseVisualStyleBackColor = true;
            this.button1.Click += new System.EventHandler(this.button1_Click);
            // 
            // chkBoxProcessIDB
            // 
            this.chkBoxProcessIDB.AutoSize = true;
            this.chkBoxProcessIDB.Location = new System.Drawing.Point(16, 176);
            this.chkBoxProcessIDB.Name = "chkBoxProcessIDB";
            this.chkBoxProcessIDB.Size = new System.Drawing.Size(317, 29);
            this.chkBoxProcessIDB.TabIndex = 8;
            this.chkBoxProcessIDB.Text = "Process .idb files with python script";
            this.chkBoxProcessIDB.UseVisualStyleBackColor = true;
            // 
            // button2
            // 
            this.button2.Location = new System.Drawing.Point(681, 180);
            this.button2.Name = "button2";
            this.button2.Size = new System.Drawing.Size(337, 34);
            this.button2.TabIndex = 9;
            this.button2.Text = "Get binaries from current Windows";
            this.button2.UseVisualStyleBackColor = true;
            this.button2.Click += new System.EventHandler(this.button2_Click);
            // 
            // frmForm01
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(10F, 25F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1030, 570);
            this.Controls.Add(this.button2);
            this.Controls.Add(this.chkBoxProcessIDB);
            this.Controls.Add(this.button1);
            this.Controls.Add(this.btnStart);
            this.Controls.Add(this.txtPathToIda);
            this.Controls.Add(this.btnPathToIda);
            this.Controls.Add(this.btnHvcallBins);
            this.Controls.Add(this.richTextBox1);
            this.Controls.Add(this.txtPathToHvcallBins);
            this.Name = "frmForm01";
            this.Text = "Extract.Hvcalls v1.0.20221109";
            this.Load += new System.EventHandler(this.frmForm01_Load);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion
        private TextBox txtPathToHvcallBins;
        private RichTextBox richTextBox1;
        private Button btnHvcallBins;
        private Button btnPathToIda;
        private TextBox txtPathToIda;
        private FolderBrowserDialog folderBrowserDialog1;
        private Button btnStart;
        private Button button1;
        private CheckBox chkBoxProcessIDB;
        private Button button2;
    }
}