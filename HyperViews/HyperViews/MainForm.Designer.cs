
namespace PTViewClient
{
    partial class MainForm
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
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
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            components = new System.ComponentModel.Container();
            lbl1 = new System.Windows.Forms.Label();
            ProcessesComboBox = new System.Windows.Forms.ComboBox();
            PTViewPanel = new System.Windows.Forms.Panel();
            DumpPageBtn = new System.Windows.Forms.Button();
            groupBox2 = new System.Windows.Forms.GroupBox();
            TranslateBtn = new System.Windows.Forms.Button();
            VirtualAddressInfoLblInput = new System.Windows.Forms.Label();
            label7 = new System.Windows.Forms.Label();
            VirtualAddressInput = new System.Windows.Forms.TextBox();
            label6 = new System.Windows.Forms.Label();
            groupBox1 = new System.Windows.Forms.GroupBox();
            VirtualAddressOutput = new System.Windows.Forms.TextBox();
            VirtualAddressInfoLbl = new System.Windows.Forms.Label();
            PTeInfoLbl = new System.Windows.Forms.Label();
            PDeInfoLbl = new System.Windows.Forms.Label();
            PDPTeLblInfo = new System.Windows.Forms.Label();
            PML4eInfoLbl = new System.Windows.Forms.Label();
            PtTextLbl = new System.Windows.Forms.Label();
            PTListBox = new System.Windows.Forms.ListBox();
            label3 = new System.Windows.Forms.Label();
            PDListBox = new System.Windows.Forms.ListBox();
            label2 = new System.Windows.Forms.Label();
            PDPTListBox = new System.Windows.Forms.ListBox();
            label1 = new System.Windows.Forms.Label();
            PML4ListBox = new System.Windows.Forms.ListBox();
            DirbaseLbl = new System.Windows.Forms.Label();
            UpdateContentTmr = new System.Windows.Forms.Timer(components);
            label5 = new System.Windows.Forms.Label();
            HighlightModeNx = new System.Windows.Forms.RadioButton();
            HighlightModeSupervisor = new System.Windows.Forms.RadioButton();
            HighlightModeNone = new System.Windows.Forms.RadioButton();
            PML4AutoEntryHighlight = new System.Windows.Forms.CheckBox();
            cb_VmList = new System.Windows.Forms.ComboBox();
            label4 = new System.Windows.Forms.Label();
            b_SelectVm = new System.Windows.Forms.Button();
            PTViewPanel.SuspendLayout();
            groupBox2.SuspendLayout();
            groupBox1.SuspendLayout();
            SuspendLayout();
            // 
            // lbl1
            // 
            lbl1.AutoSize = true;
            lbl1.Location = new System.Drawing.Point(42, 40);
            lbl1.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            lbl1.Name = "lbl1";
            lbl1.Size = new System.Drawing.Size(76, 25);
            lbl1.TabIndex = 0;
            lbl1.Text = "Process:";
            // 
            // ProcessesComboBox
            // 
            ProcessesComboBox.FormattingEnabled = true;
            ProcessesComboBox.Location = new System.Drawing.Point(131, 35);
            ProcessesComboBox.Margin = new System.Windows.Forms.Padding(4, 6, 4, 6);
            ProcessesComboBox.Name = "ProcessesComboBox";
            ProcessesComboBox.Size = new System.Drawing.Size(286, 33);
            ProcessesComboBox.TabIndex = 1;
            ProcessesComboBox.DropDown += ProcessesComboBox_DropDown;
            ProcessesComboBox.SelectedValueChanged += ProcessesComboBox_SelectedValueChanged;
            // 
            // PTViewPanel
            // 
            PTViewPanel.Controls.Add(DumpPageBtn);
            PTViewPanel.Controls.Add(groupBox2);
            PTViewPanel.Controls.Add(groupBox1);
            PTViewPanel.Controls.Add(PTeInfoLbl);
            PTViewPanel.Controls.Add(PDeInfoLbl);
            PTViewPanel.Controls.Add(PDPTeLblInfo);
            PTViewPanel.Controls.Add(PML4eInfoLbl);
            PTViewPanel.Controls.Add(PtTextLbl);
            PTViewPanel.Controls.Add(PTListBox);
            PTViewPanel.Controls.Add(label3);
            PTViewPanel.Controls.Add(PDListBox);
            PTViewPanel.Controls.Add(label2);
            PTViewPanel.Controls.Add(PDPTListBox);
            PTViewPanel.Controls.Add(label1);
            PTViewPanel.Controls.Add(PML4ListBox);
            PTViewPanel.Controls.Add(DirbaseLbl);
            PTViewPanel.Location = new System.Drawing.Point(20, 146);
            PTViewPanel.Margin = new System.Windows.Forms.Padding(4, 6, 4, 6);
            PTViewPanel.Name = "PTViewPanel";
            PTViewPanel.Size = new System.Drawing.Size(2012, 1281);
            PTViewPanel.TabIndex = 2;
            PTViewPanel.Visible = false;
            // 
            // DumpPageBtn
            // 
            DumpPageBtn.Location = new System.Drawing.Point(1490, 900);
            DumpPageBtn.Margin = new System.Windows.Forms.Padding(4, 6, 4, 6);
            DumpPageBtn.Name = "DumpPageBtn";
            DumpPageBtn.Size = new System.Drawing.Size(216, 44);
            DumpPageBtn.TabIndex = 7;
            DumpPageBtn.Text = "Dump Selected Page";
            DumpPageBtn.UseVisualStyleBackColor = true;
            DumpPageBtn.Click += DumpPageBtn_Click;
            // 
            // groupBox2
            // 
            groupBox2.Controls.Add(TranslateBtn);
            groupBox2.Controls.Add(VirtualAddressInfoLblInput);
            groupBox2.Controls.Add(label7);
            groupBox2.Controls.Add(VirtualAddressInput);
            groupBox2.Controls.Add(label6);
            groupBox2.Location = new System.Drawing.Point(1510, 392);
            groupBox2.Margin = new System.Windows.Forms.Padding(4, 6, 4, 6);
            groupBox2.Name = "groupBox2";
            groupBox2.Padding = new System.Windows.Forms.Padding(4, 6, 4, 6);
            groupBox2.Size = new System.Drawing.Size(460, 286);
            groupBox2.TabIndex = 6;
            groupBox2.TabStop = false;
            groupBox2.Text = "Address Translation";
            // 
            // TranslateBtn
            // 
            TranslateBtn.Location = new System.Drawing.Point(147, 242);
            TranslateBtn.Margin = new System.Windows.Forms.Padding(4, 6, 4, 6);
            TranslateBtn.Name = "TranslateBtn";
            TranslateBtn.Size = new System.Drawing.Size(170, 44);
            TranslateBtn.TabIndex = 3;
            TranslateBtn.Text = "Translate";
            TranslateBtn.UseVisualStyleBackColor = true;
            TranslateBtn.Click += TranslateBtn_Click;
            // 
            // VirtualAddressInfoLblInput
            // 
            VirtualAddressInfoLblInput.AutoSize = true;
            VirtualAddressInfoLblInput.Location = new System.Drawing.Point(27, 96);
            VirtualAddressInfoLblInput.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            VirtualAddressInfoLblInput.Name = "VirtualAddressInfoLblInput";
            VirtualAddressInfoLblInput.Size = new System.Drawing.Size(0, 25);
            VirtualAddressInfoLblInput.TabIndex = 2;
            // 
            // label7
            // 
            label7.AutoSize = true;
            label7.Location = new System.Drawing.Point(13, 54);
            label7.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label7.Name = "label7";
            label7.Size = new System.Drawing.Size(136, 25);
            label7.TabIndex = 2;
            label7.Text = "Virtual Address:";
            // 
            // VirtualAddressInput
            // 
            VirtualAddressInput.Location = new System.Drawing.Point(147, 48);
            VirtualAddressInput.Margin = new System.Windows.Forms.Padding(4, 6, 4, 6);
            VirtualAddressInput.Name = "VirtualAddressInput";
            VirtualAddressInput.Size = new System.Drawing.Size(282, 31);
            VirtualAddressInput.TabIndex = 1;
            VirtualAddressInput.TextChanged += VirtualAddressInput_TextChanged;
            // 
            // label6
            // 
            label6.AutoSize = true;
            label6.Location = new System.Drawing.Point(29, 48);
            label6.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label6.Name = "label6";
            label6.Size = new System.Drawing.Size(0, 25);
            label6.TabIndex = 0;
            // 
            // groupBox1
            // 
            groupBox1.Controls.Add(VirtualAddressOutput);
            groupBox1.Controls.Add(VirtualAddressInfoLbl);
            groupBox1.Location = new System.Drawing.Point(1510, 111);
            groupBox1.Margin = new System.Windows.Forms.Padding(4, 6, 4, 6);
            groupBox1.Name = "groupBox1";
            groupBox1.Padding = new System.Windows.Forms.Padding(4, 6, 4, 6);
            groupBox1.Size = new System.Drawing.Size(460, 235);
            groupBox1.TabIndex = 5;
            groupBox1.TabStop = false;
            groupBox1.Text = "Virtual Address";
            // 
            // VirtualAddressOutput
            // 
            VirtualAddressOutput.Location = new System.Drawing.Point(16, 178);
            VirtualAddressOutput.Margin = new System.Windows.Forms.Padding(4, 6, 4, 6);
            VirtualAddressOutput.Name = "VirtualAddressOutput";
            VirtualAddressOutput.ReadOnly = true;
            VirtualAddressOutput.Size = new System.Drawing.Size(433, 31);
            VirtualAddressOutput.TabIndex = 1;
            // 
            // VirtualAddressInfoLbl
            // 
            VirtualAddressInfoLbl.AutoSize = true;
            VirtualAddressInfoLbl.Location = new System.Drawing.Point(29, 48);
            VirtualAddressInfoLbl.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            VirtualAddressInfoLbl.Name = "VirtualAddressInfoLbl";
            VirtualAddressInfoLbl.Size = new System.Drawing.Size(0, 25);
            VirtualAddressInfoLbl.TabIndex = 0;
            // 
            // PTeInfoLbl
            // 
            PTeInfoLbl.AutoSize = true;
            PTeInfoLbl.Location = new System.Drawing.Point(1144, 952);
            PTeInfoLbl.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            PTeInfoLbl.Name = "PTeInfoLbl";
            PTeInfoLbl.Size = new System.Drawing.Size(0, 25);
            PTeInfoLbl.TabIndex = 4;
            // 
            // PDeInfoLbl
            // 
            PDeInfoLbl.AutoSize = true;
            PDeInfoLbl.Location = new System.Drawing.Point(782, 956);
            PDeInfoLbl.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            PDeInfoLbl.Name = "PDeInfoLbl";
            PDeInfoLbl.Size = new System.Drawing.Size(0, 25);
            PDeInfoLbl.TabIndex = 4;
            // 
            // PDPTeLblInfo
            // 
            PDPTeLblInfo.AutoSize = true;
            PDPTeLblInfo.Location = new System.Drawing.Point(431, 956);
            PDPTeLblInfo.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            PDPTeLblInfo.Name = "PDPTeLblInfo";
            PDPTeLblInfo.Size = new System.Drawing.Size(0, 25);
            PDPTeLblInfo.TabIndex = 4;
            // 
            // PML4eInfoLbl
            // 
            PML4eInfoLbl.AutoSize = true;
            PML4eInfoLbl.Location = new System.Drawing.Point(64, 956);
            PML4eInfoLbl.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            PML4eInfoLbl.Name = "PML4eInfoLbl";
            PML4eInfoLbl.Size = new System.Drawing.Size(0, 25);
            PML4eInfoLbl.TabIndex = 3;
            // 
            // PtTextLbl
            // 
            PtTextLbl.AutoSize = true;
            PtTextLbl.Location = new System.Drawing.Point(1297, 81);
            PtTextLbl.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            PtTextLbl.Name = "PtTextLbl";
            PtTextLbl.Size = new System.Drawing.Size(31, 25);
            PtTextLbl.TabIndex = 2;
            PtTextLbl.Text = "PT";
            // 
            // PTListBox
            // 
            PTListBox.DrawMode = System.Windows.Forms.DrawMode.OwnerDrawFixed;
            PTListBox.Location = new System.Drawing.Point(1130, 111);
            PTListBox.Margin = new System.Windows.Forms.Padding(4, 6, 4, 6);
            PTListBox.Name = "PTListBox";
            PTListBox.Size = new System.Drawing.Size(347, 796);
            PTListBox.TabIndex = 1;
            PTListBox.DrawItem += PTListBox_DrawItem;
            // 
            // label3
            // 
            label3.AutoSize = true;
            label3.Location = new System.Drawing.Point(944, 81);
            label3.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label3.Name = "label3";
            label3.Size = new System.Drawing.Size(35, 25);
            label3.TabIndex = 2;
            label3.Text = "PD";
            // 
            // PDListBox
            // 
            PDListBox.DrawMode = System.Windows.Forms.DrawMode.OwnerDrawFixed;
            PDListBox.Location = new System.Drawing.Point(770, 111);
            PDListBox.Margin = new System.Windows.Forms.Padding(4, 6, 4, 6);
            PDListBox.Name = "PDListBox";
            PDListBox.Size = new System.Drawing.Size(347, 796);
            PDListBox.TabIndex = 1;
            PDListBox.DrawItem += PDListBox_DrawItem;
            // 
            // label2
            // 
            label2.AutoSize = true;
            label2.Location = new System.Drawing.Point(563, 81);
            label2.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label2.Name = "label2";
            label2.Size = new System.Drawing.Size(54, 25);
            label2.TabIndex = 2;
            label2.Text = "PDPT";
            // 
            // PDPTListBox
            // 
            PDPTListBox.DrawMode = System.Windows.Forms.DrawMode.OwnerDrawFixed;
            PDPTListBox.Location = new System.Drawing.Point(410, 111);
            PDPTListBox.Margin = new System.Windows.Forms.Padding(4, 6, 4, 6);
            PDPTListBox.Name = "PDPTListBox";
            PDPTListBox.Size = new System.Drawing.Size(347, 796);
            PDPTListBox.TabIndex = 1;
            PDPTListBox.DrawItem += PDPTListBox_DrawItem;
            // 
            // label1
            // 
            label1.AutoSize = true;
            label1.Location = new System.Drawing.Point(164, 81);
            label1.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label1.Name = "label1";
            label1.Size = new System.Drawing.Size(56, 25);
            label1.TabIndex = 2;
            label1.Text = "PML4";
            // 
            // PML4ListBox
            // 
            PML4ListBox.DrawMode = System.Windows.Forms.DrawMode.OwnerDrawFixed;
            PML4ListBox.Location = new System.Drawing.Point(50, 111);
            PML4ListBox.Margin = new System.Windows.Forms.Padding(4, 6, 4, 6);
            PML4ListBox.Name = "PML4ListBox";
            PML4ListBox.Size = new System.Drawing.Size(347, 796);
            PML4ListBox.TabIndex = 1;
            PML4ListBox.DrawItem += PML4ListBox_DrawItem;
            // 
            // DirbaseLbl
            // 
            DirbaseLbl.AutoSize = true;
            DirbaseLbl.Location = new System.Drawing.Point(22, 22);
            DirbaseLbl.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            DirbaseLbl.Name = "DirbaseLbl";
            DirbaseLbl.Size = new System.Drawing.Size(115, 25);
            DirbaseLbl.TabIndex = 0;
            DirbaseLbl.Text = "Dirbase (cr3):";
            // 
            // UpdateContentTmr
            // 
            UpdateContentTmr.Tick += UpdateContentTmr_Tick;
            // 
            // label5
            // 
            label5.AutoSize = true;
            label5.Location = new System.Drawing.Point(617, 32);
            label5.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label5.Name = "label5";
            label5.Size = new System.Drawing.Size(141, 25);
            label5.TabIndex = 4;
            label5.Text = "Highlight Mode:";
            // 
            // HighlightModeNx
            // 
            HighlightModeNx.AutoSize = true;
            HighlightModeNx.Location = new System.Drawing.Point(762, 104);
            HighlightModeNx.Margin = new System.Windows.Forms.Padding(4, 6, 4, 6);
            HighlightModeNx.Name = "HighlightModeNx";
            HighlightModeNx.Size = new System.Drawing.Size(320, 29);
            HighlightModeNx.TabIndex = 5;
            HighlightModeNx.Text = "Highlight executable pages in green";
            HighlightModeNx.UseVisualStyleBackColor = true;
            HighlightModeNx.CheckedChanged += HighlightModeNx_CheckedChanged;
            // 
            // HighlightModeSupervisor
            // 
            HighlightModeSupervisor.AutoSize = true;
            HighlightModeSupervisor.Location = new System.Drawing.Point(762, 65);
            HighlightModeSupervisor.Margin = new System.Windows.Forms.Padding(4, 6, 4, 6);
            HighlightModeSupervisor.Name = "HighlightModeSupervisor";
            HighlightModeSupervisor.Size = new System.Drawing.Size(400, 29);
            HighlightModeSupervisor.TabIndex = 5;
            HighlightModeSupervisor.Text = "Highlight User (green) and Kernel (blue) pages";
            HighlightModeSupervisor.UseVisualStyleBackColor = true;
            // 
            // HighlightModeNone
            // 
            HighlightModeNone.AutoSize = true;
            HighlightModeNone.Checked = true;
            HighlightModeNone.Location = new System.Drawing.Point(762, 29);
            HighlightModeNone.Margin = new System.Windows.Forms.Padding(4, 6, 4, 6);
            HighlightModeNone.Name = "HighlightModeNone";
            HighlightModeNone.Size = new System.Drawing.Size(80, 29);
            HighlightModeNone.TabIndex = 6;
            HighlightModeNone.TabStop = true;
            HighlightModeNone.Text = "None";
            HighlightModeNone.UseVisualStyleBackColor = true;
            HighlightModeNone.CheckedChanged += HighlightModeNone_CheckedChanged;
            // 
            // PML4AutoEntryHighlight
            // 
            PML4AutoEntryHighlight.AutoSize = true;
            PML4AutoEntryHighlight.Location = new System.Drawing.Point(1189, 31);
            PML4AutoEntryHighlight.Margin = new System.Windows.Forms.Padding(4, 6, 4, 6);
            PML4AutoEntryHighlight.Name = "PML4AutoEntryHighlight";
            PML4AutoEntryHighlight.Size = new System.Drawing.Size(355, 29);
            PML4AutoEntryHighlight.TabIndex = 7;
            PML4AutoEntryHighlight.Text = "Highlight PML4 auto-entry in lime green";
            PML4AutoEntryHighlight.UseVisualStyleBackColor = true;
            // 
            // cb_VmList
            // 
            cb_VmList.FormattingEnabled = true;
            cb_VmList.Location = new System.Drawing.Point(1738, 29);
            cb_VmList.Margin = new System.Windows.Forms.Padding(4, 6, 4, 6);
            cb_VmList.Name = "cb_VmList";
            cb_VmList.Size = new System.Drawing.Size(286, 33);
            cb_VmList.TabIndex = 8;
            cb_VmList.DropDown += cb_VmList_DropDown;
            cb_VmList.SelectedValueChanged += cb_VmList_SelectedValueChanged;
            // 
            // label4
            // 
            label4.AutoSize = true;
            label4.Location = new System.Drawing.Point(1627, 32);
            label4.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label4.Name = "label4";
            label4.Size = new System.Drawing.Size(87, 25);
            label4.TabIndex = 9;
            label4.Text = "VMname:";
            // 
            // b_SelectVm
            // 
            b_SelectVm.Location = new System.Drawing.Point(1738, 75);
            b_SelectVm.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
            b_SelectVm.Name = "b_SelectVm";
            b_SelectVm.Size = new System.Drawing.Size(109, 48);
            b_SelectVm.TabIndex = 10;
            b_SelectVm.Text = "Select VM";
            b_SelectVm.UseVisualStyleBackColor = true;
            b_SelectVm.Click += b_SelectVm_Click;
            // 
            // MainForm
            // 
            AutoScaleDimensions = new System.Drawing.SizeF(10F, 25F);
            AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            ClientSize = new System.Drawing.Size(2047, 1460);
            Controls.Add(b_SelectVm);
            Controls.Add(label4);
            Controls.Add(cb_VmList);
            Controls.Add(PML4AutoEntryHighlight);
            Controls.Add(HighlightModeNone);
            Controls.Add(HighlightModeSupervisor);
            Controls.Add(HighlightModeNx);
            Controls.Add(label5);
            Controls.Add(PTViewPanel);
            Controls.Add(ProcessesComboBox);
            Controls.Add(lbl1);
            FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedToolWindow;
            Margin = new System.Windows.Forms.Padding(4, 6, 4, 6);
            Name = "MainForm";
            Text = "HyperViews";
            PTViewPanel.ResumeLayout(false);
            PTViewPanel.PerformLayout();
            groupBox2.ResumeLayout(false);
            groupBox2.PerformLayout();
            groupBox1.ResumeLayout(false);
            groupBox1.PerformLayout();
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion

        private System.Windows.Forms.Label lbl1;
        private System.Windows.Forms.ComboBox ProcessesComboBox;
        private System.Windows.Forms.Panel PTViewPanel;
        private System.Windows.Forms.Label DirbaseLbl;
        private System.Windows.Forms.Label PtTextLbl;
        private System.Windows.Forms.ListBox PTListBox;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.ListBox PDListBox;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.ListBox PDPTListBox;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.ListBox PML4ListBox;
        private System.Windows.Forms.Timer UpdateContentTmr;
        private System.Windows.Forms.Label PTeInfoLbl;
        private System.Windows.Forms.Label PDeInfoLbl;
        private System.Windows.Forms.Label PDPTeLblInfo;
        private System.Windows.Forms.Label PML4eInfoLbl;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.RadioButton HighlightModeNx;
        private System.Windows.Forms.RadioButton HighlightModeSupervisor;
        private System.Windows.Forms.RadioButton HighlightModeNone;
        private System.Windows.Forms.GroupBox groupBox1;
        private System.Windows.Forms.Label VirtualAddressInfoLbl;
        private System.Windows.Forms.TextBox VirtualAddressOutput;
        private System.Windows.Forms.GroupBox groupBox2;
        private System.Windows.Forms.Label label7;
        private System.Windows.Forms.TextBox VirtualAddressInput;
        private System.Windows.Forms.Label label6;
        private System.Windows.Forms.Label VirtualAddressInfoLblInput;
        private System.Windows.Forms.Button TranslateBtn;
        private System.Windows.Forms.Button DumpPageBtn;
        private System.Windows.Forms.CheckBox PML4AutoEntryHighlight;
        private System.Windows.Forms.ComboBox cb_VmList;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.Button b_SelectVm;
    }
}

