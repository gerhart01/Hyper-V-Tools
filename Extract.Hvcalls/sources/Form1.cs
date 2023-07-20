//
// __author__ = "Gerhart"
// __license__ = "GPL3"
//

using static System.Net.Mime.MediaTypeNames;
using System.Collections;
using System.IO;
using System;
using System.Drawing;
using System.Diagnostics;
using System.Linq.Expressions;
using System.Windows.Forms;

namespace HvcallGui
{
    public partial class frmForm01 : Form
    {

        public string g_dir_with_hvcalls_bin = "";
        public string g_path_to_ida = "";
        public string g_path_to_script_folder = "";
        public string g_script_name = "extract_hvcalls.py";
        public string g_union_json_script_name = "hvcalls_merge.py";
        public string g_config_name = "config.json";

        public string[] g_hvFiles = { "winhvr.sys", "winhv.sys", "securekernel.exe", "ntoskrnl.exe", "ntkrla57.exe", "securekernella57.exe" };

        public frmForm01()
        {
            InitializeComponent();
        }

        public void PrintText(string Text)
        {
            richTextBox1.AppendText(Text);
        }

        private void GetHvcallBinaries(HvcallGui.frmForm01 form)
        {
            if (form.txtPathToHvcallBins.Text != "")
            {
                g_dir_with_hvcalls_bin = form.txtPathToHvcallBins.Text;
            }

            ModuleHvCalls.GetHvcallBinaries(g_hvFiles, g_dir_with_hvcalls_bin, form);
        }

        public void HvcallExtract()
        {
            ModuleHvCalls.HvcallExtract(
                this,
                g_dir_with_hvcalls_bin,
                g_path_to_ida,
                g_path_to_script_folder,
                g_union_json_script_name,
                chkBoxProcessIDB.Checked,
                g_script_name
            );
        }
        private void btnPathToIda_Click(object sender, EventArgs e)
        {
            OpenFileDialog ofdOpenIda = new OpenFileDialog();

            ofdOpenIda.InitialDirectory = "c:\\";
            ofdOpenIda.Filter = "Ida PRO 64 (*.exe)|*.exe";
            ofdOpenIda.FilterIndex = 0;
            ofdOpenIda.RestoreDirectory = true;

            if (txtPathToIda.Text != "")
            {
                ofdOpenIda.FileName = txtPathToIda.Text;
            }

            if (ofdOpenIda.ShowDialog() == DialogResult.OK)
            {
                txtPathToIda.Text = ofdOpenIda.FileName;
                g_path_to_ida = ofdOpenIda.FileName;
            }
        }

        private void btnSelectHvBins_Click(object sender, EventArgs e)
        {
            if (txtPathToHvcallBins.Text != "")
            {
                folderBrowserDialog1.SelectedPath = txtPathToHvcallBins.Text;
            }

            if (folderBrowserDialog1.ShowDialog() == DialogResult.OK)
            {
                txtPathToHvcallBins.Text = folderBrowserDialog1.SelectedPath;
                g_dir_with_hvcalls_bin = folderBrowserDialog1.SelectedPath;
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            string pythonPath = ParseHvCall.GetPythonPath("3.1", "3.11");
            return;
        }

        private void ReadConfigAndFilltxtBoxes()
        {
            string cfgFile = Directory.GetCurrentDirectory() + "\\" + g_config_name;

            if (!File.Exists(cfgFile))
            {
                richTextBox1.AppendText("Configuration file config.json is not found\n ");
                return;
            }

            ParseHvCall.ConfigFile cfg = ParseHvCall.ReadConfig(Directory.GetCurrentDirectory() + "\\" + g_config_name);
            if (cfg != null)
            {
                txtPathToHvcallBins.Text = cfg.WindowsBinaryPath;
                txtPathToIda.Text = cfg.IdaPath;
                txtScriptPath.Text = cfg.ScriptPath;
                g_dir_with_hvcalls_bin = cfg.WindowsBinaryPath;
                g_path_to_ida = cfg.IdaPath;
                //g_path_to_script_folder = Directory.GetCurrentDirectory() + "\\" + g_script_name;
                g_path_to_script_folder = cfg.ScriptPath;
            }
        }

        private void frmForm01_Load(object sender, EventArgs e)
        {
            ReadConfigAndFilltxtBoxes();
        }

        private void btnStart_Click(object sender, EventArgs e)
        {
            HvcallExtract();
        }

        private void txtPathToIda_TextChanged(object sender, EventArgs e)
        {
            g_path_to_ida = txtPathToIda.Text;
        }

        private void button2_Click(object sender, EventArgs e)
        {
            GetHvcallBinaries(this);
        }

        private void btnPathToScripts_Click(object sender, EventArgs e)
        {
            if (txtScriptPath.Text != "")
            {
                folderBrowserDialog1.SelectedPath = txtScriptPath.Text;
            }

            if (folderBrowserDialog1.ShowDialog() == DialogResult.OK)
            {
                txtScriptPath.Text = folderBrowserDialog1.SelectedPath;
                g_path_to_script_folder = folderBrowserDialog1.SelectedPath;
            }
        }
    }
}