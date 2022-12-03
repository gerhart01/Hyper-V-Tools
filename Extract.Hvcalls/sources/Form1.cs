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
        public string g_path_to_script = "";
        public string g_script_name = "extract_hvcalls.py";
        public string g_union_json_script_name = "hvcalls_merge.py";

        public string[] g_hvFiles = { "winhvr.sys", "winhv.sys", "securekernel.exe", "ntoskrnl.exe", "ntkrla57.exe", "securekernella57.exe" };

        public frmForm01()
        {
            InitializeComponent();
        }

        //https://stackoverflow.com/questions/27680977/wait-for-multiple-processes-to-complete
        private void RunParallelScript(string idaPath, List<string> listOfScripts)
        {
            List<Task> tasks = new List<Task>();
            foreach (string script in listOfScripts)
            {
                string tmpScript = script;
                tasks.Add(Task.Run(delegate {
                    ProcessStartInfo myProcess = new ProcessStartInfo();
                    myProcess.FileName = idaPath;
                    myProcess.Arguments = tmpScript;
                    Process.Start(myProcess).WaitForExit();
                }));
            }
            Task.WaitAll(tasks.ToArray());
        }

        private void GetHvcallBinaries(HvcallGui.frmForm01 form)
        {
            string systemDir = Environment.GetFolderPath(Environment.SpecialFolder.System) + "\\";

            foreach (string fileName in g_hvFiles)
            {
                string file = "";
                if (fileName.Contains(".sys"))
                {
                    file = systemDir + "drivers\\" + fileName;
                }
                else
                {
                    file = systemDir + fileName;
                }

                if (File.Exists(file))
                {
                    File.Copy(g_dir_with_hvcalls_bin, file);
                }
                else
                {
                    form.richTextBox1.AppendText("File " + fileName + " is not found\n");
                }
            }
        }

        public void HvcallExtract()
        {
            if (Directory.Exists(g_dir_with_hvcalls_bin) == false)
            {
                richTextBox1.AppendText("Specify the directory with Hyper-V binaries\n");
                return;
            }

            if (File.Exists(g_path_to_ida) == false)
            {
                richTextBox1.AppendText("Specify the IDA PRO executable (file ida64.exe)\n");
                return;
            }

            if (File.Exists(g_path_to_script) == false)
            {
                richTextBox1.AppendText("Specify the directory with hvcall_path.py\n");
                return;
            }

            List<string> listOfScripts = new List<string>();

            string[] formats = { ".sys", ".exe" };
            var hvFiles = Directory.EnumerateFiles(g_dir_with_hvcalls_bin, "*.*", SearchOption.TopDirectoryOnly).Where(x => formats.Any(x.EndsWith));

            foreach (string currentFile in hvFiles)
            {
                if (currentFile is null)
                    continue;

                FileVersionInfo fileVersion = FileVersionInfo.GetVersionInfo(currentFile);
                string shortIDB = Path.GetFileNameWithoutExtension(currentFile) + ".i64";
                string shortFileName = Path.GetFileName(currentFile);
                string fileDir = Path.GetDirectoryName(currentFile);

                string idbPath = currentFile + ".i64";
                string idaParam = "";
                if (File.Exists(idbPath) == true)
                {
                    string pathToScriptWithQuotes = '"' + g_path_to_script + '"';
                    string pathToIDBWithQuotas = '"' + idbPath + '"';
                    idaParam = "-A -S" + pathToScriptWithQuotes + " " + pathToIDBWithQuotas;

                    richTextBox1.AppendText("processing .i64[.idb] file: " + shortIDB + "...  " + fileVersion.FileVersion +"\n");
                }
                else
                {
                    if (chkBoxProcessIDB.Checked == false)
                    {
                        idaParam = "-c -B " + currentFile;
                    }
                    else
                    {
                        string pathToScriptWithQuotes = '"' + g_path_to_script + '"';
                        string pathToFileWithQuotas = '"' + currentFile + '"';
                        idaParam = "-c -A -S" + pathToScriptWithQuotes + " " + pathToFileWithQuotas;
                    }

                    richTextBox1.AppendText("processing file " + Path.GetFileName(currentFile) + "...  " + fileVersion.FileVersion + "\n");
                }

                listOfScripts.Add(idaParam);
            }

            RunParallelScript(g_path_to_ida, listOfScripts);
            richTextBox1.AppendText("Files processing are finished. Run hvcalls_merge.py ...\n");

            string pythonPath = ParseHvCall.GetPythonPath();
            string fullScriptPath = Directory.GetCurrentDirectory() + "\\" + g_union_json_script_name;

            System.Diagnostics.Process.Start(pythonPath, fullScriptPath);
        }
        private void btnPathToIda_Click(object sender, EventArgs e)
        {
            OpenFileDialog ofdOpenIda = new OpenFileDialog();

            ofdOpenIda.InitialDirectory = "c:\\";
            ofdOpenIda.Filter = "Ida PRO 64 (*.exe)|*.exe";
            ofdOpenIda.FilterIndex = 0;
            ofdOpenIda.RestoreDirectory = true;

            if (ofdOpenIda.ShowDialog() == DialogResult.OK)
            {
                txtPathToIda.Text = ofdOpenIda.FileName;
                g_path_to_ida = ofdOpenIda.FileName;
            }
        }

        private void btnSelectHvBins_Click(object sender, EventArgs e)
        {
            if (folderBrowserDialog1.ShowDialog() == DialogResult.OK)
            {
                txtPathToHvcallBins.Text = folderBrowserDialog1.SelectedPath;
                g_dir_with_hvcalls_bin = folderBrowserDialog1.SelectedPath;
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            string pythonPath = ParseHvCall.GetPythonPath("3.1", "3.10");
            return;
        }

        private void ReadConfigAndFilltxtBoxes()
        {
            string cfgFile = Directory.GetCurrentDirectory() + "\\config.json";

            if (!File.Exists(cfgFile))
            {
                richTextBox1.AppendText("Configuration file config.json is not found\n ");
                return;
            }

            ParseHvCall.ConfigFile cfg = ParseHvCall.ReadConfig(Directory.GetCurrentDirectory() + "\\config.json");
            if (cfg != null)
            {
                txtPathToHvcallBins.Text = cfg.WindowsBinaryPath;
                txtPathToIda.Text = cfg.IdaPath;
                g_dir_with_hvcalls_bin = cfg.WindowsBinaryPath;
                g_path_to_ida = cfg.IdaPath;
                g_path_to_script = Directory.GetCurrentDirectory() + "\\" + g_script_name;
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
    }
}