//
// __author__ = "Gerhart"
// __license__ = "GPL3"
//

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace HvcallGui
{   
    class ModuleHvCalls
    {   
        public static void GetHvcallBinaries(string[] hvFiles, string dir_with_hvcalls_bin, frmForm01 form) 
        {
            string systemDir = Environment.GetFolderPath(Environment.SpecialFolder.System) + "\\";

            if (!Directory.Exists(dir_with_hvcalls_bin))
            {
                form.PrintText("Directory " + dir_with_hvcalls_bin + "is not presented. Try to create it\n");
                System.IO.Directory.CreateDirectory(dir_with_hvcalls_bin);
            }

            foreach (string fileName in hvFiles)
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

                string dstFileName = dir_with_hvcalls_bin + "\\" + fileName;

                if (File.Exists(file))
                {
                    if (!File.Exists(dstFileName))
                    {
                        File.Copy(file, dstFileName);
                        form.PrintText("file " + file + " was copied to " + dstFileName + "\n");
                    }
                    else
                    {
                        form.PrintText("file " + dstFileName + " already presented. Please, clear directory before copy file\n");
                    }       
                }
                else
                {
                    form.PrintText("File " + fileName + " is not found\n");
                }
            }
        }

        //
        // https://stackoverflow.com/questions/27680977/wait-for-multiple-processes-to-complete
        //
        public static void RunParallelScript1(string idaPath, List<string> listOfScripts)
        {
            List<Task> tasks = new List<Task>();
            foreach (string script in listOfScripts)
            {
                string tmpScript = script;
                tasks.Add(Task.Run(delegate
                {
                    ProcessStartInfo myProcess = new ProcessStartInfo();
                    myProcess.FileName = idaPath;
                    myProcess.Arguments = tmpScript;
                    Process.Start(myProcess).WaitForExit();
                }));
            }
            Task.WaitAll(tasks.ToArray());
        }

        public static void HvcallExtract(
                frmForm01 form,
                string g_dir_with_hvcalls_bin,
                string g_path_to_ida,
                string g_path_to_script_folder,
                string g_union_json_script_name,
                bool IschkBoxProcessIDB,
                string g_script_name
            )
        {
            if (Directory.Exists(g_dir_with_hvcalls_bin) == false)
            {
                form.PrintText("Specify the directory with Hyper-V binaries\n");
                return;
            }

            if (File.Exists(g_path_to_ida) == false)
            {
                form.PrintText("Specify the IDA PRO executable (file ida64.exe)\n");
                return;
            }

            if (Directory.Exists(g_path_to_script_folder) == false)
            {
                form.PrintText("Specify the directory with hvcall_path.py\n");
                return;
            }

            List<string> listOfScripts = new List<string>();

            string[] formats = { ".sys", ".exe" };
            var hvFiles = Directory.EnumerateFiles(g_dir_with_hvcalls_bin, "*.*", SearchOption.TopDirectoryOnly).Where(x => formats.Any(x.EndsWith));

            int filesCount = 0;

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
                string pathToScriptWithQuotes = '"' + g_path_to_script_folder + "\\" + g_script_name + '"';

                //
                // If i64 file exists
                //

                if (File.Exists(idbPath) == true)
                {
                    string pathToIDBWithQuotas = '"' + idbPath + '"';
                    idaParam = "-A -S" + pathToScriptWithQuotes + " " + pathToIDBWithQuotas;

                    form.PrintText("processing .i64[.idb] file: " + shortIDB + "...  " + fileVersion.FileVersion + "\n");
                }
                else
                {
                    if (IschkBoxProcessIDB == true)
                    {
                        string pathToFileWithQuotas = '"' + currentFile + '"';
                        idaParam = "-c -A -S" + pathToScriptWithQuotes + " " + pathToFileWithQuotas;
                    }
                    else
                    {
                        idaParam = "-c -B -S" + pathToScriptWithQuotes + " " + currentFile;
                    }

                    form.PrintText("processing file " + Path.GetFileName(currentFile) + "...  " + fileVersion.FileVersion + "\n");
                }

                //form.PrintText("string to run " + g_path_to_ida + " " + idaParam + "\n");
                listOfScripts.Add(idaParam);
            }

            RunParallelScript1(g_path_to_ida, listOfScripts);
            form.PrintText("Files processing are finished. Run hvcalls_merge.py.\n");

            string pythonPath = ParseHvCall.GetPythonPath();
            string fullScriptPath = g_path_to_script_folder + "\\" + g_union_json_script_name;

            System.Diagnostics.Process.Start(pythonPath, fullScriptPath);
            form.PrintText("Extracted files were merged.\n");
        }
    }
}
