using Microsoft.Win32;  
using System;
//
// __author__ = "Gerhart"
// __license__ = "GPL3"
//

using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Xml.Linq;
using System.Text.Json;
using System.Reflection;

namespace HvcallGui
{
    public class ParseHvCall
    {
        public static bool CheckRegistryPath(string path)
        {
            var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            var key = hklm.OpenSubKey(path);

            if (key == null)
            {
               return false;
            }

            return true;
        }

        //
        // https://stackoverflow.com/questions/41920032/automatically-find-the-path-of-the-python-executable 
        //
        public static string GetPythonPath(string requiredVersion = "", string maxVersion = "")
        {
            string[] possiblePythonLocations = new string[3] 
            {
                @"HKLM\SOFTWARE\Python\PythonCore\",
                @"HKCU\SOFTWARE\Python\PythonCore\",
                @"HKLM\SOFTWARE\Wow6432Node\Python\PythonCore\"
            };

            //Version number, install path
            Dictionary<string, string> pythonLocations = new Dictionary<string, string>();

            foreach (string possibleLocation in possiblePythonLocations)
            {
                string regKey = possibleLocation.Substring(0, 4), actualPath = possibleLocation.Substring(5);
                RegistryKey theKey = (regKey == "HKLM" ? Registry.LocalMachine : Registry.CurrentUser);

                if (theKey == null || actualPath == null)
                    continue;

                RegistryKey theValue = theKey.OpenSubKey(actualPath);

                if (theValue == null)
                    continue;

                foreach (var v in theValue.GetSubKeyNames())
                {
                    RegistryKey productKey = theValue.OpenSubKey(v);
                    if (productKey != null)
                    {
                        RegistryKey pythonExePath = productKey.OpenSubKey("InstallPath");

                        string pythonPath = "";

                        if (pythonExePath != null)
                        {
                            var valExecutePath = pythonExePath.GetValue("ExecutablePath");
                            if (valExecutePath != null)
                            {
                                pythonPath = valExecutePath.ToString();
                                // Comment this in to get (Default) value instead
                                // string pythonExePath = productKey.OpenSubKey("InstallPath").GetValue("").ToString();

                                if (pythonPath != "" && pythonPath is not null)
                                {
                                    //Console.WriteLine("Got python version; " + v + " at path; " + pythonExePath);
                                    pythonLocations.Add(v.ToString(), pythonPath);

                                }
                            }
                        }
                    }
                }
            }

            string highestVersion = "", highestVersionPath = "";

            if (pythonLocations.Count > 0)
            {
                System.Version desiredVersion = new System.Version(requiredVersion == "" ? "0.0.1" : requiredVersion),
                    maxPVersion = new System.Version(maxVersion == "" ? "999.999.999" : maxVersion);

                foreach (KeyValuePair<string, string> pVersion in pythonLocations)
                {
                    //TODO; if on 64-bit machine, prefer the 64 bit version over 32 and vice versa
                    int index = pVersion.Key.IndexOf("-"); //For x-32 and x-64 in version numbers
                    string formattedVersion = index > 0 ? pVersion.Key.Substring(0, index) : pVersion.Key;

                    System.Version thisVersion = new System.Version(formattedVersion);
                    int comparison = desiredVersion.CompareTo(thisVersion),
                        maxComparison = maxPVersion.CompareTo(thisVersion);

                    if (comparison <= 0)
                    {
                        //Version is greater or equal
                        if (maxComparison >= 0)
                        {
                            desiredVersion = thisVersion;

                            highestVersion = pVersion.Key;
                            highestVersionPath = pVersion.Value;
                        }
                        else
                        {
                            //Console.WriteLine("Version is too high; " + maxComparison.ToString());
                        }
                    }
                    else
                    {
                        //Console.WriteLine("Version (" + pVersion.Key + ") is not within the spectrum.");
                    }
                }

                //Console.WriteLine(highestVersion);
                //Console.WriteLine(highestVersionPath);       
            }

            return highestVersionPath;
        }

        public class ConfigFile
        {
            public string IdaPath { get; }
            public string WindowsBinaryPath { get;}
            public string ScriptPath { get; }
            public ConfigFile(string idaPath, string windowsBinaryPath, string scriptPath)
            {
                IdaPath = idaPath;
                WindowsBinaryPath = windowsBinaryPath;
                ScriptPath = scriptPath;
            }
        }

        public static ConfigFile ReadConfig(string filePath)
        {
            var myJsonString = File.ReadAllText(filePath);
            var model = JsonSerializer.Deserialize<ConfigFile>(myJsonString);
            return model;
        }
    }
}
