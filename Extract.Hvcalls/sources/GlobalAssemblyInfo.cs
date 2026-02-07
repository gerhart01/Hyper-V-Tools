/*
 * File: GlobalAssemblyInfo.cs
 * Project: Extract.Hvcalls GUI v2.0.20250.102
 * Artifact: hvcall-gui-refactored in claude.ai
 * 
 * Description: Global assembly attributes - Integrated C# Processor Version
 * Author: Gerhart
 * License: GPL3
 * 
 * Change Log:
 * - v2.0.20250.100: Created global assembly information file
 * - v2.0.20250.101: Fixed version format and removed duplicate attributes
 * - v2.0.20250.102: Integrated C# processor, removed Python dependency
 */

using System.Reflection;
using System.Runtime.InteropServices;

#region General Assembly Information

[assembly: AssemblyTitle("Extract.Hvcalls GUI - Integrated C# Processor")]
[assembly: AssemblyDescription("Modern GUI for extracting Hyper-V system calls using IDA Pro with integrated C# JSON processor")]
[assembly: AssemblyConfiguration("")]
[assembly: AssemblyCompany("Gerhart")]
[assembly: AssemblyProduct("Extract.Hvcalls GUI")]
[assembly: AssemblyCopyright("Copyright © 2025 Gerhart. GPL3 License.")]
[assembly: AssemblyTrademark("")]
[assembly: AssemblyCulture("")]

#endregion

#region Version Information

/// <summary>
/// Version information for the assembly using proper .NET format
/// Format: Major.Minor.Build.Revision
/// v2.0.20250.102 - Integrated C# processor version
/// </summary>
[assembly: AssemblyVersion("2.0.20250.102")]
[assembly: AssemblyFileVersion("2.0.20250.102")]
[assembly: AssemblyInformationalVersion("2.0.20250.102 - Integrated C# Processor")]

#endregion

#region Platform and Runtime Information

/// <summary>
/// COM visibility settings - false to prevent COM registration
/// </summary>
[assembly: ComVisible(false)]

/// <summary>
/// Supported operating system platform
/// Requires Windows 10 build 22621 or later for optimal functionality
/// </summary>
[assembly: System.Runtime.Versioning.SupportedOSPlatform("windows10.0.22621.0")]

#endregion

#region Security Configuration

/// <summary>
/// Allow partially trusted callers for enhanced compatibility
/// </summary>
[assembly: System.Security.AllowPartiallyTrustedCallers]

#endregion
