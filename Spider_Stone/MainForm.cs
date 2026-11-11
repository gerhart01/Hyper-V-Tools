using System.Data;
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using AI_FGF;

namespace SpiderStoneGUI;

/// <summary>
/// .NET 10 / WinForms front-end for Spider-Stone.ps1 (Windows Optional Feature analyzer),
/// built on <see cref="ToolForm"/> (AI_FGF). The window chrome, Run/Cancel, progress bar,
/// log (with quick-find), results grid (with filter + CSV export) and settings persistence
/// come from the framework; this class only describes the parameters, how to build the
/// pwsh.exe command line per mode, and the few behaviours a spec can't express (the
/// ##FEATURE## marker, picking a wcp.dll path out of the log, switching between several
/// produced CSV files, clicking a grid cell to fill the Feature name box).
/// </summary>
public sealed class MainForm : ToolForm
{
    private enum RunMode { Analyze, ListFeatures, SearchWcp }

    private const string FeatureMarker = "##FEATURE##";

    // Columns whose value is a usable feature/component name for the Feature name box.
    private static readonly HashSet<string> NameLikeColumns = new(StringComparer.OrdinalIgnoreCase)
    {
        "Feature", "Component", "AssemblyName", "Name", "ManifestName", "DisplayName",
    };

    private RunMode _mode = RunMode.Analyze;
    private readonly List<string> _featureNames = new();
    private string? _lastFeatureDir;

    private ComboBox _cmbFeature = null!;
    private ComboBox _cmbCsv = null!;
    private TextBox _txtOutputDir = null!, _txtComponentFilter = null!, _txtWcp = null!;

    protected override string FormTitle => "Spider Stone GUI — Windows Optional Feature Analyzer";
    protected override AiFgfButtonStyle ButtonStyle => AiFgfButtonStyle.Glow;   // flat / raised / glow; user can change under "Theme…"
    protected override bool ThemeButton => true;
    protected override bool PresetButtons => true;
    protected override string RunButtonText => "▶ &Run";

    public MainForm()
    {
        Fields.SetValue("OutputDirectory", Path.Combine(AppContext.BaseDirectory, "OptionalFeatureFiles"));

        string? script = ResolveScriptPath();
        string? pwsh = ResolvePwshPath();
        Log.Line($"Script : {script ?? "NOT FOUND"}");
        Log.Line($"pwsh   : {pwsh ?? "NOT FOUND — install PowerShell 7"}");
        Log.Line("Ready. Enter a feature name and press Run — or press \"List features\" to see what is installed.");

        Results.CellActivated += (column, value) =>
        {
            if (!NameLikeColumns.Contains(column) || string.IsNullOrWhiteSpace(value)) return;
            _cmbFeature.Text = value.Trim();
        };
    }

    protected override void BuildParameters(FormScaffold.RowBuilder rows)
    {
        rows.Combo("Feature name:", out _cmbFeature, editable: true, key: "Feature");
        rows.FolderText("Output directory:", out _txtOutputDir, "Select output directory", key: "OutputDirectory");
        rows.Text("Component filter:", out _txtComponentFilter, key: "ComponentFilter");
        rows.FileText("wcp.dll path:", out _txtWcp, "wcp.dll|wcp.dll|DLL files (*.dll)|*.dll|All files (*.*)|*.*", key: "Wcp");

        rows.Checks(
            ("ParsingMum", AiFgf.Check("Parse MUM files (-ParsingMum)")),
            ("NotShowGridView", AiFgf.Check("No GridView (-NotShowGridView)", @checked: true)),
            ("OpenReport", AiFgf.Check("Open HTML report (-OpenReport)")),
            ("VerboseOutput", AiFgf.Check("Verbose (-VerboseOutput)")));

        _cmbCsv = AiFgf.Combo(editable: false);
        _cmbCsv.Width = 220;
        _cmbCsv.SelectedIndexChanged += CmbCsv_SelectedIndexChanged;
        Button btnRefreshCsv = AiFgf.SmallButton("Refresh", (_, _) => PopulateCsvList(_lastFeatureDir));
        rows.Custom("CSV:", _cmbCsv, btnRefreshCsv);

        // A feature name is required only to Analyze; "List features" / "Search wcp.dll" don't need one.
        rows.Fields.Rule("Feature", v => _mode == RunMode.Analyze && string.IsNullOrWhiteSpace(v)
            ? "Please enter a feature name (or use \"List features\")." : null);

        // Direct3D (AI_FGF): fields get AiFgfButton's own sunken Raised bevel plus its soft accent
        // halo on focus; their native text/caret/selection are untouched.
        AiFgfFieldGlow.Wrap(_cmbFeature).Sunken = true;
        AiFgfFieldGlow.Wrap(_txtOutputDir).Sunken = true;
        AiFgfFieldGlow.Wrap(_txtComponentFilter).Sunken = true;
        AiFgfFieldGlow.Wrap(_txtWcp).Sunken = true;
        AiFgfFieldGlow.Wrap(_cmbCsv).Sunken = true;
    }

    protected override void ConfigureButtons(FormScaffold.BarBuilder bar)
    {
        bar.Button("List features", (_, _) => { _mode = RunMode.ListFeatures; StartRun(); }, out _);
        bar.Button("Search wcp.dll", (_, _) => { _mode = RunMode.SearchWcp; StartRun(); }, out _);
        bar.Button("Open report", (_, _) => OpenReport(), out _);
        bar.Button("Open output folder", (_, _) => OpenOutputFolder(), out _);
        bar.Button("Clear log", (_, _) => Log.Clear(), out _);
    }

    protected override ProcessRunner? BuildRun()
    {
        string? script = ResolveScriptPath();
        if (script is null)
        {
            MessageBox.Show(this,
                "Spider-Stone.ps1 was not found next to the executable (scripts\\) or in ..\\Spider_Stone.",
                "Script not found", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return null;
        }

        string? pwsh = ResolvePwshPath();
        if (pwsh is null)
        {
            MessageBox.Show(this,
                "PowerShell 7 (pwsh.exe) was not found. Install it from https://aka.ms/powershell and try again.",
                "pwsh not found", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return null;
        }

        string scriptDir = Path.GetDirectoryName(script)!;

        var runner = new ProcessRunner(pwsh)
            .Arg("-NoProfile").Arg("-ExecutionPolicy").Arg("Bypass").Arg("-File").Arg(script)
            // Critical: the script resolves WCPExtractor.psm1 via Get-Location, so the
            // working directory must be the folder that holds both files.
            .WorkingDirectory(scriptDir)
            // Ask the script to emit machine-readable progress/feature markers to stdout.
            .Env("SPIDERSTONE_PROGRESS_STDOUT", "1")
            .Utf8();

        switch (_mode)
        {
            case RunMode.Analyze:
                runner.Option("-FeatureName", _cmbFeature.Text)
                      .Option("-OutputDirectory", Fields.Text("OutputDirectory"))
                      .Option("-ComponentFilter", Fields.Text("ComponentFilter"))
                      .Option("-PathToWcp", Fields.Text("Wcp"))
                      .ArgIf(Fields.Bool("ParsingMum"), "-ParsingMum")
                      .ArgIf(Fields.Bool("NotShowGridView"), "-NotShowGridView")
                      .ArgIf(Fields.Bool("OpenReport"), "-OpenReport")
                      .ArgIf(Fields.Bool("VerboseOutput"), "-VerboseOutput");
                break;

            case RunMode.ListFeatures:
                runner.Arg("-NotShowGridView"); // no -FeatureName => prints installed features
                break;

            case RunMode.SearchWcp:
                runner.Arg("-SearchWcpDll").Arg("-NotShowGridView");
                break;
        }

        lock (_featureNames) _featureNames.Clear();

        // ##FEATURE##|<name> — collected for the dropdown. Note: unlike the pre-port app, this
        // line is NOT hidden from the visible log — ToolForm's own marker handling only
        // recognises its single ProgressMarker, with no hook to suppress a second, app-defined
        // marker. Accepted as a cosmetic regression (see migration report).
        runner.Output += (kind, line) =>
        {
            if (kind != OutputKind.StdOut) return;
            if (!line.StartsWith(FeatureMarker, StringComparison.Ordinal)) return;

            string name = line.Length > FeatureMarker.Length + 1 ? line[(FeatureMarker.Length + 1)..] : "";
            if (name.Length == 0) return;
            lock (_featureNames) _featureNames.Add(name);
        };

        return runner;
    }

    protected override void OnRunFinished(ProcessResult result)
    {
        switch (_mode)
        {
            case RunMode.SearchWcp:
                TryPickWcpFromOutput(result.StdOut);
                break;

            case RunMode.ListFeatures:
                PopulateFeatureCombo();
                break;

            case RunMode.Analyze:
                if (result.Success)
                {
                    _lastFeatureDir = ComputeFeatureDir(out _);
                    PopulateCsvList(_lastFeatureDir);
                    if (_cmbCsv.Items.Count > 0) ShowResultsTab();
                }
                break;
        }

        _mode = RunMode.Analyze; // the plain Run button always analyzes
    }

    // ------------------------------------------------------------- feature dropdown / grid

    /// <summary>
    /// Fill the Feature name dropdown (and its type-ahead autocomplete) from the names the
    /// script emitted as "##FEATURE##|&lt;name&gt;" during "List features", and show the same
    /// names as a clickable, filterable list in the Results grid.
    /// </summary>
    private void PopulateFeatureCombo()
    {
        string[] names;
        lock (_featureNames)
            names = _featureNames
                .Where(n => !string.IsNullOrWhiteSpace(n))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
                .ToArray();

        if (names.Length == 0) return;

        string typed = _cmbFeature.Text;
        _cmbFeature.BeginUpdate();
        _cmbFeature.Items.Clear();
        _cmbFeature.Items.AddRange(names);
        _cmbFeature.EndUpdate();
        _cmbFeature.Text = typed; // don't clobber what the user was typing

        var dt = new DataTable();
        dt.Columns.Add("Feature");
        foreach (string n in names) dt.Rows.Add(n);

        _cmbCsv.SelectedIndexChanged -= CmbCsv_SelectedIndexChanged;
        _cmbCsv.Items.Clear();
        _cmbCsv.SelectedIndexChanged += CmbCsv_SelectedIndexChanged;
        _lastFeatureDir = null; // this grid is the feature list, not a CSV-backed view

        Results.Show(dt);
        ShowResultsTab();
    }

    private void CmbCsv_SelectedIndexChanged(object? sender, EventArgs e)
    {
        if (_lastFeatureDir is null || _cmbCsv.SelectedItem is null) return;
        string path = Path.Combine(_lastFeatureDir, (string)_cmbCsv.SelectedItem);
        try
        {
            Results.ShowCsv(path);
        }
        catch (Exception ex)
        {
            Log.Error($"Failed to load {path}: {ex.Message}");
        }
    }

    private void PopulateCsvList(string? featureDir)
    {
        _cmbCsv.SelectedIndexChanged -= CmbCsv_SelectedIndexChanged;
        _cmbCsv.Items.Clear();

        if (!string.IsNullOrEmpty(featureDir) && Directory.Exists(featureDir))
        {
            foreach (string f in Directory.GetFiles(featureDir, "*.csv").OrderBy(f => f))
                _cmbCsv.Items.Add(Path.GetFileName(f));
        }

        _cmbCsv.SelectedIndexChanged += CmbCsv_SelectedIndexChanged;

        if (_cmbCsv.Items.Count == 0)
        {
            Log.Line("No CSV files produced.");
            return;
        }

        // Prefer the main file list; otherwise the first available.
        int preferred = 0;
        for (int i = 0; i < _cmbCsv.Items.Count; i++)
        {
            if (((string)_cmbCsv.Items[i]!).StartsWith("OptionalFeatureFiles_", StringComparison.OrdinalIgnoreCase))
            {
                preferred = i;
                break;
            }
        }
        _cmbCsv.SelectedIndex = preferred; // triggers CmbCsv_SelectedIndexChanged
    }

    // --------------------------------------------------------------------- helpers

    private void TryPickWcpFromOutput(IReadOnlyList<string> stdOut)
    {
        var rx = new Regex(@"[A-Za-z]:\\[^""'\r\n]*?wcp\.dll", RegexOptions.IgnoreCase);
        for (int i = stdOut.Count - 1; i >= 0; i--)
        {
            Match m = rx.Match(stdOut[i]);
            if (m.Success && File.Exists(m.Value))
            {
                Fields.SetValue("Wcp", m.Value);
                Log.Success($"[picked wcp.dll → {m.Value}]");
                return;
            }
        }
    }

    private void OpenReport()
    {
        string dir = ComputeFeatureDir(out string safe);
        string report = Path.Combine(dir, $"Report_{safe}.html");
        if (!File.Exists(report))
        {
            MessageBox.Show(this, $"Report not found:\n{report}\n\nRun an analysis first.",
                "No report", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        Process.Start(new ProcessStartInfo(report) { UseShellExecute = true });
    }

    private void OpenOutputFolder()
    {
        string dir = ComputeFeatureDir(out _);
        string toOpen = Directory.Exists(dir) ? dir : Path.GetDirectoryName(dir) ?? dir;
        if (!Directory.Exists(toOpen))
        {
            MessageBox.Show(this, $"Folder does not exist yet:\n{toOpen}",
                "No folder", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        Process.Start(new ProcessStartInfo(toOpen) { UseShellExecute = true });
    }

    /// <summary>Mirror the script's per-feature folder: OutputDirectory\&lt;safe-feature&gt;.</summary>
    private string ComputeFeatureDir(out string safe)
    {
        string outDir = Fields.Text("OutputDirectory");
        if (outDir.Length == 0)
            outDir = Path.Combine(AppContext.BaseDirectory, "OptionalFeatureFiles");

        if (!Path.IsPathRooted(outDir))
        {
            string? script = ResolveScriptPath();
            string baseDir = script is not null ? Path.GetDirectoryName(script)! : AppContext.BaseDirectory;
            outDir = Path.GetFullPath(Path.Combine(baseDir, outDir));
        }

        string feature = _cmbFeature.Text.Trim();
        safe = feature.Length == 0 ? "AllFeatures" : Regex.Replace(feature, @"[^\w\-]", "_");
        return Path.Combine(outDir, safe);
    }

    // ----------------------------------------------------- path resolution

    private static string? ResolveScriptPath()
    {
        foreach (string c in ScriptCandidates())
            if (File.Exists(c)) return Path.GetFullPath(c);
        return null;
    }

    private static IEnumerable<string> ScriptCandidates()
    {
        string bd = AppContext.BaseDirectory;
        yield return Path.Combine(bd, "scripts", "Spider-Stone.ps1");                              // bundled next to exe
        yield return Path.Combine(bd, "..", "..", "..", "..", "Spider_Stone", "Spider-Stone.ps1"); // dev: repo tree
        yield return Path.Combine(bd, "..", "Spider_Stone", "Spider-Stone.ps1");
    }

    private static string? ResolvePwshPath()
    {
        foreach (string name in new[] { "pwsh.exe", "pwsh" })
        {
            string? found = FindInPath(name);
            if (found is not null) return found;
        }

        foreach (var special in new[] { Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86 })
        {
            string guess = Path.Combine(Environment.GetFolderPath(special), "PowerShell", "7", "pwsh.exe");
            if (File.Exists(guess)) return guess;
        }
        return null;
    }

    private static string? FindInPath(string exe)
    {
        string path = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (string dir in path.Split(Path.PathSeparator))
        {
            if (string.IsNullOrWhiteSpace(dir)) continue;
            try
            {
                string full = Path.Combine(dir.Trim(), exe);
                if (File.Exists(full)) return full;
            }
            catch { /* malformed PATH entry */ }
        }
        return null;
    }
}
