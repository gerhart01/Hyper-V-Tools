# Spider Stone GUI (.NET 10)

Partitially AI generated

A **.NET 10 / WinForms** front-end for the current [`Spider-Stone.ps1`](../Spider_Stone/Spider-Stone.ps1).

Instead of re-implementing the analyzer in C# (which would drift from the maintained
PowerShell source of truth and its runtime `wcp.dll` loading), the GUI exposes every
script parameter as an input field and runs the **real script** via `pwsh`, streaming its
output live into an output pane. Whatever the script gains, the GUI gains for free.

## Requirements

- **.NET 10 SDK** (`net10.0-windows`) to build; the Windows Desktop runtime to run.
- **PowerShell 7** (`pwsh.exe`) on `PATH` or under `Program Files\PowerShell\7`.
- Windows 10/11 or Windows Server. The app ships an `app.manifest` that requests
  **Administrator** on launch (reading the CBS registry + WinSxS needs elevation),
  so you get a single UAC prompt up front instead of a failed run.

## Build & run

```powershell
cd SpiderStoneGUI
dotnet build -c Release
dotnet run  -c Release      # or launch bin\Release\net10.0-windows\SpiderStoneGUI.exe
```

The build copies `Spider-Stone.ps1` and `WCPExtractor.psm1` from `..\Spider_Stone` into
`bin\...\scripts\` (nothing is duplicated in source control). At runtime the GUI looks for
the script next to the executable first, then falls back to `..\Spider_Stone` for dev runs.

## Fields & buttons

| Control | Script parameter |
|---|---|
| Feature name *(dropdown + type-ahead)* | `-FeatureName` |
| Output directory (+ Browse) | `-OutputDirectory` |
| Component filter | `-ComponentFilter` |
| wcp.dll path (+ Browse) | `-PathToWcp` |
| Parse MUM files | `-ParsingMum` |
| No GridView *(default on)* | `-NotShowGridView` |
| Open HTML report | `-OpenReport` |
| Verbose | `-VerboseOutput` |
| **Run** | runs the analysis |
| **Cancel** | kills the running `pwsh` process |
| **List features** | runs with no feature → prints installed features |
| **Search wcp.dll** | runs `-SearchWcpDll` and auto-fills the wcp.dll field |
| **Open report** / **Open output folder** | opens `Report_<Feature>.html` / the per-feature folder |

The **Output** tab streams the script's console output live and has a **quick-find bar**
(type to search, `Ctrl+F` to focus it, `Enter`/`Shift+Enter` or `F3`/`Shift+F3` to jump
between matches, with an `n / total` position counter). The **Results** tab
lets you pick any produced CSV (`Components_`, `Dependencies_`, `Registry_`, …), view it
in a grid, and **Export view…** the shown table to a CSV file (UTF-8 with BOM, so Excel
reads non-ASCII correctly). A **progress bar** tracks each stage (package scan → copy →
WCP decompress → parse).

### Filtering the results grid

The Results tab has a **Filter** box: type to keep only the rows that contain your text in
**any** column (case-insensitive substring, live as you type). The counter shows
`shown of total row(s)`, **Export view…** writes exactly the filtered rows, and **✕** clears
the filter. This works for both a loaded CSV and the **List features** list, so you can
narrow a long component/feature list quickly and then click a row to load it into the
**Feature name** box.

### Feature dropdown & autocomplete

Press **List features** and the installed features fill the **Feature name** dropdown;
it also drives type-ahead autocomplete as you type. The script provides the names via an
opt-in machine-readable marker (below), so the list is always exactly what the script
would analyze — nothing is hard-coded in the GUI.

> The GUI sets the `pwsh` working directory to the script folder because the script
> resolves `WCPExtractor.psm1` via `Get-Location`, not `$PSScriptRoot`.

### How the progress bar works

The GUI sets the environment variable **`SPIDERSTONE_PROGRESS_STDOUT=1`** before running
the script. The script's `Write-StageProgress` helper then additionally emits a
machine-readable line per progress tick:

```
##PROGRESS##|<activity>|<percent>|<status>
```

and, at the end of a feature listing, one line per installed feature:

```
##FEATURE##|<feature name>
```

The GUI parses those lines to drive the progress bar and fill the feature dropdown, and
hides them from the log. Both are emitted via `Write-Host` (the Information stream) so they
never pollute function return values. Without the variable (i.e. normal command-line use)
nothing extra is printed — CLI behavior is unchanged.

## Status

Drives the current script end to end, with a live progress bar and a CSV results grid.
