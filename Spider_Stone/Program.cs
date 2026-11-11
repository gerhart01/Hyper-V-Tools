using AI_FGF;

namespace SpiderStoneGUI;

internal static class Program
{
    /// <summary>The main entry point for the application.</summary>
    [STAThread]
    static void Main() => AiFgfApp.Run(() => new MainForm(), AiFgfTheme.MidnightBlue);
}
