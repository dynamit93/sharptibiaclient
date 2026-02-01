using System;

namespace CTC
{
#if WINDOWS || XBOX || DESKTOPGL || LINUX || MACOS
    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        static void Main(string[] args)
        {
            // Present the debug window on Windows only.
#if WINDOWS
            DebugWindow dbw = new DebugWindow();
            dbw.Show();
#endif

            // Then run the game
            using (Game game = new Game())
            {
                game.Run();
            }
        }
    }
#endif
}

