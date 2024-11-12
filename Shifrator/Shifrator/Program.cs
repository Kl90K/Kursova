using EncryptionApp;
using System;
using System.Windows.Forms;

namespace Shifrator
{
    static class Program
    {
        [STAThread]
        static void Main()
        {
            // Налаштування візуальних стилів
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            // Запуск основної форми
            Application.Run(new MainForm());
        }
    }
}