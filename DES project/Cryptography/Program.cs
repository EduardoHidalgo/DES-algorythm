using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Cryptography
{
    static class Program
    {
        /// <summary>
        /// Punto de entrada principal para la aplicación.
        /// </summary>
        [STAThread]
        static void Main()
        {
            //Application.EnableVisualStyles();
            //Application.SetCompatibleTextRenderingDefault(false);
            //Application.Run(new Form1());
            DataEncryptionStandard Encryption = new DataEncryptionStandard();
            Encryption.Encrypt("HOLA MUNDO, MI NOMBRE ES EDUARDO", "FUN4V3BH");
        }
    }
}
