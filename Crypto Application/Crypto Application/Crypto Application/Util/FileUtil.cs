using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Crypto_Application.Util
{
    class FileUtil
    {
        public string GetDirectory(string filePath)
        {
            string directory = filePath.Substring(0, filePath.LastIndexOf('\\'));
            return directory;
        }

        public string getFileName(string filePath)
        {
            string fileName = filePath.Substring(filePath.LastIndexOf('\\'));
            return fileName;
        }
    }
}
