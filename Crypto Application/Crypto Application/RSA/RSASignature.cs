using Crypto_Application.Util;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Crypto_Application.RSA
{
    class RSASignature
    {
        BigInteger N;
        BigInteger PhiN;
        BigInteger SECRET_KEY;
        BigInteger PUBLIC_KEY;
        public string sign_path;
        int key_size;
        int i;
        MathUtil math = new MathUtil(); 

        public RSASignature(BigInteger PUBLIC_KEY, BigInteger N, BigInteger PhiN, BigInteger SECRET_KEY, int key_size)
        {
            this.PUBLIC_KEY = PUBLIC_KEY;
            this.N = N;
            this.PhiN = PhiN;
            this.SECRET_KEY = SECRET_KEY;
            this.key_size = key_size;
        }

        static BigInteger HashFile(string path)
        {
            BigInteger hash_value;
            StringBuilder formatted;
            string hash_string = "";
            using (FileStream fs = new FileStream(path, FileMode.Open))
            using (BufferedStream bs = new BufferedStream(fs))
            {
                using (SHA1Managed sha1 = new SHA1Managed())
                {
                    byte[] hash = sha1.ComputeHash(bs);
                    formatted = new StringBuilder(2 * hash.Length);
                    foreach (byte b in hash)
                    {
                        formatted.AppendFormat("{0:X2}", b);
                    }
                    hash_string = "0" + formatted.ToString();
                }
            }
            hash_value = BigInteger.Parse(hash_string, System.Globalization.NumberStyles.AllowHexSpecifier);
            return hash_value;
        }

        public BigInteger Sign(string path)
        {
            BigInteger M = HashFile(path);
            BigInteger SIG = math.Fast_Exponent(M, SECRET_KEY, N);
            sign_path = "D:\\RSA\\" + key_size + "_" + i + "_Signature.txt";
            using (StreamWriter sw = new StreamWriter(sign_path))
            {
                sw.WriteLine(SIG.ToString());
            }
            i++;

            return SIG;
        }

        public bool Verify(string original_path, string signature_path)
        {
            BigInteger SIG = 0;
            using (StreamReader sr = new StreamReader(signature_path))
            {
                string line;
                while ((line = sr.ReadLine()) != null)
                {
                    SIG = BigInteger.Parse(line);
                }
            }

            BigInteger M = HashFile(original_path);
            BigInteger C = math.Fast_Exponent(SIG, PUBLIC_KEY, N);
            if(M == C)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

    }
}
