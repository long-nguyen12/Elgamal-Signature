using Crypto_Application.Util;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Crypto_Application.Elgamal
{
    class ElgamalSignature
    {
        #region
        public string sign_path;
        public BigInteger K;
        public BigInteger PUBLIC_KEY;
        BigInteger P;
        BigInteger G;
        BigInteger SECRET_KEY;
        BigInteger R;
        BigInteger S;
        MathUtil math = new MathUtil();
        int key_size;
        int i;
        #endregion

        public ElgamalSignature(BigInteger PUBLIC_KEY, BigInteger P, BigInteger G, BigInteger SECRET_KEY, int key_size)
        {
            this.PUBLIC_KEY = PUBLIC_KEY;
            this.P = P;
            this.G = G;
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

        public ArrayList Sign(string path)
        {
            
            do
            {
                K = math.GetRandomNumber(key_size);
            } while (math.Extended_Euclid(K, P - 1) == false || K < 2 || K > P - 2);
            BigInteger M = HashFile(path);
            R = math.Fast_Exponent(G, K, P);
            S = (((M - SECRET_KEY * R) % (P - 1)) * math.Inverse_Modulo(K, P - 1)) % (P - 1);
            if(S < 0)
            {
                S = S + P - 1;
            }
            ArrayList signature = new ArrayList();
            signature.Add(R);
            signature.Add(S);
            sign_path = "D:\\Elgamal\\" + key_size + "_" + i + "_Signature.txt";
            using (StreamWriter sw = new StreamWriter(sign_path))
            {

                foreach (BigInteger s in signature)
                {
                    sw.WriteLine(s.ToString());
                }
            }
            i++;
            return signature;
        }

        public bool Verify(string original_file, string signature_file)
        {
            BigInteger[] signature = new BigInteger[2];
            using (StreamReader sr = new StreamReader(signature_file))
            {
                string line;
                int count = 0;
                while ((line = sr.ReadLine()) != null)
                {
                    signature[count++] = BigInteger.Parse(line);
                }

            }
            BigInteger M = HashFile(original_file);
            BigInteger first_value = math.Fast_Exponent(G, M, P);
            BigInteger second_value = (math.Fast_Exponent(PUBLIC_KEY, signature[0], P) * math.Fast_Exponent(signature[0], signature[1], P)) % P;
            if(first_value == second_value)
            {
                return true;
            }

            return false;
        }
    }
}
