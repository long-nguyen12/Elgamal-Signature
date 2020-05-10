using Crypto_Application.Util;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Crypto_Application.Elgamal
{
    class ElgamalCrypto
    {
        #region
        MathUtil mathUtil = new MathUtil();
        Conversion conversion = new Conversion();

        public BigInteger K;
        public BigInteger PUBLIC_KEY;
        BigInteger P;
        BigInteger G;
        BigInteger SECRET_KEY;
        BigInteger c1;
        BigInteger[] c2;
        int key_size;
        #endregion

        public ElgamalCrypto(BigInteger PUBLIC_KEY, BigInteger P, BigInteger G, BigInteger SECRET_KEY, int key_size)
        {
            this.PUBLIC_KEY = PUBLIC_KEY;
            this.P = P;
            this.G = G;
            this.SECRET_KEY = SECRET_KEY;
            this.key_size = key_size;
        }

        public string Encrypt(string message)
        {
            do
            {
                //K = mathUtil.RandomInRange(RandomNumberGenerator.Create(), 2, P - 2);
                K = mathUtil.GetRandomNumber(key_size);
            } while (K < 2 || K > P - 2);

            // string cipher_bits = conversion.StringToBinary(message);
            byte[] getBytes = conversion.ConvertToByteArray(message, Encoding.ASCII);
            string cipher_bits = conversion.ToBinary(getBytes);

            int length = 0;
            if (cipher_bits.Length % key_size == 0)
            {
                length = cipher_bits.Length / key_size;
            }
            else
            {
                length = cipher_bits.Length / key_size + 1;
            }
            BigInteger[] plain_numbers = new BigInteger[length];
            for (int i = 0; i < plain_numbers.Length; i++)
            {
                string temp = "";
                if (cipher_bits.Length < key_size)
                {
                    temp = cipher_bits.Substring(0, cipher_bits.Length);
                    cipher_bits = cipher_bits.Remove(0, cipher_bits.Length);
                }
                else
                {
                    temp = cipher_bits.Substring(0, key_size);
                    cipher_bits = cipher_bits.Remove(0, key_size);
                }
                plain_numbers[i] = conversion.BinaryToNumber(temp);
            }
            // calculate c1, c2
            c1 = mathUtil.Fast_Exponent(G, K, P);

            c2 = new BigInteger[plain_numbers.Length];

            BigInteger expo = mathUtil.Fast_Exponent(PUBLIC_KEY, K, P);

            for (int i = 0; i < plain_numbers.Length; i++)
            {
                c2[i] = ((plain_numbers[i] % P) * expo) % P;
            }

            // change c2 into binary -> get cipher text
            string encrypt_txt = "";
            for (int i = 0; i < c2.Length; i++)
            {
                string temp = Extension.BigIntegerExtensions.ToBinaryString(c2[i]);
                for (int j = 0; j < temp.Length % 8; j++)
                {
                    temp = "0" + temp;
                }
                encrypt_txt += conversion.BinaryToString(temp);
            }
            return encrypt_txt;
        }

        public string Decrypt()
        {
            BigInteger x = mathUtil.Fast_Exponent(c1, SECRET_KEY, P);
            BigInteger b = mathUtil.Inverse_Modulo(x, P);
            BigInteger[] plain_numbers = new BigInteger[c2.Length];
            for (int i = 0; i < c2.Length; i++)
            {
                plain_numbers[i] = ((c2[i] % P) * b) % P;
            }
            string plain_txt = "";
            for (int i = 0; i < plain_numbers.Length; i++)
            {
                string temp = Extension.BigIntegerExtensions.ToBinaryString(plain_numbers[i]);
                for (int j = 0; j < temp.Length % 8; j++)
                {
                    temp = "0" + temp;
                }
                plain_txt += conversion.BinaryToString(temp);
            }
            return plain_txt;
        }

        FileUtil fileUtil = new FileUtil();

        public string Encrypt_File(string path)
        {
            K = mathUtil.RandomInRange(P - 2);

            string file_directory = fileUtil.GetDirectory(path);
            string file_name = fileUtil.getFileName(path);
            file_name = file_name.Substring(0, file_name.LastIndexOf("."));

            string new_path = file_directory + file_name + FileExtensions.ENCRYPT_FILE_EXTENSION;

            byte[] bytes;
            try
            {
                using (FileStream file = new FileStream(path, FileMode.Open, FileAccess.Read))
                {
                    bytes = new byte[file.Length];
                    file.Read(bytes, 0, (int)file.Length);
                }
            }
            catch
            {
                return "";
            }
            string plain_bits = "";
            foreach (var b in bytes)
            {
                string temp = Convert.ToString(b, 2).PadLeft(8, '0');
                plain_bits += temp;
            }
            
            int length = 0;
            if (plain_bits.Length % key_size == 0)
            {
                length = plain_bits.Length / key_size;
            }
            else
            {
                length = plain_bits.Length / key_size + 1;
            }
            BigInteger[] plain_numbers = new BigInteger[length];
            for (int i = 0; i < plain_numbers.Length; i++)
            {
                string temp = "";
                if (plain_bits.Length < key_size)
                {
                    temp = plain_bits.Substring(0, plain_bits.Length);
                    plain_bits = plain_bits.Remove(0, plain_bits.Length);
                }
                else
                {
                    temp = plain_bits.Substring(0, key_size);
                    plain_bits = plain_bits.Remove(0, key_size);
                }
                plain_numbers[i] = conversion.BinaryToNumber(temp);
            }
            // calculate c1, c2
            c1 = mathUtil.Fast_Exponent(G, K, P);

            c2 = new BigInteger[plain_numbers.Length];

            BigInteger expo = mathUtil.Fast_Exponent(PUBLIC_KEY, K, P);

            //for (int i = 0; i < plain_numbers.Length; i++)
            //{
            //    c2[i] = ((plain_numbers[i] % P) * expo) % P;
            //}

            //string getBinary = "";
            //for (int i = 0; i < c2.Length; i++)
            //{
            //    string temp = Extension.BigIntegerExtensions.ToBinaryString(c2[i]);
            //    for (int j = 0; j < temp.Length % 8; j++)
            //    {
            //        temp = "0" + temp;
            //    }
            //    getBinary += temp;
            //}
            //int file_length = getBinary.Length / 8;
            //byte[] enc_bytes = new byte[file_length];
            //for (int i = 0; i < file_length; i++)
            //{
            //    enc_bytes[i] = Convert.ToByte(getBinary.Substring(8 * i, 8), 2);
            //}


            //File.WriteAllBytes(new_path, enc_bytes);

            string getBinary = "";
            for (int i = 0; i < plain_numbers.Length; i++)
            {
                c2[i] = ((plain_numbers[i] % P) * expo) % P;
                getBinary = Extension.BigIntegerExtensions.ToBinaryString(c2[i]);
                for (int j = 0; j < getBinary.Length % 8; j++)
                {
                    getBinary = "0" + getBinary;
                }
                int file_length = getBinary.Length / 8;
                byte[] enc_bytes = new byte[file_length];
                for (int j = 0; j < file_length; j++)
                {
                    enc_bytes[j] = Convert.ToByte(getBinary.Substring(8 * j, 8), 2);
                }
                using (FileStream fs = File.Open(new_path, FileMode.Open, FileAccess.Write))
                {
                    fs.Write(enc_bytes, 0, enc_bytes.Length);
                   }
            }
            
            return new_path;
        }

        public string Decrypt_File(string path)
        {
            string file_directory = fileUtil.GetDirectory(path);
            string file_name = fileUtil.getFileName(path);
            string extension = file_name.Substring(file_name.LastIndexOf("."));
            file_name = file_name.Substring(0, file_name.LastIndexOf("."));

            BigInteger x = mathUtil.Fast_Exponent(c1, SECRET_KEY, P);
            BigInteger b = mathUtil.Inverse_Modulo(x, P);
            BigInteger[] plain_numbers = new BigInteger[c2.Length];
            for (int i = 0; i < c2.Length; i++)
            {
                plain_numbers[i] = ((c2[i] % P) * b) % P;
            }
            string plain_binary = "";
            for (int i = 0; i < plain_numbers.Length; i++)
            {
                string temp = Extension.BigIntegerExtensions.ToBinaryString(plain_numbers[i]);
                for (int j = 0; j < temp.Length % 8; j++)
                {
                    temp = "0" + temp;
                }
                plain_binary += temp;
            }
            int length = plain_binary.Length / 8;
            byte[] bytes = new byte[length];
            for (int i = 0; i < length; i++)
            {
                bytes[i] = Convert.ToByte(plain_binary.Substring(8 * i, 8), 2);
            }

            string decrypt_path = file_directory + file_name + "_Decrypt" + extension;
            File.WriteAllBytes(decrypt_path, bytes);
            return decrypt_path;
        }


    }
}
