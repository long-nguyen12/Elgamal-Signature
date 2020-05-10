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
    class RSACrypto
    {
        MathUtil mathUtil = new MathUtil();
        Conversion conversion = new Conversion();
        
        BigInteger N;
        BigInteger PhiN;
        BigInteger SECRET_KEY;
        BigInteger PUBLIC_KEY;
        int key_size;
        BigInteger Ciphers;

        public RSACrypto(BigInteger PUBLIC_KEY, BigInteger N, BigInteger PhiN, BigInteger SECRET_KEY, int key_size)
        {
            this.PUBLIC_KEY = PUBLIC_KEY;
            this.N = N;
            this.PhiN = PhiN;
            this.SECRET_KEY = SECRET_KEY;
            this.key_size = key_size;
        }

        public string Encrypt(string message)
        {
            byte[] getBytes = conversion.ConvertToByteArray(message, Encoding.ASCII);
            string plain_bits = conversion.ToBinary(getBytes);
            BigInteger plain_number = conversion.BinaryToNumber(plain_bits);
            Ciphers = mathUtil.Fast_Exponent(plain_number, PUBLIC_KEY, N);
            string cipher_bits = Extension.BigIntegerExtensions.ToBinaryString(Ciphers);
            for (int i = 0; i < cipher_bits.Length % 8; i++)
            {
                cipher_bits = "0" + cipher_bits;
            }
            return conversion.BinaryToString(cipher_bits);
        }

        public string Decrypt()
        {
            BigInteger plain_number = mathUtil.Fast_Exponent(Ciphers, SECRET_KEY, N);
            string plain_txt = "";
            string plain_bits = Extension.BigIntegerExtensions.ToBinaryString(plain_number);
            for (int i = 0; i < plain_bits.Length % 8; i++)
            {
                plain_bits = "0" + plain_bits;
            }

            plain_txt = conversion.BinaryToString(plain_bits);
            return plain_txt;
        }

        FileUtil fileUtil = new FileUtil();
        public string Encrypt_File(string path)
        {
            string file_directory = fileUtil.GetDirectory(path);
            string file_name = fileUtil.getFileName(path);
            file_name = file_name.Substring(0, file_name.Length - 4);

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
            string cipher_bits = "";
            foreach (var b in bytes)
            {
                cipher_bits += Convert.ToString(b, 2).PadLeft(8, '0');
            }

            BigInteger plain_number = conversion.BinaryToNumber(cipher_bits);

            Ciphers = mathUtil.Fast_Exponent(plain_number, PUBLIC_KEY, N);

            string getBinary = Extension.BigIntegerExtensions.ToBinaryString(Ciphers);
           
            int file_length = getBinary.Length / 8;
            byte[] enc_bytes = new byte[file_length];
            for (int i = 0; i < file_length; i++)
            {
                enc_bytes[i] = Convert.ToByte(getBinary.Substring(8 * i, 8), 2);
            }
            File.WriteAllBytes(new_path, enc_bytes);
            return new_path;
        }

        public string Decrypt_File(string path)
        {
            string file_directory = fileUtil.GetDirectory(path);
            string file_name = fileUtil.getFileName(path);
            string extension = file_name.Substring(file_name.LastIndexOf("."));
            file_name = file_name.Substring(0, file_name.LastIndexOf("."));


            BigInteger plain_number = mathUtil.Fast_Exponent(Ciphers, SECRET_KEY, N);
            string binary = Extension.BigIntegerExtensions.ToBinaryString(plain_number);
            for (int i = 0; i < binary.Length % 8; i++)
            {
                binary = "0" + binary;
            }
            int length = binary.Length / 8;
            byte[] bytes = new byte[length];
            for (int i = 0; i < length; i++)
            {
                bytes[i] = Convert.ToByte(binary.Substring(8 * i, 8), 2);
            }

            string decrypt_path = file_directory + file_name + "_Decrypt" + extension;
            File.WriteAllBytes(decrypt_path, bytes);
            return decrypt_path;
        }
    }
}
