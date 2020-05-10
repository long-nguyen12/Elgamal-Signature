using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Crypto_Application.Util
{
    class MathUtil
    {

        public BigInteger RandomInRange(BigInteger max)
        {
            byte[] bytes = max.ToByteArray();
            BigInteger R;
            Random random = new Random();
            do
            {
                random.NextBytes(bytes);
                bytes[bytes.Length - 1] &= (byte)0x7F; //force sign bit to positive
                R = new BigInteger(bytes);
            } while (R >= max);

            return R;
        }

        public BigInteger GetRandomNumber(int size)
        {
            Random random = new Random();
            BitArray bits;
            byte[] byteArray = new byte[size / 8];
            random.NextBytes(byteArray);

            bits = new BitArray(byteArray);
            bits.Set(0, true);
            bits.Set(size - 2, true);
            bits.Set(size - 1, false);
            bits.CopyTo(byteArray, 0);

            return new BigInteger(byteArray);
        }

        public BigInteger Inverse_Modulo(BigInteger a, BigInteger n)
        {
            BigInteger temp = n, y = 0, r, q, y0 = 0, y1 = 1;

            while (a > 0)
            {
                r = n % a;
                if (r == 0) break;
                q = n / a;
                y = (y0 - y1 * q) % temp;
                y0 = y1; y1 = y;
                n = a; a = r;
            }

            if (a > 1) return -1;
            if (y < 0) y += temp;
            return y;
        }

        public BigInteger Fast_Exponent(BigInteger m, BigInteger e, BigInteger n)
        {
            string binaryString = Extension.BigIntegerExtensions.ToBinaryString(e);
            char[] binaryArray = binaryString.ToCharArray();
            BigInteger res = 1;
            for (int i = 0; i < binaryArray.Length; i++)
            {
                res = (res * res) % n;
                if (binaryArray[i] == '1')
                {
                    res = (res * m) % n;
                }
            }
            return res;
        }

        public bool Miller_Rabin(BigInteger num)
        {
            if (num == 2 || num == 3)
                return true;
            if (num < 2 || num % 2 == 0)
                return false;

            BigInteger tempNum = num - 1;

            int s = 0;
            while (tempNum % 2 == 0)
            {
                tempNum /= 2;
                s++;
            }
            BigInteger d = tempNum;

            BigInteger a;

            for (int i = 0; i < 15; i++)
            {
                do
                {
                    a = RandomInRange(num - 2);
                } while (a <= 0 || a > num - 2);
                BigInteger x = Fast_Exponent(a, d, num);
                if ((x - num) == -1 || x == 1)
                    continue;
                int j;
                for (j = 0; j < s; j++)
                {
                    x = Fast_Exponent(x, 2, num);
                    if (x == 1)
                        return false;
                    if (x - num == -1)
                        break;
                }
                if (j == s)
                    return false;
            }
            return true;
        }

        public bool Extended_Euclid(BigInteger a, BigInteger b)
        {
            bool check;
            // giải thuật Euclid;
            BigInteger temp;
            while (b != 0)
            {
                temp = a % b;
                a = b;
                b = temp;
            }
            if (a == 1)
            {
                check = true;
            }
            else
                check = false;
            return check;
        }
    }
}

namespace Extension
{
    public static class BigIntegerExtensions
    {

        #region
        /// <summary>
        /// Converts a <see cref="BigInteger"/> to a binary string.
        /// </summary>
        /// <param name="bigint">A <see cref="BigInteger"/>.</param>
        /// <returns>
        /// A <see cref="System.String"/> containing a binary
        /// representation of the supplied <see cref="BigInteger"/>.
        /// </returns>
        #endregion
        public static string ToBinaryString(this BigInteger bigint)
        {
            var bytes = bigint.ToByteArray();
            var idx = bytes.Length - 1;

            // Create a StringBuilder having appropriate capacity.
            var base2 = new StringBuilder(bytes.Length * 8);

            // Convert first byte to binary.
            var binary = Convert.ToString(bytes[idx], 2);

            // Ensure leading zero exists if value is positive.
            if (binary[0] != '0' && bigint.Sign == 1)
            {
                base2.Append('0');
            }

            // Append binary string to StringBuilder.
            base2.Append(binary);

            // Convert remaining bytes adding leading zeros.
            for (idx--; idx >= 0; idx--)
            {
                base2.Append(Convert.ToString(bytes[idx], 2).PadLeft(8, '0'));
            }

            return base2.ToString();
        }
    }
}
