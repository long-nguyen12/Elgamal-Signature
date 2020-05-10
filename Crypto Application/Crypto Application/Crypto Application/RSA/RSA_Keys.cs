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

namespace Crypto_Application.RSA
{
    class RSA_Keys
    {
        MathUtil math = new MathUtil();
        private BigInteger P;
        private BigInteger Q;
        public BigInteger N;
        private BigInteger PhiN;
        public BigInteger PK;
        private BigInteger SK;

        public ArrayList generate_keys(int size)
        {
            int get_size = size / 2;
            ArrayList keys = new ArrayList();
            do
            {
                P = math.GetRandomNumber(get_size);
            } while (math.Miller_Rabin(P) == false);
            do
            {
                Q = math.GetRandomNumber(get_size);
            } while (math.Miller_Rabin(Q) == false);
            keys.Add(P);
            keys.Add(Q);
            N = P * Q;
            keys.Add(N);
            PhiN = (P - 1) * (Q - 1);
            keys.Add(PhiN);
            do
            {
                PK = math.RandomInRange(PhiN);
            } while (math.Extended_Euclid(PK, PhiN) == false);
            keys.Add(PK);
            SK = math.Inverse_Modulo(PK, PhiN);
            keys.Add(SK);

            using (StreamWriter sw = new StreamWriter("D:\\RSA\\" + size + ".txt"))
            {

                foreach (BigInteger s in keys)
                {
                    sw.WriteLine(s.ToString());
                }
            }

            return keys;
        } 
    }
}
