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
    class Elgamal_Keys
    {
        public BigInteger PUBLIC_KEY;
        private BigInteger SECRET_KEY;

        public BigInteger P, Q, G;

        MathUtil math = new MathUtil();

        public BigInteger Get_Key(int size)
        {
            ArrayList keys_list = new ArrayList(); 

            BigInteger[] keys = new BigInteger[4];
            do
            {
                P = math.GetRandomNumber(size);
                Q = (P - 1) / 2;
            } while (math.Miller_Rabin(P) == false || math.Miller_Rabin(Q) == false);
            keys_list.Add(P);
            do
            {
                G = math.GetRandomNumber(size);
            } while (math.Fast_Exponent(G, 2, P) == 1 && math.Fast_Exponent(G, Q, P) == 1 || G < 1 || G > P - 2);
            
            SECRET_KEY = math.RandomInRange(P - 2);
            keys_list.Add(SECRET_KEY);
            PUBLIC_KEY = math.Fast_Exponent(G, SECRET_KEY, P);
            keys_list.Add(PUBLIC_KEY);
            keys_list.Add(G);

            using (StreamWriter sw = new StreamWriter("D:\\Elgamal\\" + size + ".txt"))
            {

                foreach (BigInteger s in keys_list)
                {
                    sw.WriteLine(s.ToString());
                }
            }

            return SECRET_KEY;
        }

    }
}
