using Crypto_Application.Elgamal;
using Crypto_Application.RSA;
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Crypto_Application
{
    public partial class Cryptosystem : Form
    {
        public Cryptosystem()
        {
            InitializeComponent();
        }
        #region
        Elgamal_Keys generator = new Elgamal_Keys();

        ElgamalCrypto encryption;
        BigInteger SK;
        BigInteger p;
        BigInteger PK;
        BigInteger G;
        int size;

        string encryptText;
        string encryptFile;
        bool check_file = false;
       

        private void encrypt_btn_Click(object sender, EventArgs e)
        {
            if (check_file == true)
            {
                try
                {
                    encryptFile = encryption.Encrypt_File(message.Text);
                    enc_message.Text = encryptFile;
                    k_value.Text = encryption.K.ToString();
                }
                catch (Exception exception)
                {
                    MessageBox.Show(exception.Message);
                }
            }
            else
            {
                try
                {
                    encryptText = encryption.Encrypt(message.Text);
                    enc_message.Text = encryptText;
                    k_value.Text = encryption.K.ToString();
                }
                catch (Exception exception)
                {
                    MessageBox.Show(exception.Message);
                }
            }
        }

        private void decrypt_btn_Click(object sender, EventArgs e)
        {
            if (check_file == true)
            {
                try
                {
                    string decrypt_file = encryption.Decrypt_File(message.Text);
                    dec_message.Text = decrypt_file;
                }catch(Exception exception)
                {
                    MessageBox.Show(exception.Message);
                }
            }
            else
            {
                try
                { 
                    string decryptText = encryption.Decrypt();
                    dec_message.Text = decryptText;
                }catch(Exception exception)
                {
                    MessageBox.Show(exception.Message);
                }
                
            }
            check_file = false;
        }

        private void gen_key_Click(object sender, EventArgs e)
        {
            int keysize = Convert.ToInt32(key_size.SelectedItem.ToString());
            SK = generator.Get_Key(keysize);
            p = generator.P;
            PK = generator.PUBLIC_KEY;
            G = generator.G;
            p_value.Text = p.ToString();
            secret_key.Text = SK.ToString();
            public_key.Text = PK.ToString();
            g_value.Text = G.ToString();
            encryption = new ElgamalCrypto(PK, p, G, SK, keysize);
        }

        private void file_inp_Click(object sender, EventArgs e)
        {
            OpenFileDialog get_file = new OpenFileDialog();
            string file_name = "";

            if (get_file.ShowDialog() == DialogResult.OK)
            {
                file_name = get_file.FileName;
            }
            message.Text = file_name;

            check_file = true;
        }

        private void key_file_Click(object sender, EventArgs e)
        {
            OpenFileDialog get_file = new OpenFileDialog();
            string file_name = "";

            if (get_file.ShowDialog() == DialogResult.OK)
            {
                file_name = get_file.FileName;
            }
            string[] keys = new string[4];
            try
            {
                using (StreamReader sr = new StreamReader(file_name))
                {
                    string line;
                    int count = 0;
                    while ((line = sr.ReadLine()) != null)
                    {                        
                        keys[count++] = line;
                    }
                    if (keys[0].Length <= 320)
                    {
                        key_size.Text = 1024.ToString();
                        size = 1024;
                    }
                    else
                    {
                        key_size.Text = 2048.ToString();
                        size = 2048;
                    }
                    p = BigInteger.Parse(keys[0]);
                    SK = BigInteger.Parse(keys[1]);
                    PK = BigInteger.Parse(keys[2]);
                    G = BigInteger.Parse(keys[3]);

                }
                p_value.Text = p.ToString();
                secret_key.Text = SK.ToString();
                public_key.Text = PK.ToString();
                g_value.Text = G.ToString();
                encryption = new ElgamalCrypto(PK, p, G, SK, size);
            }
            catch
            {
                return;
            }

        }

        private void showp_Click(object sender, EventArgs e)
        {
            Result result = new Result(p_value.Text);
            result.Show();
        }

        private void showsk_Click(object sender, EventArgs e)
        {
            Result result = new Result(secret_key.Text);
            result.Show();
        }

        private void showpk_Click(object sender, EventArgs e)
        {
            Result result = new Result(public_key.Text);
            result.Show();
        }

        private void showroot_Click(object sender, EventArgs e)
        {
            Result result = new Result(g_value.Text);
            result.Show();
        }

        private void showk_Click(object sender, EventArgs e)
        {
            Result result = new Result(k_value.Text);
            result.Show();
        }

        private void show_enc_Click(object sender, EventArgs e)
        {
            Result result = new Result(enc_message.Text);
            result.Show();
        }


        private void clear_Click(object sender, EventArgs e)
        {
            message.Text = enc_message.Text = dec_message.Text = k_value.Text = null;
        }

        #endregion

        #region
        RSA_Keys rsa_keys = new RSA_Keys();
        BigInteger P_RSA;
        BigInteger Q_RSA;
        BigInteger N;
        BigInteger PHI_N;
        BigInteger PK_RSA;
        BigInteger SK_RSA;
        int size_rsa;
        bool check_file_rsa = false;
        RSACrypto rsa;
        

        private void gen_key_rsa_Click(object sender, EventArgs e)
        {
            int keysize  = Convert.ToInt32(key_size_rsa.SelectedItem.ToString());
            ArrayList getkeys = rsa_keys.generate_keys(keysize);
            BigInteger[] keys = new BigInteger[6];
            int j = 0;
            foreach (BigInteger i in getkeys)
            {
                keys[j++] = i;
            }
            P_RSA = keys[0];
            Q_RSA = keys[1];
            N = keys[2];
            PHI_N = keys[3];
            PK_RSA = keys[4];
            SK_RSA = keys[5];
            p_rsa.Text = P_RSA.ToString();
            q_rsa.Text = Q_RSA.ToString();
            n_rsa.Text = N.ToString();
            phin_rsa.Text = PHI_N.ToString();
            pk_rsa.Text = PK_RSA.ToString();
            sk_rsa.Text = SK_RSA.ToString();
            rsa = new RSACrypto(PK_RSA, N, PHI_N, SK_RSA, keysize);
        }

        string rsa_enc_message = "";
        string rsa_enc_path = "";

        private void enc_btn_rsa_Click(object sender, EventArgs e)
        {
            if(check_file_rsa == true)
            {
                rsa_enc_path = rsa.Encrypt_File(message_rsa.Text);
                enc_message_rsa.Text = rsa_enc_path; 
            }
            else
            {
                rsa_enc_message = rsa.Encrypt(message_rsa.Text);
                enc_message_rsa.Text = rsa_enc_message;
            }
        }

       

        private void file_rsa_Click(object sender, EventArgs e)
        {
            OpenFileDialog get_file = new OpenFileDialog();
            string file_name = "";

            if (get_file.ShowDialog() == DialogResult.OK)
            {
                file_name = get_file.FileName;
            }
            message_rsa.Text = file_name;

            check_file_rsa = true;
        }

        private void dec_btn_rsa_Click(object sender, EventArgs e)
        {
            if(check_file_rsa == true)
            {
                dec_message_rsa.Text = rsa.Decrypt_File(message_rsa.Text);
            }
            else
            {
                dec_message_rsa.Text = rsa.Decrypt();
            }
            
        }

        private void file_keys_rsa_Click(object sender, EventArgs e)
        {
            OpenFileDialog get_file = new OpenFileDialog();
            string file_name = "";

            if (get_file.ShowDialog() == DialogResult.OK)
            {
                file_name = get_file.FileName;
            }
            string[] keys = new string[6];
            try
            {
                using (StreamReader sr = new StreamReader(file_name))
                {
                    string line;
                    int count = 0;
                    while ((line = sr.ReadLine()) != null)
                    {
                        keys[count++] = line;
                    }
                    if (keys[3].Length <= 320)
                    {
                        key_size_rsa.Text = 1024.ToString();
                        size_rsa = 1024;
                    }
                    else
                    {
                        key_size_rsa.Text = 2048.ToString();
                        size_rsa = 2048;
                    }
                    P_RSA = BigInteger.Parse(keys[0]);
                    Q_RSA = BigInteger.Parse(keys[1]);
                    N = BigInteger.Parse(keys[2]);
                    PHI_N = BigInteger.Parse(keys[3]);
                    PK_RSA = BigInteger.Parse(keys[4]);
                    SK_RSA = BigInteger.Parse(keys[5]);

                }
                p_rsa.Text = P_RSA.ToString();
                q_rsa.Text = Q_RSA.ToString();
                n_rsa.Text = N.ToString();
                phin_rsa.Text = PHI_N.ToString();
                pk_rsa.Text = PK_RSA.ToString();
                sk_rsa.Text = SK_RSA.ToString();
                rsa = new RSACrypto(PK_RSA, N, PHI_N, SK_RSA, size_rsa);
            }
            catch
            {
                return;
            }
        }
        

        private void clear_rsa_Click(object sender, EventArgs e)
        {
            message_rsa.Text = enc_message_rsa.Text = dec_message_rsa.Text = null;
        }


        #endregion

        #region
        
        ElgamalSignature e_signature;
        int key_sign;

        private void e_sign_Click(object sender, EventArgs e)
        {
            e_signature.Sign(file_path_e_sign.Text);
            k_e_sign.Text = e_signature.K.ToString();
            MessageBox.Show("Done. Your signature is stored in " + e_signature.sign_path);
        }

        private void e_verify_Click(object sender, EventArgs e)
        {
            if (e_signature.Verify(file_path_e_sign.Text, e_sign_path.Text))
            {
                MessageBox.Show("Successful");
                e_check_sign.Text = "Successful";
            }
            else
            {
                MessageBox.Show("Wrong signature");
                e_check_sign.Text = "Wrong signature";
            }
        }

        private void file_key_e_sign_Click(object sender, EventArgs e)
        {
            OpenFileDialog get_file = new OpenFileDialog();
            string file_name = "";

            if (get_file.ShowDialog() == DialogResult.OK)
            {
                file_name = get_file.FileName;
            }
            string[] keys = new string[4];
            try
            {
                using (StreamReader sr = new StreamReader(file_name))
                {
                    string line;
                    int count = 0;
                    while ((line = sr.ReadLine()) != null)
                    {
                        keys[count++] = line;
                    }
                    if (keys[0].Length <= 320)
                    {
                        key_size_e_sign.Text = 1024.ToString();
                        key_sign = 1024;
                    }
                    else
                    {
                        key_size_e_sign.Text = 2048.ToString();
                        key_sign = 2048;
                    }
                    p = BigInteger.Parse(keys[0]);
                    SK = BigInteger.Parse(keys[1]);
                    PK = BigInteger.Parse(keys[2]);
                    G = BigInteger.Parse(keys[3]);

                }
                p_e_sign.Text = p.ToString();
                sk_e_sign.Text = SK.ToString();
                pk_e_sign.Text = PK.ToString();
                g_e_sign.Text = G.ToString();
                e_signature = new ElgamalSignature(PK, p, G, SK, key_sign);
            }
            catch
            {
                return;
            }
        }

        private void gen_key_e_sign_Click(object sender, EventArgs e)
        {
            int keysize = Convert.ToInt32(key_size_e_sign.SelectedItem.ToString());
            SK = generator.Get_Key(keysize);
            p = generator.P;
            PK = generator.PUBLIC_KEY;
            G = generator.G;
            p_e_sign.Text = p.ToString();
            sk_e_sign.Text = SK.ToString();
            pk_e_sign.Text = PK.ToString();
            g_e_sign.Text = G.ToString();
            e_signature = new ElgamalSignature(PK, p, G, SK, key_sign);
        }

        private void metroButton8_Click(object sender, EventArgs e)
        {
            Result result = new Result(p_e_sign.Text);
            result.Show();
        }

        private void metroButton9_Click(object sender, EventArgs e)
        {
            Result result = new Result(p_e_sign.Text);
            result.Show();
        }

        private void metroButton10_Click(object sender, EventArgs e)
        {
            Result result = new Result(sk_e_sign.Text);
            result.Show();
        }

        private void metroButton11_Click(object sender, EventArgs e)
        {
            Result result = new Result(pk_e_sign.Text);
            result.Show();
        }

        private void metroButton7_Click(object sender, EventArgs e)
        {
            Result result = new Result(g_e_sign.Text);
            result.Show();
        }

        private void e_file_Click(object sender, EventArgs e)
        {
            OpenFileDialog get_file = new OpenFileDialog();
            string file_name = "";

            if (get_file.ShowDialog() == DialogResult.OK)
            {
                file_name = get_file.FileName;
            }
            file_path_e_sign.Text = file_name;
        }

        private void e_path_Click(object sender, EventArgs e)
        {
            OpenFileDialog get_file = new OpenFileDialog();
            string file_name = "";

            if (get_file.ShowDialog() == DialogResult.OK)
            {
                file_name = get_file.FileName;
            }
            e_sign_path.Text = file_name;
        }

        private void e_clear_sign_Click(object sender, EventArgs e)
        {
            e_sign_path.Text = k_e_sign.Text = file_path_e_sign.Text = e_check_sign.Text = null;
        }

        #endregion

        #region

        RSASignature rsa_signature;
        int size_rsa_sign;

        private void file_key_rsa_sign_Click(object sender, EventArgs e)
        {
            OpenFileDialog get_file = new OpenFileDialog();
            string file_name = "";

            if (get_file.ShowDialog() == DialogResult.OK)
            {
                file_name = get_file.FileName;
            }
            string[] keys = new string[6];
            try
            {
                using (StreamReader sr = new StreamReader(file_name))
                {
                    string line;
                    int count = 0;
                    while ((line = sr.ReadLine()) != null)
                    {
                        keys[count++] = line;
                    }
                    if (keys[3].Length <= 320)
                    {
                        key_size_rsa_sign.Text = 1024.ToString();
                        size_rsa_sign = 1024;
                    }
                    else
                    {
                        key_size_rsa_sign.Text = 2048.ToString();
                        size_rsa_sign = 2048;
                    }
                    P_RSA = BigInteger.Parse(keys[0]);
                    Q_RSA = BigInteger.Parse(keys[1]);
                    N = BigInteger.Parse(keys[2]);
                    PHI_N = BigInteger.Parse(keys[3]);
                    PK_RSA = BigInteger.Parse(keys[4]);
                    SK_RSA = BigInteger.Parse(keys[5]);

                }
                p_rsa_sign.Text = P_RSA.ToString();
                q_rsa_sign.Text = Q_RSA.ToString();
                n_rsa_sign.Text = N.ToString();
                phin_rsa_sign.Text = PHI_N.ToString();
                pk_rsa_sign.Text = PK_RSA.ToString();
                sk_rsa_sign.Text = SK_RSA.ToString();
                rsa_signature = new RSASignature(PK_RSA, N, PHI_N, SK_RSA, size_rsa_sign);
            }
            catch
            {
                return;
            }
        }

        private void gen_key_rsa_sign_Click(object sender, EventArgs e)
        {
            int keysize = Convert.ToInt32(key_size_rsa_sign.SelectedItem.ToString());
            ArrayList getkeys = rsa_keys.generate_keys(keysize);
            BigInteger[] keys = new BigInteger[6];
            int j = 0;
            foreach (BigInteger i in getkeys)
            {
                keys[j++] = i;
            }
            P_RSA = keys[0];
            Q_RSA = keys[1];
            N = keys[2];
            PHI_N = keys[3];
            PK_RSA = keys[4];
            SK_RSA = keys[5];
            p_rsa_sign.Text = P_RSA.ToString();
            q_rsa_sign.Text = Q_RSA.ToString();
            n_rsa_sign.Text = N.ToString();
            phin_rsa_sign.Text = PHI_N.ToString();
            pk_rsa_sign.Text = PK_RSA.ToString();
            sk_rsa_sign.Text = SK_RSA.ToString();
            rsa_signature = new RSASignature(PK_RSA, N, PHI_N, SK_RSA, size_rsa_sign);
        }

        private void sign_btn_rsa_Click(object sender, EventArgs e)
        {
            rsa_signature.Sign(message_rsa_sign.Text);
            MessageBox.Show("Done.Your signature is stored in " + rsa_signature.sign_path);
        }

        private void file_rsa_sign_Click(object sender, EventArgs e)
        {
            OpenFileDialog get_file = new OpenFileDialog();
            string file_name = "";

            if (get_file.ShowDialog() == DialogResult.OK)
            {
                file_name = get_file.FileName;
            }
            message_rsa_sign.Text = file_name;

        }

        private void signature_rsa_Click(object sender, EventArgs e)
        {
            OpenFileDialog get_file = new OpenFileDialog();
            string file_name = "";

            if (get_file.ShowDialog() == DialogResult.OK)
            {
                file_name = get_file.FileName;
            }
            sign_rsa_path.Text = file_name;
        }

        private void clear_rsa_sign_Click(object sender, EventArgs e)
        {
            status_sign_rsa.Text = sign_rsa_path.Text = message_rsa_sign.Text = null;
        }

        private void verify_btn_rsa_Click(object sender, EventArgs e)
        {
            if (rsa_signature.Verify(message_rsa_sign.Text, sign_rsa_path.Text))
            {
                MessageBox.Show("Successful!");
                status_sign_rsa.Text = "Successful!";
            }
            else
            {
                MessageBox.Show("Wrong signature");
                status_sign_rsa.Text = "Wrong signature";
            }
        }

        #endregion
    }
}
