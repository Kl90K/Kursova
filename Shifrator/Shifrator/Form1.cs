using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

namespace EncryptionApp
{
    public partial class MainForm : Form
    {
        private byte[] aesKey;
        private byte[] desKey;
        private byte[] tdesKey;

        public MainForm()
        {
            InitializeComponent();
        }

        private void btnRSA_Click(object sender, EventArgs e)
        {
            RSAEncryption();
        }

        private void btnRSADec_Click(object sender, EventArgs e)
        {
            RSADecipher();
        }

        private void btnVernam_Click(object sender, EventArgs e)
        {
            VernamCipher();
        }

        private void btnVernamDec_Click(object sender, EventArgs e)
        {
            VernamDecipher();
        }

        private void btnAES_Click(object sender, EventArgs e)
        {
            AESEncryption();
        }

        private void btnAESDec_Click(object sender, EventArgs e)
        {
            AESDecipher();
        }

        private void btnDES_Click(object sender, EventArgs e)
        {
            DESEncryption();
        }

        private void btnDESDec_Click(object sender, EventArgs e)
        {
            DESDecipher();
        }

        private void btnTripleDES_Click(object sender, EventArgs e)
        {
            TripleDESEncryption();
        }

        private void btnTripleDESDec_Click(object sender, EventArgs e)
        {
            TripleDESDecipher();
        }

        private void btnCaesar_Click(object sender, EventArgs e)
        {
            CaesarCipher();
        }

        private void btnCaesarDec_Click(object sender, EventArgs e)
        {
            CaesarDecipher();
        }

        private void btnXOR_Click(object sender, EventArgs e)
        {
            XORCipher();
        }

        private void btnXORDec_Click(object sender, EventArgs e)
        {
            XORDecipher();
        }

        private void RSAEncryption()
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.KeySize = 2048;
                string publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
                string privateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());

                string message = txtMessage.Text;
                byte[] encryptedMessage = rsa.Encrypt(Encoding.UTF8.GetBytes(message), RSAEncryptionPadding.OaepSHA256);
                string encryptedMessageBase64 = Convert.ToBase64String(encryptedMessage);

                File.WriteAllText("encrypted_message.txt", encryptedMessageBase64);
                txtEncryptedMessage.Text = encryptedMessageBase64; // Display encrypted message
                MessageBox.Show($"Encrypted message: {encryptedMessageBase64}\n\nSaved to 'encrypted_message.txt'.");
            }
        }

        private void RSADecipher()
        {
            string privateKeyBase64 = ""; // Insert your private key in Base64 format here
            byte[] privateKeyBytes = Convert.FromBase64String(privateKeyBase64);

            using (RSA rsa = RSA.Create())
            {
                rsa.ImportRSAPrivateKey(privateKeyBytes, out _);

                string encryptedMessageBase64 = txtEncryptedMessage.Text;
                byte[] encryptedMessage = Convert.FromBase64String(encryptedMessageBase64);

                byte[] decryptedMessage = rsa.Decrypt(encryptedMessage, RSAEncryptionPadding.OaepSHA256);
                string decryptedMessageString = Encoding.UTF8.GetString(decryptedMessage);

                txtDecryptedMessage.Text = decryptedMessageString; // Display decrypted message
                MessageBox.Show($"Decrypted message: {decryptedMessageString}");
            }
        }

        private void VernamCipher()
        {
            string message = txtMessage.Text;
            string key = txtKey.Text;

            if (key.Length != message.Length)
            {
                MessageBox.Show("Key length must be the same as message length.");
                return;
            }

            string encryptedMessage = EncryptVernam(message, key);
            File.WriteAllText("vernam_encrypted_message.txt", encryptedMessage);
            txtEncryptedMessage.Text = encryptedMessage; // Display encrypted message
            MessageBox.Show($"Encrypted message: {encryptedMessage}\n\nSaved to 'vernam_encrypted_message.txt'.");
        }

        private void VernamDecipher()
        {
            string encryptedMessage = txtEncryptedMessage.Text;
            string key = txtKey.Text;

            if (key.Length != encryptedMessage.Length)
            {
                MessageBox.Show("Key length must be the same as encrypted message length.");
                return;
            }

            string decryptedMessage = EncryptVernam(encryptedMessage, key);
            txtDecryptedMessage.Text = decryptedMessage; // Display decrypted message
            MessageBox.Show($"Decrypted message: {decryptedMessage}");
        }

        private string EncryptVernam(string message, string key)
        {
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < message.Length; i++)
            {
                char encryptedChar = (char)(message[i] ^ key[i]);
                result.Append(encryptedChar);
            }
            return result.ToString();
        }

        private void AESEncryption()
        {
            string message = txtMessage.Text;
            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.GenerateIV();
                aesKey = aes.Key; // Store the key for decryption
                byte[] encryptedMessage;

                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                using (var ms = new MemoryStream())
                {
                    ms.Write(aes.IV, 0, aes.IV.Length);
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    using (var sw = new StreamWriter(cs))
                    {
                        sw.Write(message);
                    }
                    encryptedMessage = ms.ToArray();
                }

                string encryptedMessageBase64 = Convert.ToBase64String(encryptedMessage);
                File.WriteAllText("aes_encrypted_message.txt", encryptedMessageBase64);
                txtEncryptedMessage.Text = encryptedMessageBase64; // Display encrypted message
                MessageBox.Show($"Encrypted message: {encryptedMessageBase64}\n\nSaved to 'aes_encrypted_message.txt'.");
            }
        }

        private void AESDecipher()
        {
            string encryptedMessageBase64 = txtEncryptedMessage.Text;
            byte[] fullCipher = Convert.FromBase64String(encryptedMessageBase64);

            using (Aes aes = Aes.Create())
            {
                aes.Key = aesKey; // Use the stored key
                byte[] iv = new byte[aes.BlockSize / 8];
                Array.Copy(fullCipher, 0, iv, 0, iv.Length);

                aes.IV = iv;
                byte[] cipher = new byte[fullCipher.Length - iv.Length];
                Array.Copy(fullCipher, iv.Length, cipher, 0, cipher.Length);

                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                using (var ms = new MemoryStream(cipher))
                {
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    using (var sr = new StreamReader(cs))
                    {
                        string decryptedMessage = sr.ReadToEnd();
                        txtDecryptedMessage.Text = decryptedMessage; // Display decrypted message
                        MessageBox.Show($"Decrypted message: {decryptedMessage}");
                    }
                }
            }
        }

        private void DESEncryption()
        {
            string message = txtMessage.Text;
            using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
            {
                des.GenerateIV();
                desKey = des.Key; // Store the key for decryption
                byte[] encryptedMessage;

                using (var encryptor = des.CreateEncryptor(des.Key, des.IV))
                using (var ms = new MemoryStream())
                {
                    ms.Write(des.IV, 0, des.IV.Length);
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    using (var sw = new StreamWriter(cs))
                    {
                        sw.Write(message);
                    }
                    encryptedMessage = ms.ToArray();
                }

                string encryptedMessageBase64 = Convert.ToBase64String(encryptedMessage);
                File.WriteAllText("des_encrypted_message.txt", encryptedMessageBase64);
                txtEncryptedMessage.Text = encryptedMessageBase64; // Display encrypted message
                MessageBox.Show($"Encrypted message: {encryptedMessageBase64}\n\nSaved to 'des_encrypted_message.txt'.");
            }
        }

        private void DESDecipher()
        {
            string encryptedMessageBase64 = txtEncryptedMessage.Text;
            byte[] fullCipher = Convert.FromBase64String(encryptedMessageBase64);

            using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
            {
                des.Key = desKey; // Use the stored key
                byte[] iv = new byte[des.BlockSize / 8];
                Array.Copy(fullCipher, 0, iv, 0, iv.Length);

                des.IV = iv;
                byte[] cipher = new byte[fullCipher.Length - iv.Length];
                Array.Copy(fullCipher, iv.Length, cipher, 0, cipher.Length);

                using (var decryptor = des.CreateDecryptor(des.Key, des.IV))
                using (var ms = new MemoryStream(cipher))
                {
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    using (var sr = new StreamReader(cs))
                    {
                        string decryptedMessage = sr.ReadToEnd();
                        txtDecryptedMessage.Text = decryptedMessage; // Display decrypted message
                        MessageBox.Show($"Decrypted message: {decryptedMessage}");
                    }
                }
            }
        }

        private void TripleDESEncryption()
        {
            string message = txtMessage.Text;
            using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
            {
                tdes.GenerateIV();
                tdesKey = tdes.Key; // Store the key for decryption
                byte[] encryptedMessage;

                using (var encryptor = tdes.CreateEncryptor(tdes.Key, tdes.IV))
                using (var ms = new MemoryStream())
                {
                    ms.Write(tdes.IV, 0, tdes.IV.Length);
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    using (var sw = new StreamWriter(cs))
                    {
                        sw.Write(message);
                    }
                    encryptedMessage = ms.ToArray();
                }

                string encryptedMessageBase64 = Convert.ToBase64String(encryptedMessage);
                File.WriteAllText("triple_des_encrypted_message.txt", encryptedMessageBase64);
                txtEncryptedMessage.Text = encryptedMessageBase64; // Display encrypted message
                MessageBox.Show($"Encrypted message: {encryptedMessageBase64}\n\nSaved to 'triple_des_encrypted_message.txt'.");
            }
        }

        private void TripleDESDecipher()
        {
            string encryptedMessageBase64 = txtEncryptedMessage.Text;
            byte[] fullCipher = Convert.FromBase64String(encryptedMessageBase64);

            using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
            {
                tdes.Key = tdesKey; // Use the stored key
                byte[] iv = new byte[tdes.BlockSize / 8];
                Array.Copy(fullCipher, 0, iv, 0, iv.Length);

                tdes.IV = iv;
                byte[] cipher = new byte[fullCipher.Length - iv.Length];
                Array.Copy(fullCipher, iv.Length, cipher, 0, cipher.Length);

                using (var decryptor = tdes.CreateDecryptor(tdes.Key, tdes.IV))
                using (var ms = new MemoryStream(cipher))
                {
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    using (var sr = new StreamReader(cs))
                    {
                        string decryptedMessage = sr.ReadToEnd();
                        txtDecryptedMessage.Text = decryptedMessage; // Display decrypted message
                        MessageBox.Show($"Decrypted message: {decryptedMessage}");
                    }
                }
            }
        }

        private void CaesarCipher()
        {
            string message = txtMessage.Text;
            int shift = 3; // Example shift value
            string encryptedMessage = EncryptCaesar(message, shift);
            File.WriteAllText("caesar_encrypted_message.txt", encryptedMessage);
            txtEncryptedMessage.Text = encryptedMessage; // Display encrypted message
            MessageBox.Show($"Encrypted message: {encryptedMessage}\n\nSaved to 'caesar_encrypted_message.txt'.");
        }

        private void CaesarDecipher()
        {
            string encryptedMessage = txtEncryptedMessage.Text;
            int shift = 3; // The same shift used for encryption
            string decryptedMessage = EncryptCaesar(encryptedMessage, -shift);
            txtDecryptedMessage.Text = decryptedMessage; // Display decrypted message
            MessageBox.Show($"Decrypted message: {decryptedMessage}");
        }

        private string EncryptCaesar(string message, int shift)
        {
            StringBuilder result = new StringBuilder();
            foreach (char c in message)
            {
                char encryptedChar = (char)(c + shift);
                result.Append(encryptedChar);
            }
            return result.ToString();
        }

        private void XORCipher()
        {
            string message = txtMessage.Text;
            string key = txtKey.Text;
            string encryptedMessage = EncryptXOR(message, key);
            File.WriteAllText("xor_encrypted_message.txt", encryptedMessage);
            txtEncryptedMessage.Text = encryptedMessage; // Display encrypted message
            MessageBox.Show($"Encrypted message: {encryptedMessage}\n\nSaved to 'xor_encrypted_message.txt'.");
        }

        private void XORDecipher()
        {
            string encryptedMessage = txtEncryptedMessage.Text;
            string key = txtKey.Text;
            string decryptedMessage = EncryptXOR(encryptedMessage, key);
            txtDecryptedMessage.Text = decryptedMessage; // Display decrypted message
            MessageBox.Show($"De crypted message: {decryptedMessage}");
        }

        private string EncryptXOR(string message, string key)
        {
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < message.Length; i++)
            {
                char encryptedChar = (char)(message[i] ^ key[i % key.Length]);
                result.Append(encryptedChar);
            }
            return result.ToString();
        }
    }
}