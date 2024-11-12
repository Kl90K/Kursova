using System;

namespace EncryptionApp
{
    partial class MainForm
    {
        private System.ComponentModel.IContainer components = null;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            btnRSA = new Button();
            btnRSADec = new Button();
            btnVernam = new Button();
            btnVernamDec = new Button();
            btnAES = new Button();
            btnAESDec = new Button();
            btnDES = new Button();
            btnDESDec = new Button();
            btnTripleDES = new Button();
            btnTripleDESDec = new Button();
            btnCaesar = new Button();
            btnCaesarDec = new Button();
            btnXOR = new Button();
            btnXORDec = new Button(); // Зроблено правильне оголошення кнопки
            txtMessage = new TextBox();
            txtKey = new TextBox();
            txtEncryptedMessage = new TextBox(); // Додано новий TextBox
            txtDecryptedMessage = new TextBox(); // Додано новий TextBox для розшифрованого повідомлення
            SuspendLayout();
            // 
            // btnRSA
            // 
            btnRSA.Location = new Point(12, 12);
            btnRSA.Name = "btnRSA";
            btnRSA.Size = new Size(75, 23);
            btnRSA.TabIndex = 0;
            btnRSA.Text = "RSA";
            btnRSA.UseVisualStyleBackColor = true;
            btnRSA.Click += btnRSA_Click;
            // 
            // btnRSADec
            // 
            btnRSADec.Location = new Point(93, 12);
            btnRSADec.Name = "btnRSADec";
            btnRSADec.Size = new Size(75, 23);
            btnRSADec.TabIndex = 1;
            btnRSADec.Text = "RSA Dec";
            btnRSADec.UseVisualStyleBackColor = true;
            btnRSADec.Click += btnRSADec_Click;
            // 
            // btnVernam
            // 
            btnVernam.Location = new Point(12, 41);
            btnVernam.Name = "btnVernam";
            btnVernam.Size = new Size(75, 23);
            btnVernam.TabIndex = 2;
            btnVernam.Text = "Vernam";
            btnVernam.UseVisualStyleBackColor = true;
            btnVernam.Click += btnVernam_Click;
            // 
            // btnVernamDec
            // 
            btnVernamDec.Location = new Point(93, 41);
            btnVernamDec.Name = "btnVernamDec";
            btnVernamDec.Size = new Size(75, 23);
            btnVernamDec.TabIndex = 3;
            btnVernamDec.Text = "Vernam Dec";
            btnVernamDec.UseVisualStyleBackColor = true;
            btnVernamDec.Click += btnVernamDec_Click;
            // 
            // btnAES
            // 
            btnAES.Location = new Point(12, 70);
            btnAES.Name = "btnAES";
            btnAES.Size = new Size(75, 23);
            btnAES.TabIndex = 4;
            btnAES.Text = "AES";
            btnAES.UseVisualStyleBackColor = true;
            btnAES.Click += btnAES_Click;
            // 
            // btnAESDec
            // 
            btnAESDec.Location = new Point(93, 70);
            btnAESDec.Name = "btnAESDec";
            btnAESDec.Size = new Size(75, 23);
            btnAESDec.TabIndex = 5;
            btnAESDec.Text = "AES Dec";
            btnAESDec.UseVisualStyleBackColor = true;
            btnAESDec.Click += btnAESDec_Click;
            // 
            // btnDES
            // 
            btnDES.Location = new Point(12, 99);
            btnDES.Name = "btnDES";
            btnDES.Size = new Size(75, 23);
            btnDES.TabIndex = 6;
            btnDES.Text = "DES";
            btnDES.UseVisualStyleBackColor = true;
            btnDES.Click += btnDES_Click;
            // 
            // btnDESDec
            // 
            btnDESDec.Location = new Point(93, 99);
            btnDESDec.Name = "btnDESDec";
            btnDESDec.Size = new Size(75, 23);
            btnDESDec.TabIndex = 7;
            btnDESDec.Text = "DES Dec";
            btnDESDec.UseVisualStyleBackColor = true;
            btnDESDec.Click += btnDESDec_Click;
            // 
            // btnTripleDES
            // 
            btnTripleDES.Location = new Point(12, 128);
            btnTripleDES.Name = "btnTripleDES";
            btnTripleDES.Size = new Size(75, 23);
            btnTripleDES.TabIndex = 8;
            btnTripleDES.Text = "Triple DES";
            btnTripleDES.UseVisualStyleBackColor = true;
            btnTripleDES.Click += btnTripleDES_Click;
            // 
            // btnTripleDESDec
            // 
            btnTripleDESDec.Location = new Point(93, 128);
            btnTripleDESDec.Name = "btnTripleDESDec";
            btnTripleDESDec.Size = new Size(75, 23);
            btnTripleDESDec.TabIndex = 9;
            btnTripleDESDec.Text = "Triple DES Dec";
            btnTripleDESDec.UseVisualStyleBackColor = true;
            btnTripleDESDec.Click += btnTripleDESDec_Click;
            // 
            // btnCaesar
            // 
            btnCaesar.Location = new Point(12, 157);
            btnCaesar.Name = "btnCaesar";
            btnCaesar.Size = new Size(75, 23);
            btnCaesar.TabIndex = 10;
            btnCaesar.Text = "Caesar";
            btnCaesar.UseVisualStyleBackColor = true;
            btnCaesar.Click += btnCaesar_Click;
            // 
            // btnCaesarDec
            // 
            btnCaesarDec.Location = new Point(93, 157);
            btnCaesarDec.Name = "btnCaesarDec";
            btnCaesarDec.Size = new Size(75, 23);
            btnCaesarDec.TabIndex = 11;
            btnCaesarDec.Text = "Caesar Dec";
            btnCaesarDec.UseVisualStyleBackColor = true;
            btnCaesarDec.Click += btnCaesarDec_Click;
            // 
            // btnXOR
            // 
            btnXOR.Location = new Point(12, 186);
            btnXOR.Name = "btnXOR";
            btnXOR.Size = new Size(75, 23);
            btnXOR.TabIndex = 12;
            btnXOR.Text = "XOR";
            btnXOR.UseVisualStyleBackColor = true;
            btnXOR.Click += btnXOR_Click;
            // 
            // btnXORDec
            // 
            btnXORDec.Location = new Point(93, 186);
            btnXORDec.Name = "btnXORDec";
            btnXORDec.Size = new Size(75, 23);
            btnXORDec.TabIndex = 13;
            btnXORDec.Text = "XOR Dec";
            btnXORDec.UseVisualStyleBackColor = true;
            btnXORDec.Click += btnXORDec_Click;
            // 
            // txtMessage
            // 
            txtMessage.Location = new Point(200, 12);
            txtMessage.Multiline = true;
            txtMessage.Name = "txtMessage";
            txtMessage.Size = new Size(200, 100);
            txtMessage.TabIndex = 14;
            txtMessage.Text = "Enter your message here...";
            // 
            // txtKey
            // 
            txtKey.Location = new Point(200, 120);
            txtKey.Name = "txtKey";
            txtKey.Size = new Size(200, 27);
            txtKey.TabIndex = 15;
            txtKey.Text = "Enter key here...";
            // 
            // txtEncryptedMessage
            // 
            txtEncryptedMessage.Location = new Point(200, 150);
            txtEncryptedMessage.Multiline = true;
            txtEncryptedMessage.Name = "txtEncryptedMessage";
            txtEncryptedMessage.ReadOnly = true; // Дозволяє копіювати текст, але не редагувати
            txtEncryptedMessage.Size = new Size(200, 100);
            txtEncryptedMessage.TabIndex = 16;
            txtEncryptedMessage.Text = "Зашифроване повідомлення з'явиться тут...";
            // 
            // txtDecryptedMessage
            // 
            txtDecryptedMessage.Location = new Point(200, 260);
            txtDecryptedMessage.Multiline = true;
            txtDecryptedMessage.Name = "txtDecryptedMessage";
            txtDecryptedMessage.ReadOnly = true; // Дозволяє копіювати текст, але не редагувати
            txtDecryptedMessage.Size = new Size(200, 100);
            txtDecryptedMessage.TabIndex = 17;
            txtDecryptedMessage.Text = "Розшифроване повідомлення з'явиться тут...";
            // 
            // MainForm
            // 
            ClientSize = new Size(420, 370);
            Controls.Add(txtDecryptedMessage); // Додано до контролів
            Controls.Add(txtEncryptedMessage); // Додано до контролів
            Controls.Add(txtKey);
            Controls.Add(txtMessage);
            Controls.Add(btnXORDec);
            Controls.Add(btnXOR);
            Controls.Add(btnCaesarDec);
            Controls.Add(btnCaesar);
            Controls.Add(btnTripleDESDec);
            Controls.Add(btnTripleDES);
            Controls.Add(btnDESDec);
            Controls.Add(btnDES);
            Controls.Add(btnAESDec);
            Controls.Add(btnAES);
            Controls.Add(btnVernamDec);
            Controls.Add(btnVernam);
            Controls.Add(btnRSADec);
            Controls.Add(btnRSA);
            Name = "MainForm";
            Text = "Encryption App";
            ResumeLayout(false);
            PerformLayout();
        }

        private System.Windows.Forms.Button btnRSA;
        private System.Windows.Forms.Button btnRSADec;
        private System.Windows.Forms.Button btnVernam;
        private System.Windows.Forms.Button btnVernamDec;
        private System.Windows.Forms.Button btnAES;
        private System.Windows.Forms.Button btnAESDec;
        private System.Windows.Forms.Button btnDES;
        private System.Windows.Forms.Button btnDESDec;
        private System.Windows.Forms.Button btnTripleDES;
        private System.Windows.Forms.Button btnTripleDESDec;
        private System.Windows.Forms.Button btnCaesar;
        private System.Windows.Forms.Button btnCaesarDec;
        private System.Windows.Forms.Button btnXOR;
        private System.Windows.Forms.Button btnXORDec; // Переконайтеся, що кнопка оголошена
        private System.Windows.Forms.TextBox txtMessage;
        private System.Windows.Forms.TextBox txtKey;
        private System.Windows.Forms.TextBox txtEncryptedMessage; // Додано новий TextBox
        private System.Windows.Forms.TextBox txtDecryptedMessage; // Додано новий TextBox для розшифрованого повідомлення
    }
}