﻿namespace Crypto_Application
{
    partial class Result
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.result_show = new System.Windows.Forms.TextBox();
            this.SuspendLayout();
            // 
            // result_show
            // 
            this.result_show.Location = new System.Drawing.Point(12, 12);
            this.result_show.Multiline = true;
            this.result_show.Name = "result_show";
            this.result_show.Size = new System.Drawing.Size(524, 284);
            this.result_show.TabIndex = 0;
            // 
            // Result
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(548, 306);
            this.Controls.Add(this.result_show);
            this.Name = "Result";
            this.Text = "Result";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.TextBox result_show;
    }
}