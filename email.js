// utils/email.js - Email Service
const nodemailer = require('nodemailer');

// Create transporter
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: false, // true for 465, false for other ports
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASSWORD
  }
});

// Verify connection
transporter.verify((error, success) => {
  if (error) {
    console.error('❌ Email service error:', error);
  } else {
    console.log('✅ Email service ready');
  }
});

/**
 * Send verification email to new user
 */
const sendVerificationEmail = async (email, verificationLink) => {
  try {
    const mailOptions = {
      from: `"CuToDo 💕" <${process.env.SMTP_USER}>`,
      to: email,
      subject: 'Verify Your CuToDo Account ✨',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body {
              font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
              background: linear-gradient(135deg, #FFE5EC 0%, #FFF0F5 100%);
              padding: 20px;
              margin: 0;
            }
            .container {
              max-width: 600px;
              margin: 0 auto;
              background: white;
              border-radius: 20px;
              padding: 40px;
              box-shadow: 0 10px 40px rgba(246, 165, 192, 0.2);
            }
            .header {
              text-align: center;
              margin-bottom: 30px;
            }
            .header h1 {
              color: #F6A5C0;
              font-size: 32px;
              margin: 0;
            }
            .content {
              color: #333;
              line-height: 1.6;
              font-size: 16px;
            }
            .button {
              display: inline-block;
              background: linear-gradient(135deg, #F6A5C0 0%, #CDB4FF 100%);
              color: white;
              text-decoration: none;
              padding: 15px 40px;
              border-radius: 25px;
              font-weight: 600;
              margin: 20px 0;
              text-align: center;
            }
            .button:hover {
              transform: scale(1.05);
            }
            .footer {
              text-align: center;
              color: #999;
              font-size: 12px;
              margin-top: 30px;
              padding-top: 20px;
              border-top: 1px solid #eee;
            }
            .emoji {
              font-size: 40px;
              margin: 20px 0;
              text-align: center;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>✨ Welcome to CuToDo! ✨</h1>
            </div>
            
            <div class="emoji">💕</div>
            
            <div class="content">
              <p>Hi there!</p>
              
              <p>Thanks for signing up for CuToDo — where productivity meets cute! 🌸</p>
              
              <p>To get started organizing your tasks, please verify your email address by clicking the button below:</p>
              
              <div style="text-align: center;">
                <a href="${verificationLink}" class="button">
                  Verify My Email ✓
                </a>
              </div>
              
              <p style="font-size: 14px; color: #666;">
                This link expires in 24 hours. If you didn't create a CuToDo account, you can safely ignore this email.
              </p>
              
              <p>Ready to make productivity cute? Let's go! 💖</p>
              
              <p style="margin-top: 30px;">
                Love,<br>
                <strong>The CuToDo Team</strong>
              </p>
            </div>
            
            <div class="footer">
              <p>CuToDo - Productivity, but make it cute 💕</p>
              <p style="font-size: 11px; color: #bbb;">
                If the button doesn't work, copy and paste this link:<br>
                ${verificationLink}
              </p>
            </div>
          </div>
        </body>
        </html>
      `,
      text: `
Welcome to CuToDo! 💕

Please verify your email address by clicking this link:
${verificationLink}

This link expires in 24 hours.

If you didn't create this account, you can ignore this email.

Love,
The CuToDo Team ✨
      `
    };

    const info = await transporter.sendMail(mailOptions);
    console.log('✅ Verification email sent:', info.messageId);
    return true;

  } catch (error) {
    console.error('❌ Failed to send verification email:', error);
    throw error;
  }
};

/**
 * Send password reset email
 */
const sendPasswordResetEmail = async (email, resetLink) => {
  try {
    const mailOptions = {
      from: `"CuToDo 💕" <${process.env.SMTP_USER}>`,
      to: email,
      subject: 'Reset Your CuToDo Password 🔑',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body {
              font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
              background: linear-gradient(135deg, #FFE5EC 0%, #FFF0F5 100%);
              padding: 20px;
              margin: 0;
            }
            .container {
              max-width: 600px;
              margin: 0 auto;
              background: white;
              border-radius: 20px;
              padding: 40px;
              box-shadow: 0 10px 40px rgba(246, 165, 192, 0.2);
            }
            .header {
              text-align: center;
              margin-bottom: 30px;
            }
            .header h1 {
              color: #F6A5C0;
              font-size: 32px;
              margin: 0;
            }
            .content {
              color: #333;
              line-height: 1.6;
              font-size: 16px;
            }
            .button {
              display: inline-block;
              background: linear-gradient(135deg, #F6A5C0 0%, #CDB4FF 100%);
              color: white;
              text-decoration: none;
              padding: 15px 40px;
              border-radius: 25px;
              font-weight: 600;
              margin: 20px 0;
              text-align: center;
            }
            .warning {
              background: #FFF3E0;
              border-left: 4px solid #FF9800;
              padding: 15px;
              margin: 20px 0;
              border-radius: 5px;
            }
            .footer {
              text-align: center;
              color: #999;
              font-size: 12px;
              margin-top: 30px;
              padding-top: 20px;
              border-top: 1px solid #eee;
            }
            .emoji {
              font-size: 40px;
              margin: 20px 0;
              text-align: center;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>🔑 Password Reset</h1>
            </div>
            
            <div class="emoji">💕</div>
            
            <div class="content">
              <p>Hi there!</p>
              
              <p>We received a request to reset your CuToDo password. Click the button below to create a new password:</p>
              
              <div style="text-align: center;">
                <a href="${resetLink}" class="button">
                  Reset My Password
                </a>
              </div>
              
              <div class="warning">
                <strong>⚠️ Security Notice:</strong>
                <ul style="margin: 10px 0 0 0; padding-left: 20px;">
                  <li>This link expires in 15 minutes</li>
                  <li>It can only be used once</li>
                  <li>Your old password will stop working once reset</li>
                </ul>
              </div>
              
              <p style="font-size: 14px; color: #666;">
                If you didn't request a password reset, your account is still secure. You can safely ignore this email.
              </p>
              
              <p style="margin-top: 30px;">
                Stay organized!<br>
                <strong>The CuToDo Team</strong>
              </p>
            </div>
            
            <div class="footer">
              <p>CuToDo - Productivity, but make it cute 💕</p>
              <p style="font-size: 11px; color: #bbb;">
                If the button doesn't work, copy and paste this link:<br>
                ${resetLink}
              </p>
            </div>
          </div>
        </body>
        </html>
      `,
      text: `
Password Reset Request

We received a request to reset your CuToDo password.

Click this link to reset your password:
${resetLink}

This link expires in 15 minutes and can only be used once.

If you didn't request this, you can safely ignore this email.

Stay organized!
The CuToDo Team 💕
      `
    };

    const info = await transporter.sendMail(mailOptions);
    console.log('✅ Password reset email sent:', info.messageId);
    return true;

  } catch (error) {
    console.error('❌ Failed to send reset email:', error);
    throw error;
  }
};

/**
 * Send password change confirmation email
 */
const sendPasswordChangedEmail = async (email) => {
  try {
    const mailOptions = {
      from: `"CuToDo 💕" <${process.env.SMTP_USER}>`,
      to: email,
      subject: 'Your CuToDo Password Was Changed ✓',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body {
              font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
              background: linear-gradient(135deg, #FFE5EC 0%, #FFF0F5 100%);
              padding: 20px;
              margin: 0;
            }
            .container {
              max-width: 600px;
              margin: 0 auto;
              background: white;
              border-radius: 20px;
              padding: 40px;
              box-shadow: 0 10px 40px rgba(246, 165, 192, 0.2);
            }
            .content {
              color: #333;
              line-height: 1.6;
              font-size: 16px;
            }
            .success {
              background: #E8F5E9;
              border-left: 4px solid #4CAF50;
              padding: 15px;
              margin: 20px 0;
              border-radius: 5px;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="content">
              <h2 style="color: #F6A5C0;">✓ Password Changed Successfully</h2>
              
              <div class="success">
                <p style="margin: 0;">Your CuToDo password was successfully changed.</p>
              </div>
              
              <p>If you didn't make this change, please contact support immediately.</p>
              
              <p style="margin-top: 30px;">
                Stay secure!<br>
                <strong>The CuToDo Team</strong> 💕
              </p>
            </div>
          </div>
        </body>
        </html>
      `,
      text: `
✓ Password Changed Successfully

Your CuToDo password was successfully changed.

If you didn't make this change, please contact support immediately.

Stay secure!
The CuToDo Team 💕
      `
    };

    await transporter.sendMail(mailOptions);
    console.log('✅ Password changed email sent');
    return true;

  } catch (error) {
    console.error('❌ Failed to send confirmation email:', error);
    // Don't throw - this is not critical
    return false;
  }
};

module.exports = {
  sendVerificationEmail,
  sendPasswordResetEmail,
  sendPasswordChangedEmail
};
