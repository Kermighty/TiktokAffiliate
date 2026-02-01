<?php
/**
 * Email Configuration and Mailer Class
 * Simple PHP mailer using mail() function
 */

class Mailer {
    private $from_email;
    private $from_name;
    private $site_url;

    public function __construct() {
        $this->from_email = 'noreply@tiktokaffiliate.com'; // Change this to your email
        $this->from_name = 'TikTok Affiliate Evaluator';
        $this->site_url = 'http://localhost/tiktok-affiliate'; // Change this to your actual URL
    }

    /**
     * Send verification email
     */
    public function sendVerificationEmail($to_email, $full_name, $token) {
        $subject = "Verify Your Email - TikTok Affiliate";
        $verification_link = $this->site_url . "/verify-email.php?token=" . urlencode($token);
        
        $message = $this->getEmailTemplate(
            "Welcome, $full_name!",
            "Thank you for registering with TikTok Affiliate Evaluator.",
            "Please verify your email address to activate your account.",
            "Verify Email",
            $verification_link,
            "This link will expire in 24 hours."
        );

        return $this->send($to_email, $subject, $message);
    }

    /**
     * Send password reset email
     */
    public function sendPasswordResetEmail($to_email, $full_name, $token) {
        $subject = "Reset Your Password - TikTok Affiliate";
        $reset_link = $this->site_url . "/reset-password.php?token=" . urlencode($token);
        
        $message = $this->getEmailTemplate(
            "Password Reset Request",
            "Hi $full_name,",
            "We received a request to reset your password. Click the button below to create a new password.",
            "Reset Password",
            $reset_link,
            "This link will expire in 1 hour. If you didn't request this, please ignore this email."
        );

        return $this->send($to_email, $subject, $message);
    }

    /**
     * Send OTP email
     */
    public function sendOTPEmail($to_email, $full_name, $otp) {
        $subject = "Your Password Reset Code - TikTok Affiliate";
        
        $message = $this->getEmailTemplate(
            "Password Reset Code",
            "Hi $full_name,",
            "Your password reset code is: <strong style='font-size: 24px; color: #ff0080;'>$otp</strong>",
            null,
            null,
            "This code will expire in 15 minutes. If you didn't request this, please ignore this email."
        );

        return $this->send($to_email, $subject, $message);
    }

    /**
     * Send actual email
     */
    private function send($to, $subject, $html_message) {
        $headers = "MIME-Version: 1.0" . "\r\n";
        $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
        $headers .= "From: {$this->from_name} <{$this->from_email}>" . "\r\n";
        $headers .= "Reply-To: {$this->from_email}" . "\r\n";
        $headers .= "X-Mailer: PHP/" . phpversion();

        return mail($to, $subject, $html_message, $headers);
    }

    /**
     * Email template
     */
    private function getEmailTemplate($title, $greeting, $message, $button_text = null, $button_link = null, $footer_text = null) {
        $button_html = '';
        if ($button_text && $button_link) {
            $button_html = "
                <table width='100%' cellpadding='0' cellspacing='0' style='margin: 30px 0;'>
                    <tr>
                        <td align='center'>
                            <a href='$button_link' style='display: inline-block; padding: 15px 40px; background: linear-gradient(135deg, #ff0080, #00d4ff); color: white; text-decoration: none; border-radius: 25px; font-weight: 600; font-size: 16px;'>$button_text</a>
                        </td>
                    </tr>
                </table>
            ";
        }

        return "
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset='UTF-8'>
            <meta name='viewport' content='width=device-width, initial-scale=1.0'>
        </head>
        <body style='margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;'>
            <table width='100%' cellpadding='0' cellspacing='0' style='background-color: #f4f4f4; padding: 20px;'>
                <tr>
                    <td align='center'>
                        <table width='600' cellpadding='0' cellspacing='0' style='background-color: white; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);'>
                            <!-- Header -->
                            <tr>
                                <td style='background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); padding: 40px; text-align: center;'>
                                    <h1 style='margin: 0; color: white; font-size: 28px;'>🎯 TikTok Affiliate</h1>
                                    <p style='margin: 10px 0 0 0; color: #aaa; font-size: 14px;'>Product Evaluator System</p>
                                </td>
                            </tr>
                            
                            <!-- Content -->
                            <tr>
                                <td style='padding: 40px;'>
                                    <h2 style='margin: 0 0 20px 0; color: #333; font-size: 24px;'>$title</h2>
                                    <p style='margin: 0 0 15px 0; color: #666; font-size: 16px; line-height: 1.6;'>$greeting</p>
                                    <p style='margin: 0 0 15px 0; color: #666; font-size: 16px; line-height: 1.6;'>$message</p>
                                    
                                    $button_html
                                    
                                    " . ($footer_text ? "<p style='margin: 20px 0 0 0; color: #999; font-size: 14px;'>$footer_text</p>" : "") . "
                                </td>
                            </tr>
                            
                            <!-- Footer -->
                            <tr>
                                <td style='background-color: #f8f8f8; padding: 30px; text-align: center; border-top: 1px solid #eee;'>
                                    <p style='margin: 0; color: #999; font-size: 14px;'>© " . date('Y') . " TikTok Affiliate Evaluator. All rights reserved.</p>
                                    <p style='margin: 10px 0 0 0; color: #999; font-size: 12px;'>This is an automated email. Please do not reply.</p>
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
            </table>
        </body>
        </html>
        ";
    }
}
