// utils/emailService.js
const nodemailer = require('nodemailer');

// 1. Create the Transporter

const createTransporter = async () => {
    // We use the built-in 'gmail' service option
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS, // The App Password
        },
    });

    return transporter;
};

// 2. Generic Send Function
exports.sendEmail = async ({ to, subject, html }) => {
    try {
        const transporter = await createTransporter();

        const info = await transporter.sendMail({
            from: '"Auth System" <no-reply@authsystem.com>', // Sender address
            to: to, // Receiver
            subject: subject, // Subject line
            html: html, // HTML body
        });

        console.log("Message sent: %s", info.messageId);
        
        // This is the Magic Part: It gives you a URL to view the email!
        console.log("Preview URL: %s", nodemailer.getTestMessageUrl(info));
        
        return info;
    } catch (error) {
        console.error("Error sending email:", error);
        return null;
    }
};