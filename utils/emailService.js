const nodemailer = require('nodemailer');

const createTransporter = async () => {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
        },
    });

    return transporter;
};

exports.sendEmail = async ({ to, subject, html }) => {
    try {
        const transporter = await createTransporter();

        const info = await transporter.sendMail({
            from: '"Auth System" <no-reply@authsystem.com>',
            to: to,
            subject: subject,
            html: html,
        });

        console.log("Message sent: %s", info.messageId);
        
        console.log("Preview URL: %s", nodemailer.getTestMessageUrl(info));
        
        return info;
    } catch (error) {
        console.error("Error sending email:", error);
        return null;
    }
};