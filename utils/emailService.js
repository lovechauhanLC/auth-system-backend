const nodemailer = require("nodemailer");

require('dotenv').config();

async function sendEmail({ to, subject, html }) {
    const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: process.env.SMTP_PORT,
        secure: false, // true for port 465, false for other ports
        auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS,
        },
    });
    await transporter.sendMail({
        from: `siddharth.excel2011@gmail.com`,
        to,
        subject,
        html,
    });
}
module.exports = sendEmail;