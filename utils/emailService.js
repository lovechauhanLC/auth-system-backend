const { Resend } = require('resend');
require('dotenv').config();

const resend = new Resend(process.env.RESEND_API_KEY);

exports.sendEmail = async ({ to, subject, html }) => {
    try {
        const { data, error } = await resend.emails.send({
            // ⚠️ IMPORTANT: Until you verify a domain on Resend, you MUST use 'onboarding@resend.dev'
            from: 'Auth System <onboarding@resend.dev>', 
            to: [to], // Resend expects an array for 'to'
            subject: subject,
            html: html,
        });

        if (error) {
            console.error("❌ Resend Error:", error);
            // We throw the error so your controller knows it failed
            throw new Error(error.message); 
        }

        console.log("✅ Email sent successfully via Resend:", data.id);
        return data;

    } catch (err) {
        console.error("❌ System Error sending email:", err.message);
        throw err;
    }
};