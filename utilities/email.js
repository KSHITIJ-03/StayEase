const nodemailer = require("nodemailer")

const sendEmail = async options => {
    // 1) transporter

    const transporter = nodemailer.createTransport({
        //service : "Gmail",
        host : process.env.EMAIL_HOST,
        port : process.env.EMAIL_PORT,
        auth : {
            user : process.env.EMAIL_USERNAME,
            pass : process.env.EMAIL_PASSWORD
        }
        // activate less secure app option in your gmail account
    })

    // 2) define the email options

    const emailOptions = {
        from : "StayEase <stayease@gmail.com>",
        to : options.email,
        subject : options.subject,
        text : options.message
        // html:
    }

    // 3) actually send the email

    await transporter.sendMail(emailOptions)

}

module.exports = sendEmail
