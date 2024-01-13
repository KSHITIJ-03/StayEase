const nodemailer = require("nodemailer")

const sendEmail = async options => {
    // 1) transporter

    const transporter = nodemailer.createTransport({
        //service : "Gmail",
        host : "sandbox.smtp.mailtrap.io",
        port : 25,
        auth : {
            user : "9808bad0491db0",
            pass : "a217788977b989"
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