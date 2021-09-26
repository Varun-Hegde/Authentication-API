const nodemailer = require('nodemailer');

const sendEmail = async (options) => {
	// 1) Create a transporter(A service that sends email, (like gmail))
	// 2) Define email options
	// 3) Actually send the email

	// 1)
	const transporter = nodemailer.createTransport({
		host: process.env.EMAIL_HOST,
		port: process.env.EMAIL_PORT,
		auth: {
			user: process.env.EMAIL_USERNAME,
			pass: process.env.EMAIL_PASSWORD,
		},

		//Activate in gmail "Less secure app" option
	});

	// 2)
	const mailOptions = {
		from: 'Varun Hegde <varunhegde2k@gmail.com>',
		to: options.email,
		subject: options.subject,
		text: options.message,
		// html:
	};

	// 3)
	await transporter.sendMail(mailOptions);
};

module.exports = sendEmail;
