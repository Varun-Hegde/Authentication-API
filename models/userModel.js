const mongoose = require('mongoose');

const { randomBytes, createHash } = require('crypto');
const bcrypt = require('bcrypt');
const validator = require('validator');

const userSchema = mongoose.Schema(
	{
		methods: {
			type: [String],
			required: true,
			default: ['local'],
		},
		name: {
			type: String,
			required: [true, 'Please provide your name'],
		},
		email: {
			type: String,
			required: [true, 'Please provide your email'],
			unique: true,
			lowercase: true,
			validate: [validator.isEmail, 'Please provide a valid email'],
		},
		photo: {
			type: String,
		},
		role: {
			type: String,
			enum: ['user', 'admin', 'moderator'],
			default: 'user',
		},
		local: {
			email: {
				type: String,
				lowercase: true,
				validate: [validator.isEmail, 'Please provide a valid email'],
			},
			password: {
				type: String,
				minLength: 8,
				select: false,
			},
			passwordConfirm: {
				type: String,
				validate: {
					//Works only on SAVE and CREATE!
					validator: function (val) {
						return this.local.password === val;
					},
					message: 'Passwords are not the same!',
				},
			},
		},
		google: {
			id: {
				type: String,
			},
			email: {
				type: String,
				lowercase: true,
				validate: [validator.isEmail, 'Please provide a valid email'],
			},
		},

		passwordChangedAt: Date,
		passwordResetToken: String,
		passwordResetExpires: Date,
	},
	{
		timestamps: true,
	},
);

//Encrypt password
userSchema.pre('save', async function (next) {
	if (!this.methods.includes('local')) return next();

	if (!this.isModified('local.password')) return next();
	try {
		const salt = await bcrypt.genSalt(10);
		const hashedPassword = await bcrypt.hash(this.local.password, salt);
		this.local.password = hashedPassword;
		this.local.passwordConfirm = undefined;
		next();
	} catch (err) {
		next(err);
	}
});

//Update password changed at attribute
userSchema.pre('save', function (next) {
	if (!this.isModified('local.password') || this.isNew) return next();

	this.passwordChangedAt = Date.now() - 1000;
	//Sometimes JWT could be created before this middleware function gets executed,
	//and causes issues while logging in (passwordChangedAt > token.issuedAtTime)
	next();
});

//Check if entered password is correct(during login)
userSchema.methods.correctPassword = async function (
	candidatePassword,
	userPassword,
) {
	return await bcrypt.compare(candidatePassword, userPassword);
};

//Check
userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
	if (this.passwordChangedAt) {
		const changedTimeStamp = parseInt(
			this.passwordChangedAt.getTime() / 1000,
			10,
		);

		return JWTTimestamp < changedTimeStamp;
	}

	return false;
};

//Create user password reset token
userSchema.methods.createPasswordResetToken = function () {
	// 1)Generate a token
	// 2)Encrypt and store in database
	const resetToken = randomBytes(32).toString('hex');
	this.passwordResetToken = createHash('sha256')
		.update(resetToken)
		.digest('hex');
	this.passwordResetExpires = Date.now() + 10 * 60 * 1000; //expire in 10 minutes

	return resetToken;
};

const User = mongoose.model('User', userSchema);

module.exports = User;
