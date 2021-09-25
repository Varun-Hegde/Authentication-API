const mongoose = require('mongoose');

const bcrypt = require('bcrypt');
const validator = require('validator');

const userSchema = mongoose.Schema({
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
	password: {
		type: String,
		required: [true, 'Please provide a password'],
		minLength: 8,
		select: false,
	},
	passwordConfirm: {
		type: String,
		required: [true, 'Please confirm your password'],
		validate: {
			//Works only on SAVE and CREATE!
			validator: function (val) {
				return this.password === val;
			},
			message: 'Passwords are not the same!',
		},
	},
	passwordChangedAt: Date,
});

//Encrypt password
userSchema.pre('save', async function (next) {
	if (!this.isModified('password')) return next();

	const salt = await bcrypt.genSalt(10);
	const hashedPassword = await bcrypt.hash(this.password, salt);
	this.password = hashedPassword;
	this.passwordConfirm = undefined;
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

const User = mongoose.model('User', userSchema);

module.exports = User;
