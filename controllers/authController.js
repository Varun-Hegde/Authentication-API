const User = require('../models/userModel');
const catchAsync = require('../utils/catchAsync');
const signToken = require('../utils/jwtTokens');
const AppError = require('../utils/appError');
const sendEmail = require('../utils/email');
const { createHash } = require('crypto');
const { use } = require('passport');

//Helper function to create JWT and send a proper response
const createSendToken = (user, statusCode, res) => {
	const token = signToken(user._id);

	//Create a cookie
	const cookieOptions = {
		expires: new Date(
			Date.now + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000,
		),
		httpOnly: true,
	};

	if (process.env.NODE_ENV === 'production') {
		cookieOptions.secure = true;
	}

	res.cookie('jwt', token, { httpOnly: true });

	//Remove password
	user.local.password = undefined;
	user.__v = undefined;

	res.status(statusCode).json({
		status: 'success',
		token,
		data: {
			user,
		},
	});
};

//Helper function to filter request body for updating user
const filterObj = (obj, ...allowedFields) => {
	const newObj = {};
	Object.keys(obj).forEach((el) => {
		if (allowedFields.includes(el)) newObj[el] = obj[el];
	});
	return newObj;
};

// Signup controller
const signup = catchAsync(async (req, res, next) => {
	const userExists = await User.findOne({ email: req.body.email });

	if (userExists) {
		next(
			new AppError(
				'A user with this email already exists. Try using a different email',
				401,
			),
		);
		return;
	}
	const queryObj = {
		methods: ['local'],
		name: req.body.name,
		email: req.body.email,
		local: {
			email: req.body.email,
			password: req.body.password,
			passwordConfirm: req.body.passwordConfirm,
		},
	};
	const newUser = await User.create(queryObj);

	createSendToken(newUser, 201, res);
});

//Login controller
const login = catchAsync(async (req, res, next) => {
	const { email, password } = req.body;

	// 1) Check if password and email exists in request body
	// 2) Check if user exists and password is correct
	// 3) If everything ok, send jwt token to client

	// 1)
	if (!email || !password) {
		next(new AppError('Please provide email and password!', 400));
	}

	// 2)
	const user = await User.findOne({ email }).select('+local.password -__v');

	if (
		!user ||
		!user.methods.includes('local') ||
		!(await user.correctPassword(password, user.local.password))
	) {
		return next(new AppError('Invalid email or password', 401));
	}

	// 3)
	createSendToken(user, 200, res);
});

//Logout
const logout = (req, res) => {
	res.clearCookie('jwt');
	res.status(200).json({
		status: 'success',
		message: 'Successfully logged out',
	});
};

// Forgot password controller
const forgotPassword = catchAsync(async (req, res, next) => {
	// 1) Get user based on POSTed email
	// 2) Generate the random reset token
	// 3) Send it to the user's mail

	// 1)
	const user = await User.findOne({ email: req.body.email });
	if (!user) {
		return next(
			new AppError('There is no user with this email address.', 404),
		);
	}

	if (!user.methods.includes('local')) {
		return next(
			new AppError('Try logging in using your google account', 400),
		);
	}

	// 2)
	const resetToken = user.createPasswordResetToken();
	await user.save({ validateBeforeSave: false });

	// 3)
	const resetURL = `${req.protocol}://${req.get(
		'host',
	)}/api/users/reset-password/${resetToken}`;

	const message = `Forgot your password? Submit a PATCH request with your new password and password Confirm to: ${resetURL}.
If you didn't forget your password, please ignore this email`;

	try {
		await sendEmail({
			email: user.email,
			subject: 'Your password reset token(Valid for 10 min)',
			message,
		});

		res.status(200).json({
			status: 'success',
			message: 'Token sent to your email!',
		});
	} catch (err) {
		user.passwordResetToken = undefined;
		user.passwordResetExpires = undefined;
		await user.save({ validateBeforeSave: false });

		return next(
			new AppError(
				'There was an error sending the email. Try again later',
				500,
			),
		);
	}
});

//Reset Password using token controller
const resetPassword = catchAsync(async (req, res, next) => {
	// 1) Get user based on token
	// 2) If token has not expired, and there is user, change password
	// 3) Update changedPasswordAt property fot the user
	// 4) Log the user in, send JWT

	// 1)
	const hashedToken = createHash('sha256')
		.update(req.params.token)
		.digest('hex');
	const user = await User.findOne({
		passwordResetToken: hashedToken,
		passwordResetExpires: { $gt: Date.now() },
	});

	// 2)
	if (!user) {
		return next(new AppError('Token is invalid or has expired', 400));
	}

	user.local.password = req.body.password;
	user.local.passwordConfirm = req.body.passwordConfirm;

	user.passwordResetToken = undefined;
	user.passwordResetExpires = undefined;
	await user.save();

	// 4)
	createSendToken(user, 200, res);
});

//Update/Change password
const updatePassword = catchAsync(async (req, res, next) => {
	// 1) Get user from collection
	// 2) Check if POSTed current password is correct
	// 3) If so, update password
	// 4) Log user in, send JWT

	// 1)

	const user = await User.findById(req.user._id).select('+local.password');

	if (
		(user.methods.includes('local') && !req.body.passwordCurrent) ||
		!req.body.password ||
		!req.body.passwordConfirm
	)
		return next(new AppError('Current password and new password required'));

	// 2)

	if (
		user.methods.includes('local') &&
		!(await user.correctPassword(
			req.body.passwordCurrent,
			user.local.password,
		))
	) {
		return next(new AppError('Your current password is wrong.', 401));
	}

	// 3)
	user.local.email = user.email;
	user.local.password = req.body.password;
	user.local.passwordConfirm = req.body.passwordConfirm;

	if (!user.methods.includes('local')) {
		user.methods.push('local');
	}

	await user.save();
	// User.findByIdAndUpdate will NOT work as intended!

	// 4) Log user in, send JWT
	createSendToken(user, 200, res);
});

// Update user details controller
const updateUserData = catchAsync(async (req, res, next) => {
	// 1) Create error if user POSTs password data
	// 2) Update user document

	// 1)
	if (req.body.password || req.body.passwordConfirm) {
		return next(
			new AppError(
				`This route is not for password updates. Please use /update-my-password`,
				400,
			),
		);
	}

	// 2)
	const filterBody = filterObj(req.body, 'name', 'email');
	const updatedUser = await User.findByIdAndUpdate(req.user.id, filterBody, {
		new: true,
		runValidators: true,
	});

	res.status(200).json({
		status: 'success',
		data: {
			user: updatedUser,
		},
	});
});

const googleAuth = catchAsync(async (req, res) => {
	createSendToken(req.user, 200, res);
});

const linkGoogle = catchAsync(async (req, res) => {
	res.status(200).json({
		status: 'success',
		message: 'Successfully linked your account with google',
	});
});

const unLinkGoogle = catchAsync(async (req, res, next) => {
	const googleLinked = req.user.methods.includes('google');
	if (!googleLinked) {
		next(new AppError('You need to first link your google account.', 400));
		return;
	}

	const localMethod = req.user.methods.includes('local');

	if (!localMethod) {
		next(
			new AppError(
				'Add a password to this account. Only then you can unlink your google account',
				400,
			),
		);
		return;
	}

	req.user.google = undefined;
	const googleStrPos = req.user.methods.indexOf('google');
	req.user.methods.splice(googleStrPos, 1);
	await req.user.save();

	res.json({
		status: 'success',
		message: 'Successfully unlinked your account with google',
	});
});

module.exports = {
	signup,
	login,
	logout,
	forgotPassword,
	resetPassword,
	updatePassword,
	updateUserData,
	googleAuth,
	linkGoogle,
	unLinkGoogle,
};
