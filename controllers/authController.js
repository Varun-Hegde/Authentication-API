const User = require('../models/userModel');
const catchAsync = require('../utils/catchAsync');
const signToken = require('../utils/jwtTokens');
const AppError = require('../utils/appError');

// SIGNUP controller
const signup = catchAsync(async (req, res, next) => {
	const queryObj = {
		name: req.body.name,
		email: req.body.email,
		password: req.body.password,
		passwordConfirm: req.body.passwordConfirm,
	};

	const newUser = await User.create(queryObj);

	res.status(201).json({
		status: 'success',
		token: signToken(newUser._id),
		data: {
			user: newUser,
		},
	});
});

//LOGIN controller
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
	const user = await User.findOne({ email }).select('+password');

	if (!user || !(await user.correctPassword(password, user.password))) {
		return next(new AppError('Invalid email or password', 401));
	}

	res.status(201).json({
		status: 'success',
		token: signToken(user._id),
		data: {
			user,
		},
	});
});

// Protect route middleware

module.exports = {
	signup,
	login,
};
