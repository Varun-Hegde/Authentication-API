const jwt = require('jsonwebtoken');
const { promisify } = require('util');

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
const protect = catchAsync(async (req, res, next) => {
	// 1) Getting token and check if it's there
	// 2) Verification token
	// 3) Check if user still exists?
	// 4) Check if user changed password after JWT was issued

	// 1)
	let token;
	if (
		req.headers.authorization &&
		req.headers.authorization.startsWith('Bearer')
	) {
		token = req.headers.authorization.split(' ')[1];
	}

	if (!token) {
		return next(
			new AppError(
				'You are not logged in! Please log in to continue',
				401,
			),
		);
	}

	// 2)
	const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

	// 3)
	const currentUser = await User.findById(decoded.id);
	if (!currentUser) {
		return next(
			new AppError(
				'The user belonging to this token does no longer exist.',
				401,
			),
		);
	}

	// 4)
	if (currentUser.changedPasswordAfter(decoded.iat)) {
		return next(
			new AppError(
				'User recently changed password! Please log in again.',
				401,
			),
		);
	}

	req.user = currentUser;
	next();
});

module.exports = {
	signup,
	login,
	protect,
};
