const jwt = require('jsonwebtoken');
const { promisify } = require('util');

const User = require('../models/userModel');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');

// Continue to controller only if we have a valid JWT
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
	protect,
};
