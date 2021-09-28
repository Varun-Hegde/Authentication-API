const AppError = require('../utils/appError');

//Handling Mongo CastError => Occurs when we have invalid database _id
const handleCastErrorDB = (err) => {
	const message = `Invalid ${err.path}: ${err.value}.`;
	return new AppError(message, 400);
};

//Handling MongoError => Occurs when we have duplicate database fields
const handleDuplicateFieldsDB = (err) => {
	const value = err.message.match(/(["'])(\\?.)*?\1/)[0];

	const message = `Duplicate field value: ${value}. Please use another value!`;
	return new AppError(message, 400);
};

//Handling mongo validation error:
const handleValidationErrorDB = (err) => {
	const allErrors = Object.values(err.errors);
	const errMessage = allErrors.map((el) => el.message);
	const message = `Invalid input data. ${errMessage.join('. ')}`;
	return new AppError(message, 400);
};

//Handling JWT error:
const handleJWTError = () => {
	return new AppError('Invalid token. Please log in again!', 401);
};

//Handling expired tokens
const handleJWTExpiredError = () => {
	return new AppError('Your token has expired! Please log in again', 401);
};

// Send error when in development mode
const sendErrorDev = (err, res) => {
	res.status(err.statusCode).json({
		status: err.status,
		message: err.message,
		error: err,
		stack: err.stack,
	});
};

// Send error when in production mode
const sendErrorProd = (err, res) => {
	res.status(err.statusCode).json({
		status: err.status,
		message: err.message,
	});
};

const errorHandler = (err, req, res, next) => {
	err.statusCode = err.statusCode || 500;
	err.status = err.status || 'error';

	if (process.env.NODE_ENV === 'development') {
		sendErrorDev(err, res);
	} else if (process.env.NODE_ENV === 'production') {
		let error = { ...err }; //Create a deep copy
		error.message = err.message;

		if (error.name === 'CastError') {
			error = handleCastErrorDB(error);
		}
		if (error.code === 11000) {
			error = handleDuplicateFieldsDB(error);
		}
		if (error.name === 'ValidationError') {
			error = handleValidationErrorDB(error);
		}
		if (error.name === 'JsonWebTokenError') {
			error = handleJWTError();
		}
		if (error.name === 'TokenExpiredError') {
			error = handleJWTExpiredError();
		}
		sendErrorProd(error, res);
	}
};

module.exports = errorHandler;
