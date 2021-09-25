class AppError extends Error {
	constructor(message, statusCode) {
		super(message);

		this.statusCode = statusCode;
		this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
		this.isOperational = true;
		Error.captureStackTrace(this, this.constructor);
	}
}

module.exports = AppError;
/*
All errors we create/throw ourselves are operational errors
Its only for these errors, we need to send our error message to client
If we get some error from any library, we dont need to send that to the client
*/
