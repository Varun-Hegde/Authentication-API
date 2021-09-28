const Joi = require('joi');
const AppError = require('../utils/appError');

module.exports = validateUserSignUp = async (req, res, next) => {
	const userSchema = Joi.object({
		name: Joi.string().required(),
		email: Joi.string().email().required(),
		password: Joi.string().required().min(8),
		passwordConfirm: Joi.string().required().min(8),
	});

	try {
		await userSchema.validateAsync(req.body);
		next();
	} catch (err) {
		next(err);
	}
};
