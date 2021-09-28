const express = require('express');
const router = express.Router();
const passport = require('passport');

const passportConf = require('../passport');
const authController = require('../controllers/authController');
const authMiddleware = require('../middleware/authMiddleware');
const userValidation = require('../validation/usersValidation');

const passportGoogle = passport.authenticate('googleToken', { session: false });

router.post('/signup', userValidation, authController.signup); //SignUp
router.post('/login', authController.login); //Login
router.get('/logout', authMiddleware.protect, authController.logout);

router.get(
	'/get-user',
	authMiddleware.protect,
	authMiddleware.restrictTo('admin', 'user'),
	async (req, res) => {
		res.json(req.user);
	},
); //Get user info

router.post('/forgot-password', authController.forgotPassword); //Forgot password
router.patch('/reset-password/:token', authController.resetPassword); //reset password

router.patch(
	'/update-my-password',
	authMiddleware.protect,
	authController.updatePassword,
); //update only password
router.patch(
	'/update-profile',
	authMiddleware.protect,
	authController.updateUserData,
); // update user profile

router.post('/oauth/google', passportGoogle, authController.googleAuth); //Google Oauth login/signup
router.patch(
	'/oauth/link/google',
	authMiddleware.protect,
	passportGoogle,
	authController.linkGoogle,
); //Link google
router.patch(
	'/oauth/unlink/google',
	authMiddleware.protect,
	authController.unLinkGoogle,
); //UnLink google

module.exports = router;
