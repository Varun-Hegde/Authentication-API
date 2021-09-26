const express = require('express');
const router = express.Router();

const authController = require('../controllers/authController');
const authMiddleware = require('../middleware/authMiddleware');

router.post('/signup', authController.signup);
router.post('/login', authController.login);
router.get(
	'/get-user',
	authMiddleware.protect,
	authMiddleware.restrictTo('admin', 'user'),
	async (req, res) => {
		res.json(req.user);
	},
);
router.post('/forgot-password', authController.forgotPassword);
router.patch('/reset-password/:token', authController.resetPassword);

router.patch(
	'/update-my-password',
	authMiddleware.protect,
	authController.updatePassword,
);

router.patch(
	'/update-profile',
	authMiddleware.protect,
	authController.updateUserData,
);

module.exports = router;
