const express = require('express');
const router = express.Router();

const authController = require('../controllers/authController');

router.post('/signup', authController.signup);
router.post('/login', authController.login);
router.get('/get-user', authController.protect, async (req, res) => {
	res.json(req.user);
});

module.exports = router;
