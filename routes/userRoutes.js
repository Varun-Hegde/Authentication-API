const express = require('express');
const router = express.Router();

const authController = require('../controllers/authController');
const authMiddlware = require('../middleware/authMiddleware');

router.post('/signup', authController.signup);
router.post('/login', authController.login);
router.get('/get-user', authMiddlware.protect, async (req, res) => {
	res.json(req.user);
});

module.exports = router;
