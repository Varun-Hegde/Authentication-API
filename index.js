require('dotenv').config();
const express = require('express');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const passport = require('passport');
const passportFile = require('./passport');
const connectToDatabase = require('./config//db');
const AppError = require('./utils/appError');
const globalErrorHandler = require('./controllers/globalErrorController');
const UserRouter = require('./routes/userRoutes');

const app = express();

// Connect to database
connectToDatabase();

// Middleware
// Set security HTTP headers
app.use(helmet());

// Limit repeated requests to our API
if (process.env.NODE_ENV === 'production') {
	const limiter = rateLimit({
		max: 100,
		windowMs: 60 * 60 * 1000,
		message: 'Too many requests from this IP, please try again in an hour!',
	});
	app.use('/api', limiter);
}

// Body parser
app.use(express.json());

// Data sanitization against NoSQL query injection
app.use(mongoSanitize());

// Data sanitization against XSS
app.use(xss());

if (process.env.NODE_ENV === 'development') {
	app.use(morgan('dev'));
}

// Routes
app.get('/', (req, res) => {
	res.json({
		status: 'success',
		data: {
			message: 'API is running',
		},
	});
});
app.use('/api/users', UserRouter);

// Any other invalid route
app.all('*', (req, res, next) => {
	const err = new AppError(
		`Can't find ${req.originalUrl} on this server`,
		404,
	);
	next(err);
});

// Error Handler
app.use(globalErrorHandler);

app.listen(process.env.PORT, () => {
	console.log(`API running on: http://localhost:${process.env.PORT}`);
});
