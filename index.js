require('dotenv').config();
const express = require('express');
const morgan = require('morgan');
const app = express();
const connectToDatabase = require('./config//db');

const AppError = require('./utils/appError');
const globalErrorHandler = require('./controllers/globalErrorController');
const UserRouter = require('./routes/userRoutes');

// Connect to database
connectToDatabase();

// Middleware
app.use(express.json());
if (process.env.NODE_ENV === 'development') {
	app.use(morgan('dev'));
}

// Routes
app.get('/', (req, res) => {
	res.json({
		status: 'success',
		data: {
			name: 'Varun',
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
