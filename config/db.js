const mongoose = require('mongoose');

const connectDB = async () => {
	try {
		const uri =
			process.env.NODE_ENV === 'development'
				? process.env.MONGO_LOCAL_URI
				: process.env.MONGO_PROD_URI;
		const conn = await mongoose.connect(uri, {
			useUnifiedTopology: true,
			useNewUrlParser: true,
		});
		console.log('Connected to database');
	} catch (err) {
		console.log(`Error ${err.message}`);
		process.exit(1);
	}
};

module.exports = connectDB;
