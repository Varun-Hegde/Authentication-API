const passport = require('passport');
const GoogleStrategy = require('passport-google-token').Strategy;

const User = require('./models/userModel');
const AppError = require('./utils/appError');

passport.use(
	'googleToken',
	new GoogleStrategy(
		{
			clientID: process.env.GOOGLE_CLIENT_ID,
			clientSecret: process.env.GOOGLE_CLIENT_SECRET,
			passReqToCallback: true,
		},
		async (req, accessToken, refreshToken, profile, done) => {
			try {
				//Could get accessed in 2 ways:
				// 1. When registering for 1st time
				// 2. When linking account to existing one

				//Already logged in,need to link account
				//Add google's data to an existing account

				if (req.user) {
					//Check if already linked account

					const linked = req.user.methods.includes('google');
					if (linked) {
						throw new AppError(
							'You have already linked your google account',
							400,
						);
					}
					req.user.methods.push('google');
					const googleData = {
						id: profile.id,
						email: profile.emails[0].value,
					};
					req.user.google = googleData;
					await req.user.save();
					done(null, req.user);
				} else {
					//In account creation process
					//Check if user with email already exists

					let existingUser = await User.findOne({
						'google.id': profile.id,
					});

					//Login
					if (existingUser) return done(null, existingUser);

					let localExistingUser = await User.findOne({
						'local.email': profile.emails[0].value,
					});

					if (localExistingUser) {
						//We need to merge google's data with local auth
						localExistingUser.methods.push('google');
						localExistingUser.google = {
							id: profile.id,
							email: profile.emails[0].value,
						};
						await localExistingUser.save();
						return done(null, localExistingUser);
					}

					//Create a new user, signup
					let newUser = new User({
						methods: ['google'],
						name: profile.emails[0].value.split('@')[0],
						email: profile.emails[0].value,
						photo: profile._json.picture,
						google: {
							id: profile.id,
							email: profile.emails[0].value,
						},
					});

					newUser = await newUser.save();
					req.user = newUser;

					return done(null, newUser);
				}
			} catch (err) {
				done(err, false, err.message);
			}
		},
	),
);
