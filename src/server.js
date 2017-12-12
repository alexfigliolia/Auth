const bodyParser = require('body-parser');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const User = require('./user');
const mongoose = require('mongoose');

const STATUS_USER_ERROR = 422;
const BCRYPT_COST = 11;

const server = express();

server.use(bodyParser.json());
server.use(session({
  secret: 'e5SPiqsEtjexkTj3Xqovsjzq8ovjfgVDFMfUzSmJO21dtXs4re',
  resave: true,
  saveUninitialized: false,
}));

const sendUserError = (err, res) => {
  res.status(STATUS_USER_ERROR);
  if (err && err.message) {
    res.json({ message: err.message, stack: err.stack });
  } else {
    res.json({ error: err });
  }
};

//Middlewares
const hashPassword = (req, res, next) => {
	const { password } = req.body;
	if(!password) {
		sendUserError('password is required', res);
		return;
	}
	bcrypt.hash(password, BCRYPT_COST)
	.then(pw => {
		req.password = pw;
		next();
	})
	.catch(err => {
		throw new Error(err);
	});		
}

const authenticate = (req, res, next) => {
	const { email, password } = req.body;
	if(!email) {
		sendUserError('email is required', res);
		return;
	} 
	User.findOne({ email }, (err, user) => {
		if(err || user === null) {
			sendUserError('no user found with that email', res);
			return;
		}
		const hashedPw = user.password;
		bcrypt.compare(password, hashedPw)
		.then(response => {
			if(!response) throw new Error();
			req.loggedInUser = user;
			next();
		})
		.catch(error => {
			sendUserError('something went wrong', error);
		});
	})
}


//ROUTES

server.post('/log-in', authenticate, (req, res) => {
  res.json({ success: true });
});

server.post('/users', hashPassword, (req, res) => {
  const { email, name } = req.body;
  const passwordHash = req.password;
  const newUser = new User({ email, name, password: passwordHash });
  newUser.save((err, savedUser) => {
    if (err) {
      res.status(422);
      res.json({ 'Need both Email/PW fields': err.message });
      return;
    }
    res.json(savedUser);
  });
});


server.get('/me', (req, res) => {
  // Do NOT modify this route handler in any way.
  res.json(req.user);
});

module.exports = { server };
