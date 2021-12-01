const express = require('express');
const session = require('express-session');
const hbs = require('express-handlebars');
const passport = require('passport');
const bcrypt = require('bcrypt');
require('dotenv').config();
const mongoose = require('mongoose');
const localStrategy = require('passport-local').Strategy;
const { Strategy } = require('passport-local');
const app = express();

const port = process.env.PORT || 5000;

// Running mongodb online
const uri = process.env.ATLAS_URI;
mongoose.connect(uri, {
  useNewUrlParser: true,
  // useUnifiedTopology: true
})
const connection = mongoose.connection;
connection.once('open', () => {
  console.log("MongoDB database connection established successfully");
})

// Running mongodb on PC
// mongoose.connect('mongodb://localhost:27017/node-auth-yt', {
//   useNewUrlParser: true
// })

const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true
  },
  password: {
    type: String,
    required: true
  }
});

const User = mongoose.model('User', UserSchema);


// Middleware
app.engine('hbs', hbs({ extname: '.hbs' }));
app.set('view engine', 'hbs')
app.use(express.static(__dirname + '/public'));
app.use(session({
  secret: 'verygoodsecret',
  resave: false,
  saveUninitialized: true
}));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Passport.js
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

passport.use(new localStrategy(function (username, password, done) {
  User.findOne({ username: username }, function (err, user) {
    if (err) return done(err);
    if (!user) return done(null, false, { message: 'Incorrect username.' });

    bcrypt.compare(password, user.password, function (err, res) {
      if (err) return done(err);
      if (res === false) return done(null, false, { message: 'Incorrect password.' });

      return done(null, user);
    });
  });
}));

function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
}

function isLoggedOut(req, res, next) {
  if (!req.isAuthenticated()) return next();
  res.redirect('/');
}

// Routes
app.get('/', isLoggedIn, function (req, res) {
  res.render('index', { title: 'Home' });
});

app.get('/about', isLoggedIn, function (req, res) {
  res.render('index', { title: 'About' });
});

app.get('/login', isLoggedOut, (req, res) => {
  const response = {
    title: 'Login',
    error: req.query.error
  }

  res.render('login', response);
});

app.post('/login', passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/login?error=true'
}));

app.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/');
})

// Setup our admin user
app.get('/setup', async (req, res) => {
  const exists = await User.exists({ username: 'admin' });

  if (exists) {
    console.log(exists)
    console.log('Exists')
    res.redirect('/login');
    return;
  }

  bcrypt.genSalt(10, function (err, salt) {
    if (err) return next(err);
    bcrypt.hash('pass', salt, function (err, hash) {
      if (err) return next(err);

      const newAdmin = new User({
        username: 'admin',
        password: hash
      });

      newAdmin.save();

      res.redirect('/login');
    });
  });
});

app.listen(port, () => {
  console.log(`Listening on port ${port}`);
  console.log(`http://localhost:${port}`);
});