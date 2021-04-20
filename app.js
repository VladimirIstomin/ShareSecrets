require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');
const bcrypt = require('bcrypt');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
const GoogleStrategy = require('passport-google-oauth20').Strategy;


// Server configuraton

const app = express();
app.use(express.urlencoded({extended: true}));
app.use(express.static('public'));
app.set('view engine', 'ejs');


// Session configuration

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

// Mongoose configuration

mongoose.connect('mongodb://localhost:27017/SecretsDB', {
    useFindAndModify: false,
    useNewUrlParser: true,
    useUnifiedTopology: true
});

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String,
    secrets: Array
});

const User = new mongoose.model('User', userSchema);

// Strategies configuration

passport.use('register', new LocalStrategy((username, password, done) => {
    User.findOne({username}, (err, foundUser) => {
        if (err) {
            return done(err);
        }

        if (!foundUser) {
            bcrypt.hash(password, 12, (err, hash) => {
                if (err) {
                    return done(err);
                }
                
                const user = new User({
                    username,
                    password: hash
                });

                user.save((err) => {
                    if (err) {
                        return done(err);
                    }
                })
            });
        } else {
            done(null, false, {message: 'User with this username already exists!'});
        }
    })
}));

passport.use(new LocalStrategy(
    (username, password, done) => {
        User.findOne({username}, async (err, foundUser) => {
            if (err) {
                return done(err);
            }

            if (!foundUser) {
                return done(null, false, {message: 'Incorrect username!'});
            }

            if (await bcrypt.compare(password, foundUser.password)) {
                return done(null, foundUser);
            } else {
                return done(null, false, {message: 'Incorrect password!'}); 
            }
        });
    }
));

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: 'http://localhost:3000/auth/google/secrets'
    },
    (accessToken, refreshToken, profile, done) => {
        User.findOne({googleId: profile.id}, (err, foundUser) => {
            if (err) {
                return done(err, false);
            }

            if (!foundUser) {
                const user = new User({
                    googleId: profile.id
                });

                user.save((err) => {
                    if (err) {
                        return done(err, false)
                    } else {
                        return done(err, user);
                    }
                });
            } else {
                return done(err, foundUser);
            }
        });
    }
));

passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});


// Requests

app.get('/', (req, res) => {
    res.render('home');
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', passport.authenticate('register', {
    successRedirect: '/secrets',
    failureRedirect: '/register'
}));

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', passport.authenticate('local', {
    successRedirect: '/secrets',
    failureRedirect: '/register'
}));

app.get('/logout', (req, res) => {
    req.logout();
    res.redirect('/');
});

app.get('/auth/google', passport.authenticate('google', {scope: ['profile']}));

app.get('/auth/google/secrets', passport.authenticate('google', {
    successRedirect: '/secrets',
    failureRedirect: '/register'
}));

app.get('/secrets', (req, res) => {
    if (req.isAuthenticated()) {
        User.find({secrets: {$exists: true}}, async (err, foundUsers) => {
            if (err) {
                console.log(err);
            }

            if (foundUsers) {
                const secretsList = [];

                await foundUsers.forEach(user => {
                    user.secrets.forEach(secret => {
                        secretsList.push(secret); 
                    });
                });

                res.render('secrets', {secretsList: secretsList});
            } else {
                console.log('No secrets found!');
            } 
        });  
    } else {
        res.redirect('/login');
    }
});

app.get('/submit', (req, res) => {
    if (req.isAuthenticated()) {
        res.render('submit');
    } else {
        res.redirect('/login');
    }  
});

app.post('/submit', (req, res) => {
    const secret = req.body.secret;
    const userId = req.user.id;

    User.findById(userId, (err, foundUser) => {
        if (err) {
            console.log(err);
        }

        if (foundUser) {
            if ('secrets' in foundUser) {
                foundUser.secrets.push(secret);
            } else {
                foundUser['secrets'] = [secret];
            }
            
            foundUser.save((err) => {
                if (err) {
                    console.log(err);
                } else {
                    res.redirect('/secrets');
                }
            });
        }
    })
})


app.listen(process.env.PORT || 3000, () => console.log('Server has been started!'));
