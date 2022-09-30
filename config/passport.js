const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const User = require('../models/user');

module.exports = function (passport) {
    passport.use(
        new LocalStrategy({ usernameField: 'name' }, function (name, password, done) {
            User.findOne({ name: name })
                .then(function (user) {
                    if (!user) {
                        return done(null, false, { message: 'this email does not registered' });
                    }
                    bcrypt.compare(password, user.password, function (err, isMatch) {
                        if (err) {
                            throw err;
                        }
                        if (isMatch) {
                            console.log(user)
                            return done(null, user);
                        }
                        else {
                            return done(null, false, { message: 'password incorrect' });
                        }
                    });
                })
                .catch(function (err) {
                    console.log(err);
                })
        })
    );

    passport.serializeUser(function (user, done) {
        done(null, user.id);
    });
    passport.deserializeUser(function (id, done) {
        User.findById(id, function (err, user) {
            done(err, user);
        });
    });
};