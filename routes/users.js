const { render } = require('ejs');
const express = require('express');
const router = express.Router();
const User = require('../models/user.js');
const bcrypt = require('bcrypt');
const passport = require('passport');
const QRcode = require('qrcode');
const { authenticator } = require('otplib');
const jwt = require('jsonwebtoken');
const secretkey_gen = require('../models/secret_gen')
const { ensureAuthenticated } = require("../config/auth.js");
const ws = require('../models/websocket');


router.get('/login', function (req, res) {
    res.render('login');
});
router.get('/login_mfa', ensureAuthenticated, function (req, res) {
    //console.log(req.user)
    if (!req.user.secret) {
        var secret = authenticator.generateSecret();
        QRcode.toDataURL(authenticator.keyuri(req.user.name, 'smartLock_proj', secret), function (err, url) {
            //req.flash('success_msg', 'registered successfully');
            //console.log('22+' + url);
            req.session.qr = url;
            //console.log('24+' + req.session.qr);
            req.session.secret = secret;
            req.session.name = req.user.name;
            return res.redirect('/users/register_mfa');
        })
        //console.log('29+' + req.session.qr);
        //res.redirect('/users/register_mfa');
    }
    else {
        res.render('login_mfa');
    }

})
router.get('/register_mfa', ensureAuthenticated, function (req, res) {
    if (!req.session.qr) {
        res.redirect('/dashboard');
    }
    //console.log(req.session.qr);

    res.render('register_mfa', { qr: req.session.qr, secret: req.session.secret });

})
router.post('/register_mfa', function (req, res) {
    if (!req.session.name) {
        return res.redirect('/');
    }
    let errors = [];
    User.findOne({ name: req.session.name }).exec(function (err, user) {
        //console.log(user);
        if (err) {
            throw err;
        }
        if (!user) {
            res.redirect('/');
        }
        if (!authenticator.check(req.body.code, req.session.secret)) {
            errors.push({ msg: "wrong code" });
            return res.render('register_mfa', {
                errors: errors,
                code: '',
                qr : req.session.qr,
                secret: req.session.secret

            });
            //return res.redirect('/users/login_mfa');
        }
        user.secret = req.session.secret;
        user.save();
        req.session.qr = null;
        req.session.name = null;
        //console.log(user);
        req.logout(function (err) {
            if (err) {
                throw err;
            }
            res.redirect('/users/login')
        });

        //res.redirect('/users/login')
    });
});

router.post('/login', function (req, res, next) {
    passport.authenticate('local', {
        successRedirect: '/users/login_mfa',
        failureRedirect: '/users/login',
        failureFlash: true
    })(req, res, next);
});

router.post('/login_mfa', function (req, res) {
    console.log(req.user);
    if (!req.user.name) {
        return res.redirect('/');
    }
    //console.log(req.body.code);
    //console.log(authenticator.check(req.body.code, req.user.secret));
    let errors = [];
    if (!authenticator.check(req.body.code, req.user.secret)) {
        errors.push({ msg: "wrong code" });
        return res.render('login_mfa', {
            errors: errors,
            code: ''
        });
    }
    req.session.qr = null;
    req.session.name = null;
    //console.log(secretkey_gen.secretkey);
    req.session.token = jwt.sign(req.user.name, secretkey_gen.secretkey);
    res.redirect('/dashboard');

})
router.get('/logout', function (req, res) {
    req.logout(function (err) {
        if (err) {
            throw err;
        }
        ws.ws.send('false');
        res.redirect('/users/login')
    });

});
module.exports = router;