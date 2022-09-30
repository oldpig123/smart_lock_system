const express = require('express');
const router = express.Router();
const User = require('../models/user.js');
const bcrypt = require('bcrypt');
const passport = require('passport');
const QRcode = require('qrcode');
const { authenticator } = require('otplib');
const { expressjwt: expressJWT } = require('express-jwt');
const secretkey_gen = require('../models/secret_gen');
const { ensureAuthenticated } = require("../config/auth.js");
//const errors = require('formidable/FormidableError.js');
const ws = require('../models/websocket')
const jwtmiddleware = expressJWT({
    secret: secretkey_gen.secretkey,
    algorithms: ['HS256'],
    getToken: function (req) {
        return req.session.token;
    }
})

router.get('/newuser', ensureAuthenticated, jwtmiddleware, function (req, res) {
    if (!req.user.admin) {
        return res.redirect('/dashboard')
    }
    res.render('register');
})

router.get('/rst_password', ensureAuthenticated, jwtmiddleware, function (req, res) {
    res.render('rst_password');
})

router.get('/rm_user', ensureAuthenticated, jwtmiddleware, function (req, res) {
    if (!req.user.admin) {
        return res.redirect('/dashboard')
    }
    res.render('rm_user');
})

router.get('/rst_user_secret', ensureAuthenticated, jwtmiddleware, function (req, res) {
    if (!req.user.admin) {
        return res.redirect('/dashboard')
    }
    res.render('rst_user_secret');
})

router.post('/newuser', function (req, res) {
    const { name, password, password2, admin } = req.body;
    let errors = [];
    console.log('Name: ' + name + ' pass: ' + password + ' pass2:' + password2 + 'admin:' + (admin == 'admin'));
    if (!name || !password || !password2) {
        errors.push({ msg: "please fill in all fields" });
        //console.log('please fill in all fields');
    }
    if (password.length < 6) {
        errors.push({ msg: "password must be 6 characters or more" });
        //console.log('password must be 6 characters or more');
    }
    if (password != password2) {
        errors.push({ msg: "Confirm password does not match" });
        //console.log('Confirm password does not match');
    }
    if (errors.length > 0) {
        res.render('register', {
            errors: errors,
            name: name,
            password: password,
            password2: password2
        });
    }
    else {
        User.findOne({ name: name }).exec(function (err, user) {
            //console.log(user);
            if (user) {
                errors.push({ msg: "this user name already been registered" });
                //console.log('email already been registered');
                res.render('register', {
                    errors: errors,
                    name: name,
                    password: password,
                    password2: password2
                });
            }
            else {
                var secret = authenticator.generateSecret();
                const newUser = new User({
                    name: name,
                    password: password,
                    admin: (admin == 'admin')
                    //secret: secret
                });
                bcrypt.genSalt(10, function (err, salt) {
                    bcrypt.hash(newUser.password, salt, function (err, hash) {
                        if (err) {
                            throw err;
                        }
                        newUser.password = hash;
                        newUser.save()
                            .then(function (value) {
                                console.log(value);
                                //console.log(authenticator.keyuri(email,'MFA_App',secret));
                                QRcode.toDataURL(authenticator.keyuri(name, 'smartLock_proj', secret), function (err, url) {
                                    req.flash('success_msg', 'registered successfully');
                                    //console.log(url);
                                    req.session.qr = url;
                                    req.session.secret = secret;
                                    req.session.name = name;
                                    res.redirect('/dashboard');
                                })

                            })
                            .catch(function (value) {
                                console.log(value);
                            });
                    })
                })
            }
        })
    }
});

router.post('/rst_password', function (req, res) {
    const { original_password, new_password, c_password } = req.body;
    let errors = [];
    bcrypt.compare(original_password, req.user.password, function (err, isMatch) {
        if (err) {
            throw err;
        }
        if (isMatch) {
            if (original_password == new_password) {
                errors.push({ msg: 'new password can not be original password' });

            }
            if (c_password != new_password) {
                errors.push({ msg: 'Confirm password does not match' });

            }
            if (new_password.length < 6) {
                errors.push({ msg: 'New password is too short' });
            }
            if (errors.length > 0) {
                res.render('rst_password', {
                    errors: errors,
                    original_password: original_password,
                    new_password: new_password,
                    c_password: c_password
                });
            }
            else {
                User.findOne({ name: req.user.name }).exec(function (err, user) {
                    if (err) {
                        throw err;
                    }
                    bcrypt.genSalt(10, function (err, salt) {
                        bcrypt.hash(new_password, salt, function (err, hash) {
                            if (err) {
                                throw err;
                            }
                            user.password = hash;
                            user.save();
                            req.logout(function (err) {
                                if (err) {
                                    throw err;
                                }
                                res.redirect('/users/login')
                            });
                        })
                    })
                })
            }


        }
        else {
            errors.push({ msg: 'wrong password' });
            res.render('rst_password', {
                errors: errors,
                original_password: '',
                new_password: new_password,
                c_password: c_password
            });
        }
    })
})

router.post('/rm_user', function (req, res) {
    const { password, name } = req.body;
    let errors = [];
    bcrypt.compare(password, req.user.password, function (err, isMatch) {
        if (err) {
            throw err;
        }
        if (isMatch) {
            User.findOne({ name: name }).exec(function (err, user) {
                if (err) {
                    throw err;
                }
                if (user) {
                    user.delete();
                    return res.redirect('/dashboard');
                }
                else{
                    errors.push({ msg: 'no user with this name' });
                    return res.render('rm_user', {
                        errors: errors,
                        password: '',
                        name: ''
                    });
                }
            })
        }
        else {
            errors.push({ msg: 'wrong password' });
            res.render('rm_user', {
                errors: errors,
                password: '',
                name: name
            });
        }
    })
})

router.post('/rst_user_secret', function (req, res) {
    const { password, name } = req.body;
    let errors = [];
    bcrypt.compare(password, req.user.password, function (err, isMatch) {
        if (err) {
            throw err;
        }
        if (isMatch) {
            User.findOne({ name: name }).exec(function (err, user) {
                if (err) {
                    throw err;
                }
                if (user) {
                    user.secret = undefined;
                    user.save();
                    return res.redirect('/dashboard');
                }
                else{
                    errors.push({ msg: 'no user with this name' });
                    return res.render('rm_user', {
                        errors: errors,
                        password: '',
                        name: ''
                    });
                }
            })
        }
        else {
            errors.push({ msg: 'wrong password' });
            res.render('rm_user', {
                errors: errors,
                password: '',
                name: name
            });
        }
    })
})

router.post('/rst_secret',ensureAuthenticated, jwtmiddleware,function(req,res){
    User.findOne({name:req.user.name}).exec(function (err,user) {
        if (err) {
            throw err;
        }
        user.secret = undefined;
        user.save();
        res.redirect('/dashboard')
    })
})

router.post('/unlock',ensureAuthenticated, jwtmiddleware,function(req,res){
    ws.ws.send('true');
    //console.log(ws.getstatus())
    res.redirect('/dashboard');
})

router.post('/lock',ensureAuthenticated, jwtmiddleware,function(req,res){
    ws.ws.send('false');
    //console.log(ws.getstatus())
    res.redirect('/dashboard');
})
module.exports = router;