const express = require('express');
const router = express.Router();
const { expressjwt: expressJWT } = require('express-jwt');
const secretkey_gen = require('../models/secret_gen');
const { ensureAuthenticated } = require("../config/auth.js");
const ws = require('../models/websocket');
const jwtmiddleware = expressJWT({
    secret: secretkey_gen.secretkey,
    algorithms: ['HS256'],
    getToken: function (req) {
        return req.session.token;
    }
})
router.get('/', function (req, res) {
    res.render('welcome');
});

router.get('/register', function (req, res) {
    res.render('register');
});

router.get('/dashboard', ensureAuthenticated,jwtmiddleware, function (req, res) {
    ws.ws.send('get');
    var st = ws.getstatus();
    console.log('lock status:'+st);
    res.render('dashboard', { user: req.user ,status: st});
})
module.exports = router;