const ws = require('../models/websocket')
module.exports = {
    ensureAuthenticated: function (req, res, next) {
        if (req.isAuthenticated()) {
            return next();
        }
        ws.ws.send('false');
        req.flash('error_msg', 'loging first');
        res.redirect('/users/login');
    }
}