const express = require('express');
const router = express.Router();
const app = express();
const mongoose = require('mongoose');
const expressEjsLayout = require('express-ejs-layouts');
const session = require('express-session');
const flash = require('connect-flash');
const passport = require('passport');
var https = require('https');
var fs = require('fs');
const https_options = {
    key: fs.readFileSync('../key.pem'),
    cert: fs.readFileSync('../cert.pem')
};
require('./config/passport')(passport);

mongoose.connect('mongodb://localhost/test',{useNewUrlParser: true, useUnifiedTopology: true})
.then(function (){console.log('connected,,')})
.catch(function (err){ console.log(err)});

app.set('view engine','ejs');
app.use(expressEjsLayout);

app.use(express.urlencoded({extended : false}));

app.use(session({
    secret:'secret',
    resave:true ,
    saveUninitialized : true,
    cookie:{
        maxAge: 300000
    }
}));

app.use(passport.initialize());
app.use(passport.session());

app.use(flash());
app.use(function (req,res,next) {
    res.locals.success_msg = req.flash('success_msg');
    res.locals.error_msg = req.flash('error_msg');
    res.locals.error = req.flash('error');
    next();
});


app.use('/',require('./routes/index'));
app.use('/users',require('./routes/users'));
app.use('/userop',require('./routes/userop'));

app.listen(3000);
https.createServer(https_options,app).listen(8000);