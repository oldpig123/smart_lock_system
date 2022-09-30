const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const UserSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    admin: {
        type: Boolean,
        required: true,
        default: false
    },
    password: {
        type: String,
        required: true
    },
    secret: {
        type: String,
        require: true
    },
    date: {
        type: Date,
        default: Date.now
    }
});
const User = mongoose.model('User', UserSchema);
User.findOne({ name: 'admin' }).exec(function (err, user) {
    if (!user) {
        bcrypt.genSalt(10, function (err, salt) {
            bcrypt.hash('admin', salt, function (err, hash) {
                if (err) {
                    throw err;
                }
                var newUser = new User({
                    name: 'admin',
                    admin: true,
                    //secret: secret
                });
                newUser.password = hash;
                newUser.save();
                //console.log(newUser);
                console.log('admin user init')
            })
        })

    }
})

module.exports = User;