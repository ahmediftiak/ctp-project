const bcrypt = require("bcryptjs");
const passport = require("passport");
const LocalStrategy = require('passport-local');

const { User } = require('../models');

function passwordMatch(submittedPassword, storedPasswordHash) {
    return bcrypt.compareSync(submittedPassword, storedPasswordHash);
}

passport.use(new LocalStrategy(
    {
        usernameField: 'email',
        passworldField: 'password',
    },
    (email, password, done) => {
        User.findOne({ where: { email } })
            .then((user) => {
                if (!user) {
                    console.log('\n\nFailed Login: user does not exist\n\n');
                    return done(null, false, { message: 'Failed Login' });
                }
                if (passwordMatch(password, user.passwordHash) === false) {
                    console.log('\n\nFailed Login: password does not match\n\n');
                    return done(null, false, { message: 'Failed Login' });
                }

                console.log('\n\nSuccessful Login\n\n');
                return done(null, user, { message: 'Successfully Logined In!' });
            })
            .catch(err => { return done(err) });
    })
);

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    User.findByPk(id)
    .then((user) => {
        if(!user) {
            done(null, false);
            return;
        }

        done(null, user);
        return;
    })
    .catch(err => done(err, null));
});

passport.isAuthenticated = () => 
    (req, res, next) => (req.user ? next() : res.sendStatus(401));

module.exports = passport;
