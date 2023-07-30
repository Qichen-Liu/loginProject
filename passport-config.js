const LocalStrategy = require('passport-local').Strategy
const bcrypt = require('bcrypt')

function initialize(passport, getUserByEmail, getUserById) {

    // core authentication logic for the local strategy
    // done is a callback provided by Passport.js to indicate the result of the authentication process
    const authenticateUser = async (email, password, done) => {
        const user = getUserByEmail(email)
        if (user == null) {
            return done(null, false, { message: 'No user with that email' })
        }

        try {
            if (await bcrypt.compare(password, user.password)) {
                // password matches, return with no error and the user
                return done(null, user)
            } else {
                return done(null, false, { message: 'Password incorrect' })
            }
        } catch (e) {
            return done(e)
        }
    }

    // use local strategy
    passport.use(new LocalStrategy({ usernameField: 'email' }, authenticateUser))

    // store user in session by user id
    passport.serializeUser((user, done) => done(null, user.id))
    
    // deserializeUser function is used to specify how to retrieve the user object 
    // from the session based on the stored ID. It calls the getUserById(id) 
    // function provided earlier to fetch the user object by ID.
    passport.deserializeUser((id, done) => {
        return done(null, getUserById(id))
    })
}

module.exports = initialize