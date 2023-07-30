if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config()
}

const express = require('express')
const app = express()
const bcrypt = require('bcrypt')
const passport = require('passport')
const flash = require('express-flash')
const session = require('express-session')
const methodOverride = require('method-override')
const initializePassport = require('./passport-config')
const uuid = require('uuid');
const nodemailer = require('nodemailer');


// get by email
// get by id
initializePassport(
    passport,
    email => users.find(user => user.email === email),
    id => users.find(user => user.id === id)
)

const users = []

app.set('view-engine', 'ejs')
app.use(express.urlencoded({ extended: false }))
app.use(flash())
app.use(session(
    {
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false
    }
))

app.use(passport.initialize())
app.use(passport.session())
app.use(methodOverride('_method'))

app.get('/', checkAuthenticated, (req, res) => {
    res.render('index.ejs', { name: req.user.name })
})

app.get('/login', checkNotAuthenticated, (req, res) => {
    res.render('login.ejs')
})

// app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
//     successRedirect: '/',
//     failureRedirect: '/login',
//     failureFlash: true
// }))

app.post('/login', checkNotAuthenticated, async (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) {
            return next(err);
        }
        if (!user) {
            return res.redirect('/login');
        }

        // Check if the user is verified
        if (!user.verified) {
            return res.status(401).send('Please verify your email before logging in.');
        }

        req.logIn(user, (err) => {
            if (err) {
                return next(err);
            }
            return res.redirect('/');
        });
    })(req, res, next);
});


app.get('/register', checkNotAuthenticated, (req, res) => {
    res.render('register.ejs')
})

const transporter = nodemailer.createTransport({
    // Set up your email transport configuration here (e.g., Gmail, SMTP, etc.)
    // For example:
    service: 'Gmail',
    auth: {
        user: 'qichen2534@gmail.com',
        pass: 'disckxwnfghcyfba',
    },
});

app.post('/register', checkNotAuthenticated, async (req, res) => {
    try {

        const { name, email, password } = req.body;
        const existingUser = users.find((user) => user.email === email);
        if (existingUser) {
            return res.status(400).json({ message: 'Email already registered.' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const verificationToken = uuid.v4(); // Generate a unique verification token
        users.push({
            id: Date.now().toString(),
            name: name,
            email: email,
            password: hashedPassword,
            verified: false, // Add a 'verified' field to the user object
            verificationToken, // Add the verification token to the user object
        });

        // Send the verification email
        const mailOptions = {
            from: 'qichen2534@gmail.com',
            to: req.body.email,
            subject: 'Email Verification',
            html: `    
        <h1>Welcome to DataLynn</h1>
        <p>Please click the following link to verify your email:</p>
        <a href="http://localhost:3000/verify/${verificationToken}">Verify Email</a>
      `,
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.log(error);
            } else {
                console.log('Email sent: ' + info.response);
            }
        });

        res.redirect('/login');
    } catch (error) {
        res.redirect('/register');
    }
    console.log(users);
});

app.get('/verify/:token', async (req, res) => {
    try {
        const { token } = req.params;

        // Find the user with the verification token
        const user = users.find((user) => user.verificationToken === token);

        if (!user) {
            return res.status(404).send('Invalid verification token.');
        }

        // Mark the user as verified
        user.verified = true;

        // Remove the verification token (optional, as it won't be used again)
        delete user.verificationToken;
        console.log(user)

        res.send('Email verified successfully. You can return to login');
    } catch (error) {
        res.status(500).send('Error verifying email.');
    }
});


app.delete('/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            // Handle any error that occurred during logout
            return res.status(500).send('Error logging out.');
        }

        // Redirect the user to a different page or perform any other actions after logout
        res.redirect('/login'); // For example, redirect to the login page
    });
});

// {middleware functions}
function checkAuthenticated(req, res, next) {
    // if logged in
    if (req.isAuthenticated()) {
        return next()
    }
    // else
    res.redirect('/login')
}

function checkNotAuthenticated(req, res, next) {
    // if authenticated already, redirect them
    if (req.isAuthenticated()) {
        return res.redirect('/')
    }
    next()
}

app.listen(3000)