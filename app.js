require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const favicon = require('serve-favicon')
//const encrypt = require("mongoose-encryption"); // - Encrytion
//const md5 = require("md5"); // - Hashing
//const bcrypt = require("bcrypt"); // - Salting & Hashing
//const saltRounds = 10;

const session = require("express-session");
const passportLocalMongoose = require("passport-local-mongoose"); // This package will salt and hash our passwords automatically without us having to do anything
const passport = require("passport");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");
const FacebookStrategy = require("passport-facebook");

const app = express();
app.use(favicon(__dirname + '/public/favicon.ico'));
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
    secret: "Let me tell you my secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb+srv://admin-rahul:rahul3148@cluster0.wb3xjbv.mongodb.net/usersDB");

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    username: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// ENCRYPTION
//userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());


// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

passport.serializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, {
            id: user.id,
            username: user.username,
            picture: user.picture
        });
    });
});

passport.deserializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "https://rocky-plateau-17810.herokuapp.com/auth/google/secrets",
    //userProfileURL: "http://www.googleapis.com/oauth2/v3/userinfo"
},
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ username: profile.displayName, googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "https://rocky-plateau-17810.herokuapp.com/auth/facebook/secrets"
},
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ username: profile.displayName, facebookId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

app.get("/", function (req, res) {
    res.render("home");
});

app.get("/auth/google",
    passport.authenticate("google", { scope: ["profile"] })
);

app.get('/auth/facebook',
    passport.authenticate('facebook'));


app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect('/secrets');
    });

app.get('/auth/facebook/secrets',
    passport.authenticate('facebook', { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect('/secrets');
    });


app.get("/login", function (req, res) {
    res.render("login");
});

app.post("/login", function (req, res) {
    const userName = req.body.username;
    const passWord = req.body.password;

    const user = new User({
        username: userName,
        password: passWord
    });

    req.login(user, function (err) {
        if (!err) {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            });
        }
    });
    // const password = md5(req.body.password); -- USING md5 Hashing

    // Salting & Hashing
    // User.findOne({ email: username }, function (err, foundUser) {
    //     if (err) {
    //         console.log(err);
    //     }
    //     else {
    //         if (foundUser) {
    //             bcrypt.compare(password, founduser.password, function (err, result) {
    //                 if (result === true) {
    //                     res.render("secrets");
    //                 }
    //             });
    //         }
    //         else {

    //         }
    //     }
    // });
});

app.get("/register", function (req, res) {
    res.render("register");
});

app.get("/secrets", function (req, res) {
    if (!req.isAuthenticated()) {
        res.redirect("/login");
    }
    User.find({ "secret": { $ne: null } }, function (err, foundUsers) {
        if (err) {
            console.log(err);
        }
        else {
            if (foundUsers) {
                res.render("secrets", { userWithSecrets: foundUsers });
            }
        }
    });
});

app.get("/submit", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("submit");
    }
    else {
        res.redirect("/login");
    }
});

app.post("/submit", function (req, res) {
    const submittedSecret = req.body.secret;

    User.findById(req.user.id, function (err, founduser) {
        if (err) {
            console.log(err);
        }
        else {
            if (founduser) {
                founduser.secret = submittedSecret;
                founduser.save(function () {
                    res.redirect("/secrets");
                })
            }
        }
    });
});

app.get("/logout", function (req, res) {
    req.logout(function (err) {
        if (err) {
            console.log(err);
        }
        else {
            res.redirect("/");
        }
    });

});

app.post("/register", function (req, res) {

    User.register({ username: req.body.username }, req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register")
        }
        else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            });
        }
    });

    // Salting & hashing
    // bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
    //     const newUser = new User({
    //         email: req.body.username,
    //         password: hash

    //     });

    //     newUser.save(function (err) {
    //         if (!err) {
    //             res.render("secrets");
    //         }
    //     });
    // });

    // const newUser = new User({
    //     email: req.body.username,
    //     // password: md5(req.body.password) -- Using md5 Hashing

    // });

    // newUser.save(function (err) {
    //     if (!err) {
    //         res.render("secrets");
    //     }
    // });
})

app.listen(process.env.PORT || 3000, function () {
    console.log("Server has started successfully.")
});