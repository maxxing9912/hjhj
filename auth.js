// auth.js (Express router)
const express = require('express');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
require('dotenv').config();

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

passport.use(new DiscordStrategy({
    clientID: process.env.DISCORD_CLIENT_ID,
    clientSecret: process.env.DISCORD_CLIENT_SECRET,
    callbackURL: `${process.env.SITE_URL}/auth/discord/callback`,
    scope: ['identify']
  },
  (accessToken, refreshToken, profile, done) => {
    // profile.id is the Discord user ID
    done(null, profile);
  }
));

const router = express.Router();
router.use(require('express-session')({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }));
router.use(passport.initialize());
router.use(passport.session());

// 1) Redirect to Discord for login
router.get('/discord', passport.authenticate('discord'));

// 2) Discord callback
router.get('/discord/callback',
  passport.authenticate('discord', { failureRedirect: '/login' }),
  (req, res) => {
    // On success: req.user contains { id, username, discriminator, avatar }
    res.redirect('/dashboard');
  }
);

module.exports = router;