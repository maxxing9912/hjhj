// server.js (backend del sito)
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const path = require('path');
const bodyParser = require('body-parser');
const fetch = require('node-fetch');
const Stripe = require('stripe');

const app = express();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// ─────────────────────────────────────────────────────────────────
// 1) Configura express-session per memorizzare la sessione utente
// ─────────────────────────────────────────────────────────────────
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
}));

// ─────────────────────────────────────────────────────────────────
// 2) Inizializza Passport
// ─────────────────────────────────────────────────────────────────
app.use(passport.initialize());
app.use(passport.session());

// ─────────────────────────────────────────────────────────────────
// 3) Passport serialize/deserialize
// ─────────────────────────────────────────────────────────────────
passport.serializeUser((user, done) => {
  // Salviamo in sessione l’intero profilo Discord (per semplicità)
  done(null, user);
});
passport.deserializeUser((obj, done) => {
  done(null, obj);
});

// ─────────────────────────────────────────────────────────────────
// 4) Configura la strategia Discord (passport-discord)
// ─────────────────────────────────────────────────────────────────
passport.use(new DiscordStrategy({
    clientID: process.env.DISCORD_CLIENT_ID,
    clientSecret: process.env.DISCORD_CLIENT_SECRET,
    callbackURL: process.env.SITE_URL + '/auth/discord/callback',
    scope: ['identify']
  },
  (accessToken, refreshToken, profile, done) => {
    return done(null, profile);
  }
));

// ─────────────────────────────────────────────────────────────────
// 5) Middleware per proteggere le rotte (assicurarsi che l’utente sia loggato)
// ─────────────────────────────────────────────────────────────────
function ensureAuth(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/auth/discord');
}

// ─────────────────────────────────────────────────────────────────
// 6) Route per far partire il login Discord
// ─────────────────────────────────────────────────────────────────
app.get('/auth/discord', passport.authenticate('discord'));

// ─────────────────────────────────────────────────────────────────
// 7) Callback che Discord richiama dopo login
// ─────────────────────────────────────────────────────────────────
app.get(
  '/auth/discord/callback',
  passport.authenticate('discord', { failureRedirect: '/auth/failure' }),
  (req, res) => {
    // Login riuscito, reindirizziamo alla home (che usa ensureAuth)
    res.redirect('/');
  }
);

app.get('/auth/failure', (req, res) => {
  res.send('❌ Discord login failed. Riprova.');
});

// ─────────────────────────────────────────────────────────────────
// 8) Rotta principale “/” protegge con ensureAuth
//    Se l’utente è autenticato, serviamo il file index.html
// ─────────────────────────────────────────────────────────────────
app.get('/', ensureAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─────────────────────────────────────────────────────────────────
// 9) Altre rotte protette, ad es. /dashboard, /pricing, ecc.
//    Qui useremo solo “ensureAuth” per proteggere
// ─────────────────────────────────────────────────────────────────
app.get('/pricing.html', ensureAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'pricing.html'));
});

// ─────────────────────────────────────────────────────────────────
// 10) Endpoint STATICI per tutta la cartella “public”
// ─────────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

// ─────────────────────────────────────────────────────────────────
// 11) CHIAMATA AJAX get “/api/me” (il bot ne ha uno suo; questo ritorna solo i dati di sessione)
//     NB: nel front-end di index.html e pricing.html userai questo endpoint
// ─────────────────────────────────────────────────────────────────
app.get('/api/me', ensureAuth, (req, res) => {
  const user = req.user; // contiene { id, username, discriminator, avatar, ... }
  res.json({
    id: user.id,
    username: user.username,
    discriminator: user.discriminator,
    avatar: user.avatar
  });
});

// ─────────────────────────────────────────────────────────────────
// 12) ROUTE per creare la sessione Stripe Checkout
//     Qui memorizziamo nel metadata di Checkout l’ID Discord dell’utente
// ─────────────────────────────────────────────────────────────────
app.post('/create-checkout-session', ensureAuth, express.json(), async (req, res) => {
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'payment',
      line_items: [
        {
          price_data: {
            currency: 'eur',
            product_data: {
              name: 'Clarivex Premium (lifetime access)'
            },
            unit_amount: 399, // €3.99 → 399 centesimi
          },
          quantity: 1,
        }
      ],
      // Durante il redirect, includiamo i meta “discordId” per il webhook
      success_url: `${process.env.SITE_URL}/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.SITE_URL}/pricing.html`,
      metadata: {
        discordId: req.user.id
      }
    });

    return res.json({ sessionId: session.id });
  } catch (err) {
    console.error('[create-checkout-session] Errore:', err);
    return res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────
// 13) WEBHOOK di Stripe: riceve l’evento “checkout.session.completed”
//     Quando arriva, salviamo is_premium nel DB del sito e invochiamo il bot
// ─────────────────────────────────────────────────────────────────
app.post('/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  let event;
  try {
    const signature = req.headers['stripe-signature'];
    event = stripe.webhooks.constructEvent(req.body, signature, process.env.STRIPE_ENDPOINT_SECRET);
  } catch (err) {
    console.error('[stripe-webhook] Firma non valida:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const discordId = session.metadata.discordId;
    console.log(`[stripe-webhook] session completed per Discord ID: ${discordId}`);

    // 1) Qui potresti salvare sul tuo DB “utente con discordId è premium”
    //    (ad esempio: db.users.update({ discordId }, { is_premium: true }); )
    //    PER LO SCENARIO DI TEST USIAMO SOLO console.log
    console.log(`[sito-db] set is_premium = true per ${discordId}`);

    // 2) Chiamiamo il bot-webhook per impostare in QuickDB “premiumUser_<discordId> = true”
    try {
      await fetch(process.env.BOT_WEBHOOK_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ discordId, premium: true })
      });
      console.log(`[sito → bot] Notificato bot che ${discordId} è Premium`);
    } catch (err) {
      console.error('[sito → bot] Errore chiamando bot-webhook:', err);
    }
  }

  res.sendStatus(200);
});

// ─────────────────────────────────────────────────────────────────
// Lancio del server sul porto specificato in .env (es. 4242)
// ─────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 4242;
app.listen(PORT, () => {
  console.log(`🌐 Sito listening on http://localhost:${PORT}`);
});