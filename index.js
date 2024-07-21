const express = require('express');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const redisClient = require('./redisClient');
const mongoose = require("mongoose");
const MongoStore = require('connect-mongo');
const app = express();
const Session = require("./Session");



const uri = 'mongodb+srv://Aniket4611:Aniket20@nikicoin.boz57.mongodb.net/diadema_api_layer?retryWrites=true&w=majority';
const dbConnection = () => {
  try {
    mongoose.connect(uri).then(console.log("Database Connected"));
  } catch (e) {
    console.log("could not connect");
  }
};
dbConnection();



const sessionStore = MongoStore.create({
    mongoUrl: 'mongodb+srv://Aniket4611:Aniket20@nikicoin.boz57.mongodb.net/diadema_api_layer?retryWrites=true&w=majority',
    collectionName: 'sessions'
});

app.use(session({
    store: sessionStore,
    secret: 'your-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1800000 } // Session max age in milliseconds (30 minutes)
}));

const client = jwksClient({
    jwksUri: 'http://localhost:8080/realms/diadema-realm/protocol/openid-connect/certs'
});

function getKey(header, callback) {
    client.getSigningKey(header.kid, function(err, key) {
        const signingKey = key.publicKey || key.rsaPublicKey;
        callback(null, signingKey);
    });
}

function authenticateJWT(req, res, next) {
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const token = authHeader.split(' ')[1];
        jwt.verify(token, getKey, {
            audience:'diadema-api-client',
            issuer: 'http://localhost:8080/realms/diadema-realm'
        }, (err, user) => {
            if (err) {
                console.log(err);
                return res.sendStatus(403);
            }

            req.user = user;
            next();
        });
    } else {
        res.sendStatus(401);
    }
}

const crypto = require('crypto');

function hashEmail(email) {
    return crypto.createHash('sha256').update(email).digest('hex');
}



async function sessionManager(req, res, next) {
    const emailHash = hashEmail(req.user.email);
    let session = await Session.findOne({ emailHash });

    if (session) {
        const currentTime = Date.now();
        const inactiveTime = currentTime - session.lastActivity.getTime();

        if (inactiveTime > 1800000) { // 30 minutes in milliseconds
            await Session.deleteOne({ emailHash });
            res.status(401).json({ message: 'Session expired' });
        } else {
            session.lastActivity = new Date(currentTime);
            session.expiresAt = new Date(currentTime + 1800000); // Reset expiry to 30 minutes from now
            await session.save();
            next();
        }
    } else {
        session = new Session({
            emailHash,
            lastActivity: new Date(),
            accessToken: req.headers.authorization.split(' ')[1],
            userId: req.user.email,
            currentState:'dashboard',
            expiresAt: new Date(Date.now() + 1800000), // Set expiry to 30 minutes from now
        });
        await session.save();
        next();
    }
}
//app.use(authenticateJWT);
//app.use(sessionManager);

app.get('/api/dashboard', authenticateJWT,sessionManager, async(req, res) => {

    const emailHash = hashEmail(req.user.email);
    let session = await Session.findOne({ emailHash });

    session.currentState = 'dashboard';
    await session.save();
    res.json({message:"you are on dashboard, you can access case functionality"});

});


app.get('/api/cases', authenticateJWT,sessionManager, async(req, res) => {

    //console.log(req.route);
   // res.redirect(`http://localhost:8080/auth/realms/diadema-realm/protocol/openid-connect/auth?client_id=diadema-api-client&response_type=code&redirect_uri=http://localhost:4000/api/sessions`);

   const emailHash = hashEmail(req.user.email);
    let session = await Session.findOne({ emailHash });

   if(session.currentState == 'dashboard'){
    session.currentState = 'cases';
    await session.save();
    res.json({ message: 'Access granted to Diadema API', user: req.user });}
   else{
   res.json({message:"cannot access cases functionality"})
   }
});

app.get('/api/sessions', async (req, res) => {
    try {
        const sessions = await mongoose.connection.collection('sessions').find({}).toArray();
        res.json(sessions);
    } catch (err) {
        res.status(500).send('Failed to fetch sessions');
    }
});

app.listen(4000, () => {
    console.log('Diadema app listening on port 4000');
});
