require('dotenv').config();
const express = require('express');
const app = express();
const massive = require('massive');
const session = require('express-session');
const bcrypt = require('bcryptjs');

const { SERVER_PORT, DB_STRING, SESSION_SECRET } = process.env;

app.use(express.json());

app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUnitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24
    }
}));

massive(DB_STRING).then(db => {
    app.set('db', db);
    console.log('DB connected');
}).catch(err => console.log(err));

// auth endpoints
app.post('/auth/register', (req, res) => {
    const { username, password } = req.body;
    const db = req.app.get('db');

    db.checkForUser(username).then(user => {
        console.log(user)
        
        if(!user[0]) {
            const salt = bcrypt.genSaltSync(10)

            bcrypt.hash(password, salt).then(hash => {

                db.addUser(username, hash).then(user => {
                    console.log(user)

                    req.session.user = {...user[0]};

                    console.log(req.session.user)

                    res.status(200).json(req.session.user);
                })
            })
        } else {
            res.status(409).json({error: "Username is taken"})
        }
    })
});

app.post('/auth/login', async (req, res) => {
    const { username, password } = req.body;
    const db = req.app.get('db');

    const hash = await db.checkUser(username);
    console.log(hash);

    const doesMatch = bcrypt.compareSync(password, hash[0].hash);

    if (doesMatch) {
        const foundUser = await db.checkForUser(username);

        req.session.user = {...foundUser[0]}

        res.status(200).json(req.session.user);
    } else {
        res.status(409).json({error: "Username or Password incorrect!"})
    }
});

app.listen(SERVER_PORT, () => console.log(`Server listening on ${SERVER_PORT}`));