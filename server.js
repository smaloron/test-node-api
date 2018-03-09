const fs = require('fs');
const bodyParser = require('body-parser');
const jsonServer = require('json-server');
const jwt = require('jsonwebtoken');

const server = jsonServer.create();
const router = jsonServer.router('./data.json');
const userdb = JSON.parse(fs.readFileSync('./users.json', 'UTF-8'));


server.use(jsonServer.defaults());

server.use(bodyParser.urlencoded({extended: true}));
server.use(bodyParser.json());

const SECRET_KEY = '123456789';
const expiresIn = '1h';

function createToken(payload){
    return jwt.sign(payload, SECRET_KEY, {expiresIn})
}

function verifyToken(token){
    return  jwt.verify(token, SECRET_KEY, (err, decode) => decode !== undefined ?  decode : err)
}

function getUser({email, password}) {
    user = userdb.users.find( user => {
        return user.email === email && user.password === password
    });
    return user;
}


server.post('/auth/login', (req, res) => {
    const {email, password} = req.body;
    let user = getUser({email, password});
    if (! user) {
        const status = 401;
        const message = 'Non autorisé';
        res.status(status).json({status, message});
        return
    }
    const access_token = createToken({email, password, id:user.id});
    res.status(200).json({access_token})
});

server.post('/auth/register', (req, res) => {
    const {email, password} = req.body;
    let user = getUser({email, password});
    if (! user) {
        const id= new Date().getTime();
        user = {user, password, id};
        userdb.users.push(user);
        fs.writeFileSync('./users', JSON.stringify(userdb), "UTF-8");
        const access_token = createToken(user);
        res.status(200).json({access_token});
        return
    }
    const status = 401;
    const message = 'Utilisateur déjà existant';
    res.status(status).json({status, message});

});

//Sécurisation des routes autres que /auth
server.use(/^(?!\/auth).*$/,  (req, res, next) => {
    if (req.headers.authorization === undefined || req.headers.authorization.split(' ')[0] !== 'Bearer') {
        const status = 401;
        const message = 'authorisation non valide';
        res.status(status).json({status, message});
        return
    }
    try {
        verifyToken(req.headers.authorization.split(' ')[1]);
        next()
    } catch (err) {
        const status = 401;
        const message = 'token non valide';
        res.status(status).json({status, message})
    }
});

server.use(router);

//Lancer le serveur avec npm run start-auth
server.listen(3000, () => {
    console.log('Serveur en route')
});

