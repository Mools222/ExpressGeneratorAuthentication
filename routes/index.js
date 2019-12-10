var express = require('express');
var router = express.Router();

// [Import fs]
let fs = require('fs').promises;

// [Import bcrypt]
let bcrypt = require('bcrypt');
const SALT_ROUNDS = 10;

// [Import multer]
const multer = require('multer');
const upload = multer({
    dest: '../public/images',
    limits: {
        fileSize: 4 * 1024 * 1024, // [max file size = 4 mb]
    },
});

function redirectIfLoggedIn(req, res, next) {
    if (req.session.user)
        return next();
    return res.render('index', {page: 'Start'});
}

// Get homepage
router.get('/', redirectIfLoggedIn, function (req, res, next) {
    // console.log('Cookies: ' + req.cookies);
    // console.log('Cookies connect.sid: ' + req.cookies["connect.sid"]);
    // console.log('Sessions id: ' + req.session.id);
    // console.log('Sessions cookie expires: ' + req.session.cookie._expires);

    // if (req.session.user) {
        res.render('index', {
            page: 'Start',
            user: req.session.user.userName,
            password: req.session.user.password,
            expirationDate: req.session.cookie._expires
        });
    // } else {
    //     res.render('index', {page: 'Start'});
    // }
});

// Handle logins
router.post('/', async function (req, res, next) {
    console.log(req.body);

    let userObject = await checkLogin(req.body.login, req.body.password); // "login" is undefined if no such login is found - Otherwise the login object (which contains the user name and password) is returned

    if (userObject) { // If the login is undefined, it is converted to false. If it contains something, it is converted to true (https://www.w3schools.com/js/js_type_conversion.asp)
        console.log(`User logged in. User name: "${req.body.login}". Password: "${req.body.password}".`);

        // Save user to session
        req.session.user = {userName: userObject.login, password: userObject.password, avatar: userObject.avatar};

        // Redirect
        res.status(200).redirect('/');
    } else {
        console.log(`Someone failed to log in. User name: "${req.body.login}". Password: "${req.body.password}".`);

        res.render('index', {error: "Error: Wrong user name and/or password."})
    }
});

// Show account details
router.get('/account', redirectIfLoggedIn, function (req, res, next) {
    // if (req.session.user) {
        res.render('account', {
            page: 'Account',
            user: req.session.user.userName,
            password: req.session.user.password,
            avatar: req.session.user.avatar,
            expirationDate: req.session.cookie._expires
        });
    // } else {
    //     res.status(200).redirect('/');
    // }
});


// Handle logouts
router.get('/logout', function (req, res, next) {
    req.session.destroy(function (err) {
        console.log("User logged out.")
    });
    res.status(200).redirect('/');
});

// Get create user page
router.get('/create', function (req, res, next) {
    if (req.session.user)
        return res.status(200).redirect('/');

    return res.render('createuser', {page: 'Register'});
});

// Handle create user request
router.post('/create', upload.single('avatar'), async function (req, res, next) {
    console.log(req.body);

    let userCreated = await createNewUser(req.body.login, req.body.password, (req.file ? req.file.path : null));

    if (userCreated === "User created.") {
        // res.redirect('/create?success=true');
        res.render('createuser', {page: 'Register', success: "Success: " + userCreated});
    } else {
        // res.redirect('/create?success=false');
        res.render('createuser', {page: 'Register', error: userCreated});
    }
});

async function checkLogin(userName, password) {
    let data = await fs.readFile("../logins.json");

    let loginsArray = JSON.parse(data);

    for (let i = 0; i < loginsArray.length; i++) {
        if (loginsArray[i].login === userName && await bcrypt.compare(password, loginsArray[i].password))
            return loginsArray[i];
    }
}

async function createNewUser(userName, password, avatarFilePath) {
    if (userName.length < 1)
        return "User name must be over 1 character long.";

    let data = await fs.readFile("../logins.json");
    let loginsArray = JSON.parse(data);

    for (let i = 0; i < loginsArray.length; i++) {
        if (loginsArray[i].login === userName)
            return "Duplicate user names cannot exist.";
    }

    // Hash password
    password = await bcrypt.hash(password, SALT_ROUNDS);

    loginsArray.push({
        id: loginsArray.length + 1,
        login: userName,
        password: password,
        avatar: (avatarFilePath ? avatarFilePath.slice(10) : null)
    });
    await fs.writeFile("../logins.json", JSON.stringify(loginsArray));
    return "User created.";
}

async function getUserById(userId) {
    let data = await fs.readFile("../logins.json");
    let loginsArray = JSON.parse(data);

    for (let i = 0; i < loginsArray.length; i++) {
        if (loginsArray[i].id === userId)
            return loginsArray[i];
    }
}

module.exports = router;
