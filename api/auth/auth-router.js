const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { jwtSecret } = require("./../secrets/index"); // use this secret!
const bcryptjs = require('bcryptjs')

const Users = require('./../users/users-model');
const {isValid} = require('./../users/users-services')
const {buildToken} = require('./buildToken')

router.post("/register", validateRoleName, (req, res, next) => {
  const credentials = req.body;

    const rounds = process.env.BCRYPT_ROUNDS || 8

    const hash = bcryptjs.hashSync(credentials.password, rounds)

    credentials.password = hash

    Users.add(credentials)
      .then(user=>{
        res.status(201).json(user)
      })
      .catch(next)
  
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
});


router.post("/login", checkUsernameExists,  (req, res, next) => {
  const { username, password } = req.body

  if(isValid(req.body)){
    Users.findBy({username: username})
      .then(([user])=>{
        if(user && bcryptjs.compareSync(password, user.password)){
          const token = buildToken(user)
          res.status(200).json({message: `${username} is back`, token})
        } else {
          res.status(401).json({message: 'These are Invalid credentials'})
        }
      })
      .catch(next)
  } else {
    res.status(400).json({
      message: "Please Don't Provide User Name And Password"
    })
  }
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});

module.exports = router;
