const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs')

const db = require('./database/dbConfig.js');
const Users = require('./users/users-model.js');
const restricted = require('./auth/restricted-middleware')

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.get('/', (req, res) => {
  res.send("It's alive!");
});

// REGISTER - HASHING PASSWORD HERE
server.post('/api/register', (req, res) => {
  let user = req.body;

  // HASH PASSWORD
  const hash = bcrypt.hashSync(user.password) 
  user.password = hash

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});


// LOGIN - CHECKING HASH PASSWORD HERE
server.post('/api/login', (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
          
        // CHECK IF PASSWORD IS MATCHING PASSWORD IN DB SAVED WHEN REGISTERED
      if (user && bcrypt.compareSync(password, user.password)) {
        res.status(200).json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }

    })
    .catch(error => {
      res.status(500).json(error);
    });
});



// CAN ONLY BE ACCESSED BY CLIENTS WITH VALID CREDENTIALS
server.get('/api/users', restricted, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});



// HASH A PASSWORD
server.post('/hash', (req, res) => {
    const password = req.body.password

    // hash the password
    // the second number is the rounds
     const hash = bcrypt.hashSync(password, 12) 
     res.status(200).json({ password, hash })
})




const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
