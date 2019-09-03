const bcrypt = require('bcryptjs')
const Users = require('../users/users-model.js');

module.exports = restricted

// MIDDLEWARE TO CHECK CREDENTIALS
function restricted(req, res, next) {
  let { username, password } = req.headers;

  if(username && password) {

    Users.findBy({ username })
    .first()
    .then(user => {
      
      // CHECK IF PASSWORD IS MATCHING PASSWORD IN DB SAVED WHEN REGISTERED
      if (user && bcrypt.compareSync(password, user.password)) {
        next()
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
      
    })
    .catch(error => {
      res.status(500).json(error);
    });

  } else {
    res.status(400).json({ message: 'please provide valid credentials'})
  }
}
