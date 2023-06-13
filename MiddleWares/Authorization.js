const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
dotenv.config();
//Import of models
// Middleware function for JWT verification
function authenticateToken(req, res, next) {
    // Get the token from the request headers or query parameters
    const token = req.headers['authorization'].split(" ")[1] || req.query.token.split(" ")[1];
    let jwtSecretKey = process.env.JWT_SECRET_KEY;
  
    if (!token) {
      // Token is missing
      return res.status(401).json({ error: 'Authentication token missing' });
    }
  
    // Verify the token using the secret key
    jwt.verify(token, jwtSecretKey, (err, user) => {
      if (err) {
        // Token verification failed
        return res.status(403).json({ error: 'Invalid token' });
      }
    
      // Token is valid, attach the user object to the request for further use
      req.user = user;
      next();
    });
  }


  module.exports = authenticateToken;