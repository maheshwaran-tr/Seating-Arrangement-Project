const jwt = require('jsonwebtoken');
const User = require('../models/User');

const verifyJWT = (req, res, next) => {
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (!authHeader?.startsWith('Bearer ')) return res.sendStatus(401);
    const token = authHeader.split(' ')[1];
    jwt.verify(
        token,
        "5832b56285ae114f7c64644cc44d2cd2d08d6c693c67832d3a33ad2c440517a403e29634165d10027daa4c91d579bb8bf55e944cac41661c2dfe1ddf4d7e053d31e0019375c740ecb19c339881836d80b666ba7ac68626322e6be785ff9369d8541a86fa66eced4fa8ed85c0c484a0c16cce3e12ca2481fee65b0cbf73c181d3620499ab32184914740db7eb7a457fd9d3c5d5d2d6e5b1a70777622ffe0ca3b79f395cc2458b8f689b882bae89e4e4d81b965740defc24f090908a7515f0c260a8b333211f1f4b7d49d97b399e16e6b380cb8aa55c3217f7a417aa02900aef0d3d370eec5d49533226b45e8c871ed19e0cbea8e1d86c05dfb6b428f542cd14ad",
        async (err, decoded) => {
            if (err) return res.sendStatus(403); // invalid token
            try {
                req.user = await User.findById(decoded.id).select('-password');
                next();
            } catch (error) {
                res.status(500).json({ 'message': error.message });
            }
        });
}

module.exports = verifyJWT;