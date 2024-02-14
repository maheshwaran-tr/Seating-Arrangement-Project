const User = require('../models/User');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const handleLogin = async (req, res) => {
    const { user, pwd } = req.body;
    if (!user || !pwd) return res.status(400).json({ 'message': 'Username and password are required.' });

    const foundUser = await User.findOne({ username: user }).exec();
    if (!foundUser) return res.sendStatus(401);

    // evaluate password
    const match = await bcrypt.compare(pwd, foundUser.password);

    if (match) {
        const accessToken = jwt.sign({ id: foundUser._id }, "5832b56285ae114f7c64644cc44d2cd2d08d6c693c67832d3a33ad2c440517a403e29634165d10027daa4c91d579bb8bf55e944cac41661c2dfe1ddf4d7e053d31e0019375c740ecb19c339881836d80b666ba7ac68626322e6be785ff9369d8541a86fa66eced4fa8ed85c0c484a0c16cce3e12ca2481fee65b0cbf73c181d3620499ab32184914740db7eb7a457fd9d3c5d5d2d6e5b1a70777622ffe0ca3b79f395cc2458b8f689b882bae89e4e4d81b965740defc24f090908a7515f0c260a8b333211f1f4b7d49d97b399e16e6b380cb8aa55c3217f7a417aa02900aef0d3d370eec5d49533226b45e8c871ed19e0cbea8e1d86c05dfb6b428f542cd14ad", { expiresIn: '1h' });
        const refreshToken = jwt.sign({ id: foundUser._id }, "c2911980169c2e3e7301cb771e406aa93781b2995e050f2982d620e30ba60a1b880aee0a8d4ae027780ad91a03b36252629e9c85074dcf14fc5e16ebfed76dea8dbf7f1bd0b7c58158b910f85a3db45a4de99d4d02d0cb8697ac2d0ef60157db240bef9b47ce0114fc63c99755dc29caab6fb84fd7a6690af81c812fc19be47121b3c8d0c701fe80b007422655b03db88de3b4aec98d0390ed6ea19352f4d41ff4071aea9b155360a7cc96bd40f69b1649469ecfe3e0e2bd4eef552b8799de5aed2fe89bfa947d4f07e7d4e417225cadc5ee1421353133e531f99bca182b3b81f1cd29ac729229c6a8810bdc3cf375bc3ba8ee2924a15a39cc06fa9c935d484d", { expiresIn: '1d' });

        // saving refesh token with the current user
        foundUser.refreshToken = refreshToken;
        const result = await foundUser.save();
        console.log(result);

        // Creates Secure Cookie with refresh token
        res.cookie('jwt', refreshToken, { httpOnly: true, secure: true, sameSite: 'None', maxAge: 24 * 60 * 60 * 1000 });

        // Send the access token to user
        res.json({ accessToken });
    }
    else {
        res.sendStatus(401);
    }
}

module.exports = { handleLogin };