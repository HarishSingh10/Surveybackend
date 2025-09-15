const jwt = require('jsonwebtoken');

const createAccessToken = (payload) =>
    jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '5d' });

const createRefreshToken = (payload) =>
    jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '30d' });

module.exports = { createAccessToken, createRefreshToken };
