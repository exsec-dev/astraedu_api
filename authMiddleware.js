const jwt = require('jsonwebtoken');

module.exports = function (req, res, next) {
    try {
        const token = req.headers.authorization.split(' ')[1];
        if (!token) {
            console.error('Not authorized', e);
            return res.status(403).json({ message: 'Пользователь не авторизован' });
        }
        const decoded = jwt.verify(token, process.env.SECRET);
        req.user = decoded.username;
        next();
    } catch (e) {
        console.error('Not authorized', e);
        return res.status(403).json({ message: 'Пользователь не авторизован' });
    }
};