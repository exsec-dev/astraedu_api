const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const authMiddleware = require('./authMiddleware');
const fs = require('fs');
const router = express.Router();

const generateAccessToken = (username) => {
    const payload = { username };
    return jwt.sign(payload, process.env.SECRET, { expiresIn: '72h' });
}

const encrypt = async (pass) => {
    const saltRounds = 10;
    const hash = await bcrypt.hash(pass, saltRounds);
    return hash;
}

const compare = async (passToCheck, hash) => {
    const isEqual = await bcrypt.compare(passToCheck, hash);
    return isEqual;
}

const getUser = async (pool, username, callback) => {
    pool.query('SELECT * FROM users WHERE username = ?', [username], (error, results) => {
        if (error) {
            console.error('Error getting user: ' + error.stack);
            callback(null, error);
        } else {
            if (results.length > 0) {
                callback(true, results[0]);
            } else {
                callback(false, null);
            }
        }
    });
}

module.exports = (pool) => {

    router.get('/users', (req, res) => {
        pool.query('SELECT * FROM users', (error, results) => {
            if (error) {
                console.error('GET error: ' + error.stack);
                res.status(500).json({ message: 'Произошла ошибка при получении пользователей' });
            } else {
                res.json(results);
            }
        });
    });

    router.get('/user', authMiddleware, (req, res) => {
        const { user } = req;
        pool.query('SELECT * FROM users WHERE username = ?', [user], (error, results) => {
            if (error) {
                console.error('GET error: ' + error.stack);
                res.status(500).json({ message: 'Произошла ошибка при получении пользователей' });
            } else {
                res.json(results[0]);
            }
        });
    });

    // Register user
    router.post('/register', (req, res) => {
        const { username, password } = req.body;

        getUser(pool, username, (isUserExists, data) => {
            if (isUserExists === false) {
                encrypt(password).then((hash) => {
                    const imageData = fs.readFileSync('./icons/avatar.jpg');
                    const query = `
                        INSERT INTO users (username, password, date)
                        VALUES (?, ?, ?);

                        INSERT INTO userdata (username, points, coins, achievements, favorite_achievement, avatar)
                        VALUES (?, ?, ?, ?, ?, ?);
                    `;
                    const values = [
                        [username, hash, (new Date()).toLocaleString()],
                        [username, 0, 0, JSON.stringify(["quick_start"]), "quick_start", imageData]
                    ];
                    pool.query(query, values, (error, results) => {
                        if (error) {
                            console.error('Error adding new user ' + error.stack);
                            res.status(500).send('Error adding new user ' + error.stack);
                        } else {
                            const token = generateAccessToken(username);
                            res.status(201).json({ token });
                        }
                    });
                })
                .catch((error) => {
                    console.error('Error encrypting pass ' + error);
                    res.status(500).send('Error encrypting pass ' + error);
                });
            } else if (isUserExists === true) {
                res.status(409).json({ message: 'Такой пользователь уже существует' });
            } else {
                res.status(500).send('Error checking if user exists: ' + data);
            }
        });
    });

    // User login
    router.post('/login', (req, res) => {
        const { username, password } = req.body;
        
        getUser(pool, username, (isUserExists, data) => {
            if (isUserExists === true) {
                compare(password, data?.password).then((isEqual) => {
                    if (isEqual) {
                        const token = generateAccessToken(username);
                        res.status(201).json({ token });
                    } else {
                        res.status(401).json({ message: 'Неверный логин или пароль' });
                    }
                }).catch((error) => {
                    console.error('Error comparing pass ' + error);
                    res.status(500).send('Error comparing pass ' + error);
                });
            } else if (isUserExists === false) {
                res.status(401).json({ message: 'Неверный логин или пароль' });
            } else {
                res.status(500).send('Error checking if user exists: ' + data);
            }
        });
    });

    return router;
};