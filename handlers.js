const express = require('express');
const bcrypt = require('bcrypt');
const router = express.Router();

const encrypt = async (pass) => {
    const saltRounds = 10;
    const hash = await bcrypt.hash(pass, saltRounds);
    return hash;
}

const compare = async (passToCheck, hash) => {
    const isEqual = await bcrypt.compare(passToCheck, hash);
    return isEqual;
}

const getUser = (pool, username, callback) => {
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
                res.status(500).send('Произошла ошибка при получении пользователей');
            } else {
                res.json(results);
            }
        });
    });

    // Adding new user
    router.post('/users', (req, res) => {
        const { username, password } = req.body;

        getUser(pool, username, (isUserExists, data) => {
            if (isUserExists === false) {
                encrypt(password).then((hash) => {
                    pool.query('INSERT INTO users (username, password, date) VALUES (?, ?, ?)', [username, hash, (new Date()).toLocaleString()], (error, results) => {
                        if (error) {
                            console.error('Error adding new user ' + error.stack);
                            res.status(500).send('Error adding new user ' + error.stack);
                        } else {
                            res.status(201).send('Ok');
                        }
                    });
                })
                .catch((error) => {
                    console.error('Error encrypting pass ' + error);
                    res.status(500).send('Error encrypting pass ' + error);
                });
            } else if (isUserExists === true) {
                res.status(409).send('User already exists');
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
                        res.status(200).send('Ok');
                    } else {
                        res.status(401).send('Wrong credentials');
                    }
                }).catch((error) => {
                    console.error('Error comparing pass ' + error);
                    res.status(500).send('Error comparing pass ' + error);
                });
            } else if (isUserExists === false) {
                res.status(401).send('User not exists');
            } else {
                res.status(500).send('Error checking if user exists: ' + data);
            }
        });
    });

    return router;
};