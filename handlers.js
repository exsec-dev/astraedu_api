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

    // Get user data
    router.get('/user', authMiddleware, (req, res) => {
        const { user } = req;
        const query = `
            SELECT *
            FROM userdata t1
            JOIN modules t2 ON t1.username = t2.username
            WHERE t1.username = ?;
        `;
        pool.query(query, [user], (error, results) => {
            if (error) {
                console.error('GET error: ' + error.stack);
                res.status(500).json({ message: 'Произошла ошибка при получении данных пользователя' });
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
                    const query = `
                        INSERT INTO users (username, password, date)
                        VALUES (?, ?, ?);
                    `;
                    const values = [username, hash, (new Date()).toLocaleString()];
                    pool.query(query, values, (error, results) => {
                        if (error) {
                            console.error('Error adding new user ' + error.stack);
                            res.status(500).send('Error adding new user ' + error.stack);
                        } else {
                            const query2 = `
                                INSERT INTO userdata (username, points, coins, achievements, favorite_achievement, avatar)
                                VALUES (?, ?, ?, ?, ?, ?);
                            `;
                            const imageData = fs.readFileSync('./icons/avatar.jpg');
                            const values2 = [username, 5, 0, JSON.stringify([]), "quick_start", imageData];
                            pool.query(query2, values2, (error, results) => {
                                if (error) {
                                    console.error('Error adding new user ' + error.stack);
                                    res.status(500).send('Error adding new user ' + error.stack);
                                } else {
                                    const query3 = `
                                        INSERT INTO modules (username, intro, command_line)
                                        VALUES (?, ?, ?);
                                    `;
                                    const commandLineData = new Array(2).fill({progress: 0, details: [null, null, null, null, null], bonus: false});
                                    const introData = new Array(5).fill({status: 0});
                                    const values3 = [username, JSON.stringify(introData), JSON.stringify(commandLineData)];
                                    pool.query(query3, values3, (error, results) => {
                                        if (error) {
                                            console.error('Error adding new user ' + error.stack);
                                            res.status(500).send('Error adding new user ' + error.stack);
                                        } else {
                                            const token = generateAccessToken(username);
                                            res.status(201).json({ token });
                                        }
                                    });
                                }
                            });
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

    // Get user account data
    router.get('/account', authMiddleware, (req, res) => {
        const { user } = req;
        const query = `SELECT * FROM users WHERE username = ?`;
        pool.query(query, [user], (error, results) => {
            if (error) {
                console.error('GET error: ' + error.stack);
                res.status(500).json({ message: 'Произошла ошибка при получении данных аккаунта' });
            } else {
                res.status(200).json({
                    id: results[0].id,
                    username: results[0].username,
                });
            }
        });
    });

    // Change user account data
    router.post('/account', authMiddleware, (req, res) => {
        const { user } = req;
        const { username, password } = req.body;
        // Changing password
        if (!!password && !username) {
            encrypt(password).then((hash) => {
                const query = `
                    UPDATE users
                    SET password = ?
                    WHERE username = ?;
                `;
                pool.query(query, [hash, user], (error, results) => {
                    if (error) {
                        console.error('Error changing password ' + error.stack);
                        res.status(500).send('Error changing password ' + error.stack);
                    } else {
                        const token = generateAccessToken(user);
                        res.status(201).json({ token, message: "Пароль успешно изменен" });
                    }
                });
            })
            .catch((error) => {
                console.error('Error encrypting pass ' + error);
                res.status(500).send('Error encrypting pass ' + error);
            });
        }
        // Changing username
        if (!!username && !password) {
            getUser(pool, username, (isUserExists, data) => {
                if (isUserExists === false) {
                    const query = `
                        UPDATE users
                        SET username = ?
                        WHERE username = ?;
                    `;
                    pool.query(query, [username, user], (error, results) => {
                        if (error) {
                            console.error('Error changing username ' + error.stack);
                            res.status(500).send('Error changing username ' + error.stack);
                        } else {
                            const query2 = `
                                UPDATE userdata
                                SET username = ?
                                WHERE username = ?;
                            `;
                            pool.query(query2, [username, user], (error, results) => {
                                if (error) {
                                    console.error('Error changing username ' + error.stack);
                                    res.status(500).send('Error changing username ' + error.stack);
                                } else {
                                    const query3 = `
                                        UPDATE modules
                                        SET username = ?
                                        WHERE username = ?;
                                    `;
                                    pool.query(query3, [username, user], (error, results) => {
                                        if (error) {
                                            console.error('Error changing username ' + error.stack);
                                            res.status(500).send('Error changing username ' + error.stack);
                                        } else {
                                            const token = generateAccessToken(username);
                                            res.status(201).json({ token, message: "Логин успешно изменен" });
                                        }
                                    });
                                }
                            });
                        }
                    });
                } else if (isUserExists === true) {
                    res.status(409).json({ message: 'Такой пользователь уже существует' });
                } else {
                    res.status(500).send('Error checking if user exists: ' + data);
                }
            });
        }
        // Changing both
        if (!!username && !!password) {
            getUser(pool, username, (isUserExists, data) => {
                if (isUserExists === false) {
                    encrypt(password).then((hash) => {
                        const query = `
                            UPDATE users
                            SET username = ?,
                                password = ?
                            WHERE username = ?;
                        `;
                        pool.query(query, [username, hash, user], (error, results) => {
                            if (error) {
                                console.error('Error changing username & pass ' + error.stack);
                                res.status(500).send('Error changing username & pass ' + error.stack);
                            } else {
                                const query2 = `
                                    UPDATE userdata
                                    SET username = ?
                                    WHERE username = ?;
                                `;
                                pool.query(query2, [username, user], (error, results) => {
                                    if (error) {
                                        console.error('Error changing username ' + error.stack);
                                        res.status(500).send('Error changing username ' + error.stack);
                                    } else {
                                        const query3 = `
                                            UPDATE modules
                                            SET username = ?
                                            WHERE username = ?;
                                        `;
                                        pool.query(query3, [username, user], (error, results) => {
                                            if (error) {
                                                console.error('Error changing username ' + error.stack);
                                                res.status(500).send('Error changing username ' + error.stack);
                                            } else {
                                                const token = generateAccessToken(username);
                                                res.status(201).json({ token, message: "Логин и пароль успешно изменены" });
                                            }
                                        });
                                    }
                                });
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
        }
    });

    // Set avatar
    router.post('/avatar', authMiddleware, (req, res) => {
        const { user } = req;
        const { avatar } = req.body;
        const query = `UPDATE userdata SET avatar = ? WHERE username = ?;`;
        const buffer = Buffer.from(avatar.split(';base64,').pop(), 'base64');
        pool.query(query, [buffer, user], (error, results) => {
            if (error) {
                console.error('GET error: ' + error.stack);
                res.status(500).json({ message: 'Произошла ошибка при смене аватара' });
            } else {
                res.status(200).json({ message: 'Ok' });
            }
        });
    });

    // Coins exchange
    router.get('/coins/exchange', authMiddleware, (req, res) => {
        const { user } = req;
        const { coins } = req.query;
        const query = `
            UPDATE userdata
            SET coins = coins - ?,
                points = points + ?
            WHERE username = ?;
        `;
        pool.query(query, [coins, coins * 10, user], (error, results) => {
            if (error) {
                console.error('GET error: ' + error.stack);
                res.status(500).json({ message: 'Произошла ошибка при обмене коинов' });
            } else {
                res.status(200).json({ message: 'Ok' });
            }
        });
    });

    // Add achievement
    router.get('/achievements/add', authMiddleware, (req, res) => {
        const { user } = req;
        const { achievement } = req.query;
        const query = `
            UPDATE userdata
            SET achievements = JSON_ARRAY_APPEND(achievements, '$', ?)
            WHERE username = ?;
        `;
        pool.query(query, [achievement, user], (error, results) => {
            if (error) {
                console.error('GET error: ' + error.stack);
                res.status(500).json({ message: 'Произошла ошибка при добавлении достижения' });
            } else {
                res.status(200).json({ message: 'Ok' });
            }
        });
    });

    // Set favorite achievement
    router.get('/achievements/favorite', authMiddleware, (req, res) => {
        const { user } = req;
        const { favorite } = req.query;
        const query = `
            UPDATE userdata
            SET favorite_achievement = ?
            WHERE username = ?;
        `;
        pool.query(query, [favorite, user], (error, results) => {
            if (error) {
                console.error('GET error: ' + error.stack);
                res.status(500).json({ message: 'Ошибка при смене достижения' });
            } else {
                res.status(200).json({ message: 'Ok' });
            }
        });
    });

    return router;
};