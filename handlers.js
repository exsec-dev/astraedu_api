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
                            const values2 = [username, 0, 0, JSON.stringify([]), "quick_start", imageData];
                            pool.query(query2, values2, (error, results) => {
                                if (error) {
                                    console.error('Error adding new user ' + error.stack);
                                    res.status(500).send('Error adding new user ' + error.stack);
                                } else {
                                    const query3 = `
                                        INSERT INTO modules (username, intro, command_line, file_system)
                                        VALUES (?, ?, ?, ?);
                                    `;
                                    const introData = [{ status: 1 }, { status: 0 }];
                                    const moduleData = new Array(4).fill({ progress: 0, details: [null, null, null, null, null], bonus: false, retry_count: 3, status: 0 });
                                    moduleData.push({ progress: 0, details: [null], bonus: true, status: 0 });
                                    const values3 = [username, JSON.stringify(introData), JSON.stringify(moduleData), JSON.stringify(moduleData)];
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

    // Add new review
    router.post('/review', authMiddleware, (req, res) => {
        const { user } = req;
        const { review } = req.body;
        const query = `INSERT INTO reviews (username, review, date) VALUES (?, ?, ?);`;
        pool.query(query, [user, review, (new Date()).toLocaleString()], (error, results) => {
            if (error) {
                console.error('GET error: ' + error.stack);
                res.status(500).json({ message: 'Произошла ошибка при добавлении отзыва' });
            } else {
                res.status(200).json({ message: 'Ok' });
            }
        });
    });

    // Get reviews
    router.get('/review', authMiddleware, (req, res) => {
        const { user } = req;
        const query = `SELECT * FROM reviews WHERE username = ?`;
        pool.query(query, [user], (error, results) => {
            if (error) {
                console.error('GET error: ' + error.stack);
                res.status(500).json({ message: 'Произошла ошибка при получении отзыва' });
            } else {
                if (results.length) {
                    res.status(400).json({ message: 'Вы уже отправили отзыв' });
                } else {
                    res.status(200).json({ message: 'Ok' });
                }
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
        pool.query(query, [parseInt(coins), parseInt(coins) * 10, user], (error, results) => {
            if (error) {
                console.error('GET error: ' + error.stack);
                res.status(500).json({ message: 'Произошла ошибка при обмене коинов' });
            } else {
                res.status(200).json({ message: 'Ok' });
            }
        });
    });

    // Get all users data
    router.get('/leaderboard', authMiddleware, (req, res) => {
        const query = `SELECT * FROM userdata ORDER BY points DESC;`;
        pool.query(query, [], (error, results) => {
            if (error) {
                console.error('GET error: ' + error.stack);
                res.status(500).json({ message: 'Произошла ошибка при получении таблицы лидеров' });
            } else {
                res.status(200).json(results);
            }
        });
    });

    // Add achievement
    router.get('/achievements/add', authMiddleware, (req, res) => {
        const { user } = req;
        const { achievement } = req.query;
        const query = `
            UPDATE userdata
            SET achievements = JSON_ARRAY_APPEND(achievements, '$', ?),
                points = points + ?
            WHERE JSON_SEARCH(achievements, 'one', ?) IS NULL
            AND username = ?;
        `;
        pool.query(query, [achievement, 5, achievement, user], (error, results) => {
            if (error) {
                console.error('GET error: ' + error.stack);
                res.status(500).json({ message: 'Произошла ошибка при добавлении достижения' });
            } else {
                if (results.affectedRows) {
                    res.status(200).json({ message: 'Ok' });
                } else {
                    res.status(400).json({ message: 'Достижение уже существует' });
                }
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

    // Change module status
    router.get('/module/status', authMiddleware, (req, res) => {
        const { user } = req;
        const { status, module, id } = req.query;
        const moduleMap = {
            "Введение": "intro",
            "Командная строка": "command_line",
            "Файловая система": "file_system"
        };
        const query = `
            UPDATE modules
            SET ${moduleMap[module]} = JSON_SET(${moduleMap[module]}, '$[${id}].status', ${parseInt(status)})
            WHERE username = ?;
        `;
        pool.query(query, [user], (error, results) => {
            if (error) {
                console.error('GET error: ' + error.stack);
                res.status(500).json({ message: 'Произошла ошибка при изменении статуса' });
            } else {
                if (module === "Введение" && parseInt(status) === 2) {
                    const query2 = `
                        UPDATE userdata
                        SET points = points + 5
                        WHERE username = ?;
                    `;
                    pool.query(query2, [user], (error, results) => {
                        if (error) {
                            console.error('GET error: ' + error.stack);
                            res.status(500).json({ message: 'Произошла ошибка при добавлении очков' });
                        } else {
                            res.status(200).json({ message: 'Ok' });
                        }
                    });
                } else {
                    res.status(200).json({ message: 'Ok' });
                }
            }
        });
    });

    // Set answer
    router.get('/module/answer', authMiddleware, (req, res) => {
        const { user } = req;
        const { answer, question, module, chapter, is_correct } = req.query;
        const moduleMap = {
            "Введение": "intro",
            "Командная строка": "command_line",
            "Файловая система": "file_system"
        };
        const query = `
            UPDATE modules
            SET ${moduleMap[module]} = JSON_SET(${moduleMap[module]}, '$[${parseInt(chapter)}].details[${parseInt(question)}]', '${answer}')
            ${JSON.parse(is_correct) ? `, ${moduleMap[module]} = JSON_SET(${moduleMap[module]}, '$[${parseInt(chapter)}].progress', JSON_EXTRACT(${moduleMap[module]}, '$[${parseInt(chapter)}].progress') + 1)` : ''}
            WHERE username = ?
            AND JSON_EXTRACT(${moduleMap[module]}, '$[${parseInt(chapter)}].details[${parseInt(question)}]') LIKE '%null%';
        `;
        pool.query(query, [user], (error, results) => {
            if (error) {
                console.error('GET error: ' + error.stack);
                res.status(500).json({ message: 'Произошла ошибка при изменении ответа' });
            } else if (!!results?.affectedRows) {
                const query2 = `
                    UPDATE modules
                    SET ${moduleMap[module]} = JSON_SET(${moduleMap[module]}, '$[${parseInt(chapter)}].status', 2)
                    ${parseInt(chapter) < 3 ? `, ${moduleMap[module]} = JSON_SET(${moduleMap[module]}, '$[${parseInt(chapter) + 1}].status', 1)` : ''}
                    WHERE JSON_EXTRACT(${moduleMap[module]}, '$[${parseInt(chapter)}].details') NOT LIKE '%null%'
                    AND username = ?;
                `;
                pool.query(query2, [user], (error, results) => {
                    if (error) {
                        console.error('GET error: ' + error.stack);
                        res.status(500).json({ message: 'Произошла ошибка при изменении статуса' });
                    } else {
                        if (JSON.parse(is_correct)) {
                            const query3 = `
                                UPDATE userdata
                                SET points = points + 1
                                WHERE username = ?;
                            `;
                            pool.query(query3, [user], (error, results) => {
                                if (error) {
                                    console.error('GET error: ' + error.stack);
                                    res.status(500).json({ message: 'Произошла ошибка при добавлении очков' });
                                } else {
                                    if (parseInt(chapter) === 3) {
                                        const query4 = `
                                            UPDATE modules
                                            SET ${moduleMap[module]} = JSON_SET(${moduleMap[module]}, '$[${parseInt(chapter) + 1}].status', 1)
                                            WHERE JSON_EXTRACT(${moduleMap[module]}, '$[0].progress') = 5
                                            AND JSON_EXTRACT(${moduleMap[module]}, '$[1].progress') = 5
                                            AND JSON_EXTRACT(${moduleMap[module]}, '$[2].progress') = 5
                                            AND JSON_EXTRACT(${moduleMap[module]}, '$[3].progress') = 5
                                            AND username = ?;
                                        `;
                                        pool.query(query4, [user], (error, results) => {
                                            if (error) {
                                                console.error('GET error: ' + error.stack);
                                                res.status(500).json({ message: 'Произошла ошибка при изменении статуса бонуса' });
                                            } else {
                                                if (results.affectedRows) {
                                                    const query5 = `
                                                        UPDATE userdata
                                                        SET coins = coins + 1
                                                        WHERE username = ?;
                                                    `;
                                                    pool.query(query5, [user], (error, results) => {
                                                        if (error) {
                                                            console.error('GET error: ' + error.stack);
                                                            res.status(500).json({ message: 'Произошла ошибка при добавлении коинов' });
                                                        } else {
                                                            res.status(200).json({ message: 'Bonus' });
                                                        }
                                                    });
                                                } else {
                                                    res.status(200).json({ message: 'Ok' });
                                                }
                                            }
                                        });
                                    } else {
                                        res.status(200).json({ message: 'Ok' });
                                    }
                                }
                            });
                        } else {
                            res.status(200).json({ message: 'Ok' });
                        }
                    }
                });
            } else {
                res.status(500).json({ message: 'Ответ уже дан' });
            }
        });
    });

    // Decrease try count
    router.get('/module/retry', authMiddleware, (req, res) => {
        const { user } = req;
        const { question, module, chapter } = req.query;
        const moduleMap = {
            "Введение": "intro",
            "Командная строка": "command_line",
            "Файловая система": "file_system"
        };
        const query = `
            UPDATE modules
            SET ${moduleMap[module]} = JSON_SET(${moduleMap[module]}, '$[${parseInt(chapter)}].retry_count', JSON_EXTRACT(${moduleMap[module]}, '$[${parseInt(chapter)}].retry_count') - 1),
            ${moduleMap[module]} = JSON_SET(${moduleMap[module]}, '$[${parseInt(chapter)}].details[${parseInt(question)}]', null)
            WHERE username = ?;
        `;
        pool.query(query, [user], (error, results) => {
            if (error) {
                console.error('GET error: ' + error.stack);
                res.status(500).json({ message: 'Произошла ошибка при списывании попытки' });
            } else {
                res.status(200).json({ message: 'Ok' });
            }
        });
    });

    return router;
};