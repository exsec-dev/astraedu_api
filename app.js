const express = require("express");
const mysql = require("mysql");
require('dotenv').config();

const app = express();
const port = process.env.PORT;
app.use(express.json());

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_LOGIN,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

const handlers = require('./handlers.js')(pool);
app.use('/', handlers);

app.listen(port, () => {
    console.log(`ASTRA_EDU_BACK IS RUNNING ON PORT ${port}---------`);
})