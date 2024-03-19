const express = require("express");
const mysql = require("mysql");

const app = express();
app.use(express.json());

const pool = mysql.createPool({
    host: 'exsec.beget.tech',
    user: 'exsec_astraedu',
    password: '6BjrIT1*',
    database: 'exsec_astraedu'
});

const handlers = require('./handlers.js')(pool);
app.use(handlers);

app.listen( () => {
    console.log("ASTRA_EDU_BACK IS RUNNING---------");
})