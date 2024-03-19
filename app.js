const express = require("express");
const mysql = require("mysql");

const app = express();
app.use(express.json());

const port = 80;
//let conn;

// function reconnect() {
//     conn = mysql.createConnection({
//         host: 'exsec.beget.tech',
//         user: 'exsec_astraedu',
//         password: '6BjrIT1*',
//         database: 'exsec_astraedu'
//     });

//     conn.connect((err) => {
//         if (err) {
//             console.error('Error trying connect to database: ' + err.stack);
//             setTimeout(reconnect, 2000);
//         } else {
//             console.log('CONNECTED DATABASE---------');
//         }
//     });

//     conn.on('error', (err) => {
//         if (err.code === 'PROTOCOL_CONNECTION_LOST') {
//             reconnect();
//         } else {
//             throw err;
//         }
//     });
// }

// reconnect();

const pool = mysql.createPool({
    host: 'exsec.beget.tech',
    user: 'exsec_astraedu',
    password: '6BjrIT1*',
    database: 'exsec_astraedu'
});

const handlers = require('./handlers.js')(pool);
app.use(handlers);

app.listen(port, () => {
    console.log("ASTRA_EDU_BACK IS RUNNING ON PORT 80---------");
})