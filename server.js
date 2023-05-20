const express = require('express');
const app = express();
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
const jsonParser = bodyParser.json();
const bcrypt = require('bcrypt');
var jwt = require('jsonwebtoken');
const secret = 'loginAPI'
const saltRounds = 10;
require('dotenv').config();

app.use(cors());
app.use(express.json())

const connection = mysql.createConnection(process.env.DATABASE_URL);

app.post('/register', jsonParser, function (req, res, next) {
    bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
        connection.execute(
            'INSERT INTO users(username, password) VALUES (?,?)',
            [req.body.username, hash],
            function (err, results, fields) {
                if (err) {
                    res.json({ status: 'error', message: err });
                    return;
                }
                res.json({ status: 'ok' });
            }
        );
    });
});

app.post('/login', jsonParser, function (req, res, next) {
    connection.execute(
        'SELECT * FROM users WHERE username = ?',
        [req.body.username],
        function (err, user, fields) {
            if (err) {
                res.json({ status: 'error', massage: err });
                return
            }
            if (user.length == 0) {
                res.json({ status: 'error', massage: 'no user found' });
                return
            }
            bcrypt.compare(req.body.password, user[0].password, function (err, isLogin) {
                if (isLogin) {
                    var token = jwt.sign({ Username: user[0].username }, secret, { expiresIn: '1d' });
                    res.json({ status: 'ok', message: 'login success', token })
                } else {
                    res.json({ status: 'error', massage: 'incorrect password' })
                }
            });
        }
    );
})

app.post('/authen', jsonParser, function (req, res, next) {
    try {
        const token = req.headers.authorization.split(' ')[1]
        var decoded = jwt.verify(token, secret);
        res.json({ status: 'ok', decoded })
    } catch (err) {
        res.json({ status: 'error', massage: err.massage })
    }
})

app.post('/info', jsonParser, function (req, res, next) {
    connection.execute(
        'INSERT INTO certificate(certificateNo, standard, scope, company, approval,until ) VALUES (?,?,?,?,?,?)',
        [req.body.certificateNo, req.body.standard, req.body.scope, req.body.company, req.body.approval, req.body.until],
        function (err, results, fields) {
            if (err) {
                res.json({ status: 'error', message: err });
                return;
            }
            res.json({ status: 'ok' ,fields});
        }
    );

});

app.get('/info', jsonParser, function (req, res, next) {
    connection.execute(
        'SELECT * FROM certificate', (err, result) => {
            if (err) {
                console.log(err);
            } else {
                res.send(result);
            }
        });
});

app.put('/info', jsonParser, function (req, res, next) {
    connection.execute(
        'UPDATE certificate SET  standard = ?,scope = ?,company = ?,approval = ?, until = ? WHERE certificateNo = ? ',
        [ req.body.standard, req.body.scope, req.body.company, req.body.approval, req.body.until,req.body.certificateNo],
        function (err, results, fields) {
            if (err) {
                res.json({ status: 'error', message: err });
                return;
            }
            res.json({ status: 'ok' });
        }
    );
});

app.delete('/info', jsonParser, function (req, res, next) {
    connection.execute(
        'DELETE  FROM certificate WHERE certificateNo = ?',[req.body.certificateNo] ,(err, result) =>{
            if (err) {
                console.log(err);
            } else {
                res.send(result);
            }
        });
});

app.get('/all', function (req, res, next) {
    const searchValue = req.query.search;

    const sql = `SELECT * FROM certificate WHERE 
        certificateNo LIKE '%${searchValue}%' OR 
        standard LIKE '%${searchValue}%' OR 
        scope LIKE '%${searchValue}%' OR 
        company LIKE '%${searchValue}%'`;

    connection.query(sql, (err, result) => {
        if (err) {
            console.log(err);
            res.status(500).json({ error: 'Error executing the query' });
        } else {
            res.send(result);
        }
    });
});

app.get('/:x/:y', jsonParser, (req, res) => {
    const x = req.params.x;
    const y = req.params.y;
    connection.query(`SELECT * FROM certificate WHERE ${x} LIKE ?`, [`%${y}%`], (err, result) =>{
      if (err) {
        console.log(err);
      } else {
        res.send(result);
      } 
    });
  });
  

app.listen(3333, function () {
    console.log('CORS-enabled web server listening on port 3333')
})  
