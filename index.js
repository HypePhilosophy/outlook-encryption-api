const express = require('express');
const password_encrypt  = require('./encrypter');

const app = express();
//app.use( bodyParser.json() );
app.use(express.json());

var count = 0;
app.get('/home', (req, res) => {
    count += 1;
    console.log(count)
    return res.send('<h1>Recieved Request</h1>');
  });

app.post('/outlook-encrypt', (req, res) => {
    const key = req.body.key;
    const random_number = req.body.random_number;
    const password = req.body.password;
    const cipher_value = password_encrypt.encryptStart(password, key, random_number);
    const cipher_json_object = {Cipher_Value: cipher_value}
    return res.send(JSON.stringify(cipher_json_object));

  });


app.listen(3000, () => {
    console.log("Running on port 3000");
})