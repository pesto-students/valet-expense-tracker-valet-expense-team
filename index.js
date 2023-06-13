const express = require('express');
const app = express();
const dotenv = require('dotenv');
const connect = require('./Config/db');
dotenv.config();

const cors = require('cors')
app.use(cors({
    origin: "*"
}));
const auth = require('./routes/auth.js');
const userOperationsInsert = require('./routes/userOperationsInsert.js');
const userOperationsUpdate = require('./routes/userOperationsUpdate.js');
const userOperationsFetch= require('./routes/userOperationsFetch.js');
const userDashboardGraphs= require('./routes/userDashboardGraphs.js');
const userOperationsDelete= require('./routes/userOperationsDelete.js');
var bodyParser = require('body-parser');
app.use(express.json());
// app.use(bodyParser.json());
app.use('/api',auth);
app.use('/api',userOperationsInsert);
app.use('/api',userOperationsUpdate);
app.use('/api',userOperationsFetch);
app.use('/api',userDashboardGraphs);
app.use('/api',userOperationsDelete);

app.listen(process.env.PORT, async ()=>{
    await connect()
    console.log('Server is listening on port: ' + process.env.PORT);
});
