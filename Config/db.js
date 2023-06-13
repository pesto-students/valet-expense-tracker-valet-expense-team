const mongoose = require('mongoose');
const dotenv = require('dotenv');
dotenv.config();

const mongodbquery = process.env.NODE_ENV === "PROD" ? process.env.PRODUCTION_DB : process.env.TEST_DB;

const connect = () => {
    return mongoose.connect(mongodbquery)
}

module.exports = connect;