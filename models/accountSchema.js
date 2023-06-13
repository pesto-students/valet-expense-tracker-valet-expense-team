const mongoose = require('mongoose')

const accountSchema = new mongoose.Schema({
    accountName: String,
    accountDesc: String,
    userId: String,
    createTimeStamp: String
})

module.exports = mongoose.model('accountSchema', accountSchema);