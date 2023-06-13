const mongoose = require('mongoose')

const goalSchema = new mongoose.Schema({
    goalName: String,
    goalDesc: String,
    categoryId: String,
    userId: String,
    goalAmount: String,
    createTimeStamp: String
})

module.exports = mongoose.model('goalSchema', goalSchema);