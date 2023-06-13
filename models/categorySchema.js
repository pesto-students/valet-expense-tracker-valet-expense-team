const mongoose = require('mongoose')

const categorySchema = new mongoose.Schema({
    categoryName: String,
    categoryDesc: String,
    accountID: String,
    userId: String,
    categoryType: String,
    categoryBudget: String,
    createTimeStamp: String
})

module.exports = mongoose.model('categorySchema', categorySchema);