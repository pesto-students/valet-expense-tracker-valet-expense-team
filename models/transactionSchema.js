const mongoose = require('mongoose')
const {Schema} = require('mongoose')
const transactionSchema = new mongoose.Schema({
    transactionName: String,
    categoryOrGoal: String,
    transactionAmount: String,
    transactionDate: String,
    accountId:{ type: Schema.Types.ObjectId, ref: 'accountSchema',required:true },
    goalId:{type: Schema.Types.ObjectId, ref: 'goalSchema',required:false},
    categoryId:{type: Schema.Types.ObjectId, ref: 'categorySchema',required:false},
    userId: String,
    transactiontype: String,
    createTimeStamp: String
})

module.exports = mongoose.model('transactionSchema', transactionSchema);