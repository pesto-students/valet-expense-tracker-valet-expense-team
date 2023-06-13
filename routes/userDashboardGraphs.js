const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
dotenv.config();

//Import of models
const userSchema = require('../models/userSchema.js');
const accountSchema = require('../models/accountSchema.js');
const categorySchema = require('../models/categorySchema.js');
const goalSchema = require('../models/goalSchema.js');
const transactionSchema = require('../models/transactionSchema.js');
const authenticateToken = require('../MiddleWares/Authorization')

router.get("/category/fetchExpensebyCategory", authenticateToken, async (req, res)=>{
    try{

        await transactionSchema.aggregate([
            {
                $match: {
                    $and: [
                        {
                            userId: req.user.userId //from token
                        },
                        {
                            categoryOrGoal: 'Category'
                        }
                    ]
                }
            },
            {
                $lookup: {
                    from: "categoryschemas",
                    let: {
                      searchId: {
                        $toObjectId: "$categoryId",
                      },
                    },
                    pipeline: [
                      {$match: {
                              $expr: {
                                $eq: ['$_id', '$$searchId']
                              }
                            }
                      }
                    ],
                  
                    as: "productInfo",
                  }
            },          
            {
                $unwind: '$productInfo'
            },
            {
                $group: {
                _id: '$productInfo',
                transactions: { $push: '$$ROOT' }
                }
            }
        ]).then((data) => {
            dataArray = []

            if(data.length > 0){
                for(let i=0;i<data.length;i++){
                    
                    totalAmount = 0

                    dataCategoryName = data[i]['_id']['categoryName']
                    dataCategoryBudget = Number(data[i]['_id']['categoryBudget']);
                    
                    for(let j=0;j<data[i]['transactions'].length;j++){
                        dataTransactionAmount = Number(data[i]['transactions'][j]['transactionAmount'])
                        dataTransactiontype = data[i]['transactions'][j]['transactiontype']
                        
                        if(dataTransactiontype == 'Expense'){
                            totalAmount += dataTransactionAmount;
                        }
                    }


                    if (!isNaN(totalAmount) && !isNaN(dataCategoryBudget)) {
                        const totalAmount1 = parseInt(totalAmount);
                        const dataCategoryBudget1 = parseInt(dataCategoryBudget);
                        percentage = (totalAmount1/dataCategoryBudget1) * 100

                      } else {
                        percentage = 0;
                      }

                    dataStruct = {
                        'categoryName': dataCategoryName,
                        'categoryBudget': dataCategoryBudget,
                        'totalTransactions': totalAmount,
                        'percentage': percentage
                    }
                    dataArray.push(dataStruct)
                }
            }

            res.status(200).json({
                'Status': true,
                "type":"fetched-data",
                'Message':'OK! records featched.',
                'count': dataArray.length,
                'data': dataArray
            })
        })

    } catch(err){
        res.status(500).json({"Status": false,"type":"fetched-data", "Error": err.message })
    }
})

//by goals
router.get("/category/fetchExpensebyGoal", authenticateToken, async (req, res)=>{
    try{

        await transactionSchema.aggregate([
            {
                $match: {
                    $and: [
                        {
                            userId: req.user.userId //from token
                        },
                        {
                            categoryOrGoal: 'Goal'
                        }
                    ]
                }
            },
            {
                $lookup: {
                    from: "goalschemas",
                    let: {
                      searchId: {
                        $toObjectId: "$goalId",
                      },
                    },
                    pipeline: [
                      {$match: {
                              $expr: {
                                $eq: ['$_id', '$$searchId']
                              }
                            }
                      }
                    ],
                  
                    as: "productInfo",
                  }
            },          
            {
                $unwind: '$productInfo'
            },
            {
                $group: {
                _id: '$productInfo',
                transactions: { $push: '$$ROOT' }
                }
            }
        ]).then((data) => {
            dataArray = []

            if(data.length > 0){
                for(let i=0;i<data.length;i++){
                    
                    totalAmount = 0

                    dataCategoryName = data[i]['_id']['goalName']
                    dataCategoryBudget = data[i]['_id']['goalAmount']
                    
                    for(let j=0;j<data[i]['transactions'].length;j++){
                        dataTransactionAmount = data[i]['transactions'][j]['transactionAmount']
                        dataTransactiontype = data[i]['transactions'][j]['transactiontype']
                        
                        if(dataTransactiontype == 'Transfer'){
                            totalAmount += dataTransactionAmount;
                        }
                    }


                    if (!isNaN(totalAmount) && !isNaN(dataCategoryBudget)) {
                        const totalAmount1 = parseInt(totalAmount);
                        const dataCategoryBudget1 = parseInt(dataCategoryBudget);

                        percentage = (totalAmount1/dataCategoryBudget1) * 100

                      } else {
                        percentage = 0;
                      }

                    dataStruct = {
                        'goalName': dataCategoryName,
                        'goalBudget': dataCategoryBudget,
                        'totalTransactions': totalAmount,
                        'percentage': percentage
                    }
                    dataArray.push([dataStruct])
                }
            }

            res.status(200).json({
                'Status':true,
                'Message': 'OK! records featched.',
                "type":"fetched-data",
                'count': dataArray.length,
                'data': dataArray
            })
        })

    } catch(err){
        res.status(500).json({"Status": false,"type":"fetched-data", "Error": err.message })
    }
})

module.exports = router;