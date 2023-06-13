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

//Add Account
router.post("/accounts/add", authenticateToken, async (req, res)=>{
    try{
            const accountdata = new accountSchema({
                    accountName: req.body.accountName,
                    accountDesc: req.body.accountDesc,
                    userId: req.user.userId, //from token
                    createTimeStamp: Date.now()
            })
            
            await userSchema.findById(req.user.userId).then((data)=>{
                if(data.length != 0){ 
                    accountSchema.find({$and: [{ accountName: {$eq: req.body.accountName}, userId: {$eq: req.user.userId}}]}).then((account)=>{
                        if(account.length > 0) 
                            res.status(200).json({"Status":false,"Message": "Account already exists!"})
                        else {
                            accountdata.save().then((data) => {
                            res.status(200).json({"Status":true,"Message": "OK, Account Created.", "data" : data}); 
                            });
                        }
                    })
                }else{
                    res.status(200).json({"Status":false,"Message": "User Not registered!"})
                }
            }).catch((err)=>{
                res.status(500).json({"Status":false, "Error": err.message })
            })
    } catch(err){
        res.status(500).json({"Status": false, "Error": err.message })
    }
})   

//Add category
router.post("/categories/add", authenticateToken, async (req, res)=>{
    try{
            const categorydata = new categorySchema({
                categoryName: req.body.categoryName,
                categoryDesc: req.body.categoryDesc,
                userId: req.user.userId, //from token
                categoryType: req.body.categoryType,
                categoryBudget: req.body.categoryBudget,
                createTimeStamp: Date.now()
            })

             await categorySchema.find({$and: [{categoryName: {$eq: req.body.categoryName}, userId: {$eq: req.user.userId}}]}).then((account)=>{
                if(account.length > 0) 
                        res.status(200).json({"Status":false, "Message":"Category already exists!"})
                else {
                       categorydata.save().then((data) => {
                          res.status(200).json({"Status": true,"Message":"OK, Category Created.", "data" : data})  
                        })
                }
             })
              
    } catch(err){
        res.status(500).json({"Status": false, "Error": err.message })
    }
})   


//Add goals
router.post("/goals/add",authenticateToken, async (req, res)=>{
    try{
            const goaldata = new goalSchema({
                    goalName: req.body.goalName,
                    goalDesc: req.body.goalDesc,
                    categoryId: req.body.categoryId,
                    userId: req.user.userId, //from token
                    goalAmount: req.body.goalAmount,
                    createTimeStamp: Date.now()
            })

            await categorySchema.findById(req.body.categoryId).then((data)=>{
                    //console.log(data)
                    if(data.length != 0){
                        goalSchema.find({$and: [{goalName: {$eq: req.body.goalName}, userId: {$eq: req.user.userId}}]}).then((account)=>{
                            if(account.length > 0) 
                                res.status(200).json({"Status":false, "Message":"Goal already exists!"})
                            else {
                                    goaldata.save().then((data) => {
                                    res.status(200).json({"Status": true,"Message":"OK, Goal Created.", "data" : data}); 
                                });
                            }
                        })
                    }else{
                        res.status(200).json({"Status":false,"Message": "Category Not registered!"})
                    }
                }).catch((err)=>{
                    res.status(500).json({"Status": false, "Error": err.message })
                })
    } catch(err){
        res.status(500).json({"Status": false, "Error": err.message })
    }
})   


//Add Transaction
router.post("/transactions/add",authenticateToken, async (req, res)=>{
    try{
            const transactiondata = new transactionSchema({
                    transactionName: req.body.transactionName,
                    transactionDesc: req.body.transactionDesc, 
                    categoryOrGoal: req.body.categoryOrGoal,
                    accountId: req.body.accountId,
                    goalId:req.body.goalId,
                    categoryId:req.body.categoryId,
                    transactionAmount: req.body.transactionAmount,
                    transactionDate: req.body.transactionDate,
                    userId: req.user.userId, //from token
                    transactiontype: req.body.transactiontype,
                    createTimeStamp: Date.now()
            })

            if(req.body.categoryOrGoal == 'Category'){
                await categorySchema.findById(req.body.categoryId).then((data)=>{
                    //console.log(data)
                    if(data.length != 0){
                        transactiondata.save().then((data) => {
                            res.status(200).json({"Status":true, "Message":"OK, Transaction Created.", "data" : data}); 
                        });
                         
                    }else{
                        res.status(200).json({"Status":false,"Message": "Category Not registered!"})
                    }
                }).catch((err)=>{
                    res.status(500).json({"Status": "DB Error!!", "Error": err })
                })
            } else if(req.body.categoryOrGoal == 'Goal'){
                await goalSchema.findById(req.body.goalId).then((data)=>{
                    //console.log(data)
                    if(data.length != 0){
                        transactiondata.save().then((data) => {
                            res.status(200).json({"Status":true,"Message": "OK, Transaction Created.", "data" : data}); 
                        });
                         
                    }else{
                        res.status(200).json({"Status":false,"Message": "Goal Not registered!"})
                    }
                }).catch((err)=>{
                    res.status(500).json({"Status":false,  "Error": err.message })
                })
            } else{
                res.status(200).json({"Status":false,"Message": "Check CategoryOrGoal value!!", "data" : req.body}); 
            }
    } catch(err){
        res.status(500).json({"Status":false, "Error": err.message })
    }
})   


module.exports = router;