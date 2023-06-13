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

//Fetch Account by user
router.get('/user-details',authenticateToken,async (req, res) => {
    try{
        const userId = req.user.userId;
        await userSchema.findOne({"_id": {$eq: userId}}).then((data) => {
            res.status(200).json({"Status": true,"type":"fetched-data","Message":"OK, Fetched successfully.", "data": data})
        }).catch((err) => {
            res.status(500).json({"Status":false,"type":"fetched-data", "Error": err.message })
        })
    }catch(err){
        res.status(500).json({"Status":false,"type":"fetched-data", "Error": err.message })
    }
})
router.get("/accounts", authenticateToken, async (req, res)=>{
    try{
        

        const userId = req.user.userId;
        
        await accountSchema.find({"userId": {$eq: userId}}).then((data)=>{
                // console.log(data)
                res.status(200).json({"Status": true,"type":"fetched-data","Message":"OK, Fetched successfully.", "count": data.length, "data": data}); 
            }).catch((err)=>{
                res.status(500).json({"Status":false,"type":"fetched-data", "Error": err.message })
                throw err;
            })
    }catch(err){
        res.status(500).json({"Status": false,"type":"fetched-data", "Error": err.message})
    }
})


//Fetch category by user
router.get("/categories", authenticateToken, async (req, res)=>{
  try{
      const userId = req.user.userId;
      
      await categorySchema.find({"userId": {$eq: userId}}).then((data)=>{
              //console.log(data)
              res.status(200).json({"Status":true,"type":"fetched-data","Message": "OK, Fetched successfully.", "count": data.length, "data": data}); 
          }).catch((err)=>{
              res.status(500).json({"Status":false,"type":"fetched-data", "Error": err.message })
              throw err;
          })
  }catch(err){
      res.status(500).json({"Status": false,"type":"fetched-data", "Error": err.message })
  }
})


//Fetch goal by user
router.get("/goals", authenticateToken, async (req, res)=>{
  try{
      const userId = req.user.userId;
      
      await goalSchema.find({"userId": {$eq: userId}}).then((data)=>{
              //console.log(data)
              res.status(200).json({"Status":true,"type":"fetched-data","Message" :"OK, Fetched successfully.", "count": data.length, "data": data}); 
          }).catch((err)=>{
              res.status(500).json({"Status":false,"type":"fetched-data", "Error": err.message })
              throw err;
          })
  }catch(err){
      res.status(500).json({"Status": false,"type":"fetched-data", "Error": err.message })
  }
})



//Fetch transaction by user
router.get("/transactions", authenticateToken, async (req, res)=>{
  try{
      const userId = req.user.userId;
      
      await transactionSchema.find({"userId": {$eq: userId}}).populate("goalId").populate('accountId').populate('categoryId').then((data)=>{
            //console.log(data)
              res.status(200).json({"Status":true,"type":"fetched-data","Message": "OK, Fetched successfully.", "count": data.length, "data": data}); 
          }).catch((err)=>{
              res.status(500).json({"Status":false,"type":"fetched-data", "Error": err.message })
              throw err;
          })
  }catch(err){
      res.status(500).json({"Status":false,"type":"fetched-data", "Error": err.message })
  }
})



// get individual results

router.get("/accounts/:id", authenticateToken, async (req, res) => {
    try {
        const id = req.params.id;
        const objectId = new mongoose.Types.ObjectId(id); // Convert the id to a valid ObjectId

        await accountSchema.findById(objectId)
            .then((data) => {
                if (!data) {
                    res.status(404).json({
                        "Status": false,
                        "type": "fetched-data",
                        "Error": "Account not found."
                    });
                } else {
                    res.status(200).json({
                        "Status": true,
                        "type": "fetched-data",
                        "Message": "OK, Fetched successfully.",
                        "data": data
                    });
                }
            })
            .catch((err) => {
                res.status(500).json({
                    "Status": false,
                    "type": "fetched-data",
                    "Error": err.message
                });
                throw err;
            });
    } catch (err) {
        res.status(500).json({
            "Status": false,
            "type": "fetched-data",
            "Error": err.message
        });
    }
});
router.get("/categories/:id", authenticateToken, async (req, res) => {
    try {
      const id = req.params.id;
  
      const category = await categorySchema.findById(id);
  
      if (!category) {
        return res.status(404).json({
          "Status": false,
          "type": "fetched-data",
          "Error": "Category not found."
        });
      }
  
      res.status(200).json({
        "Status": true,
        "type": "fetched-data",
        "Message": "OK, Category fetched successfully.",
        "data": category
      });
    } catch (err) {
      res.status(500).json({
        "Status": false,
        "type": "fetched-data",
        "Error": err.message
      });
    }
  });

  router.get("/goals/:id", authenticateToken, async (req, res) => {
    try {
      const id = req.params.id;
  
      const goal = await goalSchema.findById(id);
  
      if (!goal) {
        return res.status(404).json({
          "Status": false,
          "type": "fetched-data",
          "Error": "Goal not found."
        });
      }
  
      res.status(200).json({
        "Status": true,
        "type": "fetched-data",
        "Message": "OK, Goal fetched successfully.",
        "data": goal
      });
    } catch (err) {
      res.status(500).json({
        "Status": false,
        "type": "fetched-data",
        "Error": err.message
      });
    }
  });


  router.get("/transactions/:id", authenticateToken, async (req, res) => {
    try {
      const id = req.params.id;
  
      const transaction = await transactionSchema.findById(id)
        .populate('accountId', 'accountName') // Populate the account information
        .populate('goalId', 'goalName') // Populate the goal information
        .populate('categoryId', 'categoryName'); // Populate the category information
  
      if (!transaction) {
        return res.status(404).json({
          "Status": false,
          "type": "fetched-data",
          "Error": "Transaction not found."
        });
      }
  
      res.status(200).json({
        "Status": true,
        "type": "fetched-data",
        "Message": "OK, Transaction fetched successfully.",
        "data": transaction
      });
    } catch (err) {
      res.status(500).json({
        "Status": false,
        "type": "fetched-data",
        "Error": err.message
      });
    }
  });
  

module.exports = router;