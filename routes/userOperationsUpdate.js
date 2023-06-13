const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const FormData = require('form-data');
const fetch = require('node-fetch').default;
dotenv.config();

//Import of models
const userSchema = require('../models/userSchema.js');
const accountSchema = require('../models/accountSchema.js');
const categorySchema = require('../models/categorySchema.js');
const goalSchema = require('../models/goalSchema.js');
const transactionSchema = require('../models/transactionSchema.js');
const authenticateToken = require('../MiddleWares/Authorization')
//Manage Budget
router.put("/category/updateBudget", authenticateToken, async (req, res)=>{
    try{
            const budget = req.body.categoryBudget;
            const categoryId = req.body.categoryId;
            const categorydataUpdate = {
                categoryBudget: budget
            }
            const categoryDataId={
                _id:req.body.categoryId
            }
            categorySchema.updateOne(categoryDataId,{$set:categorydataUpdate}).then((data)=>{
                    res.status(200).json({"Status":true,"Message": "Budget updated successfully."}); 
                }).catch((err)=>{
                    res.status(500).json({"Status":false, "Error": err.message })
                    throw err;
            })
        
    }catch(err){
        res.status(500).json({"Status":false,"Error": err.message })
    }
})

router.put("/user-details", authenticateToken, async (req, res) => {
  try {
      const userData = {
        userName: req.body.userName,
        email: req.body.email,
        password: req.body.password,
        profileImage: req.body.profileImage,
      };
    const userId = { _id: req.user.userId };
    await userSchema
      .updateOne(userId, { $set: userData })
      .then((data) => {
        res
          .status(200)
          .json({ Status: true, Message: "Profile updated successfully." });
      })
      .catch((err) => {
        res.status(500).json({ Status: false, Error: err.message });
      });
  } catch (err) {
    res.status(500).json({ Status: false, Error: err.message });
  }
});

router.put("/accounts/:id", authenticateToken, async (req, res) => {
  try {
      const id = req.params.id;
      const updateData = req.body; // Assuming the updated data is sent in the request body

      const updatedAccount = await accountSchema.findByIdAndUpdate(id, updateData, {
          new: true // Return the updated account as the result
      });

      if (!updatedAccount) {
          return res.status(404).json({
              "Status": false,
              "type": "update-data",
              "Error": "Account not found."
          });
      }

      res.status(200).json({
          "Status": true,
          "type": "update-data",
          "Message": "OK, Account updated successfully.",
          "data": updatedAccount
      });
  } catch (err) {
      res.status(500).json({
          "Status": false,
          "type": "update-data",
          "Error": err.message
      });
  }
});


router.put("/categories/:id", authenticateToken, async (req, res) => {
  try {
    const id = req.params.id;
    const updateData = req.body; // Assuming the updated data is sent in the request body

    const updatedCategory = await categorySchema.findByIdAndUpdate(id, updateData, {
      new: true // Return the updated category as the result
    });

    if (!updatedCategory) {
      return res.status(404).json({
        "Status": false,
        "type": "update-data",
        "Error": "Category not found."
      });
    }

    res.status(200).json({
      "Status": true,
      "type": "update-data",
      "Message": "OK, Category updated successfully.",
      "data": updatedCategory
    });
  } catch (err) {
    res.status(500).json({
      "Status": false,
      "type": "update-data",
      "Error": err.message
    });
  }
});

router.put("/goals/:id", authenticateToken, async (req, res) => {
  try {
    const id = req.params.id;
    const updateData = req.body; // Assuming the updated data is sent in the request body

    const updatedGoal = await goalSchema.findByIdAndUpdate(id, updateData, {
      new: true // Return the updated goal as the result
    });

    if (!updatedGoal) {
      return res.status(404).json({
        "Status": false,
        "type": "update-data",
        "Error": "Goal not found."
      });
    }

    res.status(200).json({
      "Status": true,
      "type": "update-data",
      "Message": "OK, Goal updated successfully.",
      "data": updatedGoal
    });
  } catch (err) {
    res.status(500).json({
      "Status": false,
      "type": "update-data",
      "Error": err.message
    });
  }
});

router.put("/transactions/:id", authenticateToken, async (req, res) => {
  try {
    const id = req.params.id;
    const updateData = req.body; // Assuming the updated data is sent in the request body

    const updatedTransaction = await transactionSchema.findByIdAndUpdate(id, updateData, {
      new: true // Return the updated transaction as the result
    });

    if (!updatedTransaction) {
      return res.status(404).json({
        "Status": false,
        "type": "update-data",
        "Error": "Transaction not found."
      });
    }

    res.status(200).json({
      "Status": true,
      "type": "update-data",
      "Message": "OK, Transaction updated successfully.",
      "data": updatedTransaction
    });
  } catch (err) {
    res.status(500).json({
      "Status": false,
      "type": "update-data",
      "Error": err.message
    });
  }
});




module.exports = router;