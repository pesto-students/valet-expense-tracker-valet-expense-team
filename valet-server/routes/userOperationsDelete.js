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
// Delete account by ID
router.delete("/accounts/delete/:id", authenticateToken, async (req, res) => {
    try {
      const id = req.params.id;
  
      const deletedAccount = await accountSchema.findByIdAndDelete(id);
  
      if (!deletedAccount) {
        return res.status(404).json({
          "Status": false,
          "type": "delete-data",
          "Error": "Account not found."
        });
      }
  
      res.status(200).json({
        "Status": true,
        "type": "delete-data",
        "Message": "OK, Account deleted successfully.",
        "data": deletedAccount
      });
    } catch (err) {
      res.status(500).json({
        "Status": false,
        "type": "delete-data",
        "Error": err.message
      });
    }
  });

  // Delete category by ID
router.delete("/categories/delete/:id", authenticateToken, async (req, res) => {
    try {
      const id = req.params.id;
  
      const deletedCategory = await categorySchema.findByIdAndDelete(id);
  
      if (!deletedCategory) {
        return res.status(404).json({
          "Status": false,
          "type": "delete-data",
          "Error": "Category not found."
        });
      }
  
      res.status(200).json({
        "Status": true,
        "type": "delete-data",
        "Message": "OK, Category deleted successfully.",
        "data": deletedCategory
      });
    } catch (err) {
      res.status(500).json({
        "Status": false,
        "type": "delete-data",
        "Error": err.message
      });
    }
  });
  
  // Delete goal by ID
router.delete("/goals/delete/:id", authenticateToken, async (req, res) => {
    try {
      const id = req.params.id;
  
      const deletedGoal = await goalSchema.findByIdAndDelete(id);
  
      if (!deletedGoal) {
        return res.status(404).json({
          "Status": false,
          "type": "delete-data",
          "Error": "Goal not found."
        });
      }
  
      res.status(200).json({
        "Status": true,
        "type": "delete-data",
        "Message": "OK, Goal deleted successfully.",
        "data": deletedGoal
      });
    } catch (err) {
      res.status(500).json({
        "Status": false,
        "type": "delete-data",
        "Error": err.message
      });
    }
  });
  

  router.delete("/transactions/delete/:id", authenticateToken, async (req, res) => {
    try {
      const id = req.params.id;
  
      const deletedTransaction = await transactionSchema.findByIdAndDelete(id);
  
      if (!deletedTransaction) {
        return res.status(404).json({
          "Status": false,
          "type": "delete-data",
          "Error": "Transaction not found."
        });
      }
  
      res.status(200).json({
        "Status": true,
        "type": "delete-data",
        "Message": "OK, Transaction deleted successfully.",
        "data": deletedTransaction
      });
    } catch (err) {
      res.status(500).json({
        "Status": false,
        "type": "delete-data",
        "Error": err.message
      });
    }
  });

  router.delete("/transactions/delete/byCategory/:categoryId", authenticateToken, async (req, res) => {
    try {
      const categoryId = req.params.categoryId;
  
      const deletedTransactions = await transactionSchema.deleteMany({ categoryId });
  
      res.status(200).json({
        "Status": true,
        "type": "delete-data",
        "Message": "OK, Transactions deleted successfully.",
        "data": deletedTransactions
      });
    } catch (err) {
      res.status(500).json({
        "Status": false,
        "type": "delete-data",
        "Error": err.message
      });
    }
  });

  router.delete("/transactions/delete/byGoal/:goalId", authenticateToken, async (req, res) => {
    try {
      const goalId = req.params.goalId;
  
      const deletedTransactions = await transactionSchema.deleteMany({ goalId });
  
      res.status(200).json({
        "Status": true,
        "type": "delete-data",
        "Message": "OK, Transactions deleted successfully.",
        "data": deletedTransactions
      });
    } catch (err) {
      res.status(500).json({
        "Status": false,
        "type": "delete-data",
        "Error": err.message
      });
    }
  });

  router.delete("/transactions/delete/byAccount/:accountId", authenticateToken, async (req, res) => {
    try {
      const accountId = req.params.accountId;
  
      const deletedTransactions = await transactionSchema.deleteMany({ accountId });
  
      res.status(200).json({
        "Status": true,
        "type": "delete-data",
        "Message": "OK, Transactions deleted successfully.",
        "data": deletedTransactions
      });
    } catch (err) {
      res.status(500).json({
        "Status": false,
        "type": "delete-data",
        "Error": err.message
      });
    }
  });
  
  module.exports = router;