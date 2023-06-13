const express = require('express');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');


const router = express.Router();
dotenv.config();

//Import of models
const userSchema = require('../models/userSchema.js');

//Login API
router.post("/login", async (req, res)=>{
        try{
                const Userdata = {
                        email: req.body.email,
                        //password: req.body.password
                }

                let jwtSecretKey = process.env.JWT_SECRET_KEY;
        
                await userSchema.findOne({ email: { $eq: req.body.email } })
                .then(async (data)=>{
                        if(data.length != 0){
                                const match = await bcrypt.compare(req.body.password, data.password);

                                if(match){
                                        let user = {
                                                time: Date(),
                                                email: req.body.email,
                                                userId: data["_id"]
                                        };
                                        const token = jwt.sign(user, jwtSecretKey, { expiresIn: '1h' });              
                                        res.status(200).json({"Status": true, "Bearer Token": token,"Message":"User Successfully logged In !", "Users Details" : data[0]});  

                                }else{
                                        res.status(200).json({"Status":false,"Message": "User Not registered / Incorrect Password!"})
                                }
                        }else{
                                res.status(200).json({"Status":false,"Message": "User Not registered / Incorrect Password!"})
                        }
                        }).catch((err)=>{
                                res.status(500).json({"Status": false, "Error": err.message})
                        })
        } catch(err){
            res.status(500).json({"Status": false, "Error": err.message })
        }
})   

//SignUp API
router.post('/signup', async (req, res) => {
        try{
            const userSchemaData = new userSchema({
                //userId: req.body.userId,
                userName: req.body.userName,
                password: req.body.password,
                email: req.body.email,
                createTimeStamp: Date.now()
            })

            let jwtSecretKey = process.env.JWT_SECRET_KEY;

            // Hash the password
            const hashedPassword = await bcrypt.hash(req.body.password, 10);
            userSchemaData.password = hashedPassword;

            await userSchema.findOne({email: {$eq: req.body.email}}).then((data)=>{
                //console.log(data)
                if(data == null){
                        userSchemaData.save().then((data) => {
                                let user = {
                                        time: Date(),
                                        email: req.body.email,
                                        userId: data["_id"]
                                }
                                
                                const token = jwt.sign(user, jwtSecretKey, { expiresIn: '1h' }); 
                                
                            res.status(200).json({"Status": true, "Bearer Token": token,"Message":"User Successfully logged In !", "Users Details" : data});  
                        });
                }else{
                    res.status(200).json({"Status": false, "Message":"User already registered with the given email!"});
                }
            }).catch((err) => {
                res.status(500).json({"Status": false, "Error": err.message})
               })

        }catch(err) {
                console.error(err);
                res.status(500).json({"Status": false, "Error": err.message})
        }
})

//Forget Password
router.post("/forgetpassword", async (req, res)=>{
        try{
                const UserdataId = {
                        email: req.body.email
                }
                
                const UserdataUpdate = {
                        password: req.body.password
                }

            await userSchema.updateOne(UserdataId,{$set:UserdataUpdate}).then((data)=>{
                //console.log(data)
                if(data['acknowledged'] == true){
                        res.status(200).json({"Status": true,"Message":"OK, Password Reset successful","Users data" : data});  
                }else{
                        res.status(200).json({"Status":false,"Message": "User Not registered / Incorrect email!"})
                }
                }).catch((err)=>{
                        res.status(500).json({"Status": false, "Error": err.message })
                })
        } catch(err){
            res.status(500).json({"Status":false, "Error": err.message })
        }
})   

module.exports = router;
