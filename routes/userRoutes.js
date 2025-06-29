const express = require('express');
const router = express.Router();
const User = require('./../models/user');
const {jwtAuthMiddleware, generateToken} = require('./../jwt');

//  POST route to add a person
router.post('/signup', async (req, res)=>{
    try{
        const data = req.body // assuming the request body contains the person data 
 
        //create a new user document using the mongoose model
        const newUser = new User(data);

        //save the new user to the database
        const response = await newUser.save();
        console.log('data saved');

         const payload = {
            id: response.id
         }
         console.log(JSON.stringify(payload));
         const token = generateToken(payload);
         console.log("Token is: ", token);
          res.status(200).json({response: response, token: token});
         
    }catch(err){
        console.log(err);
        res.status(500).json({error: 'Internal server error'});
    }
})

// login route
router.post('/login', async(req, res)=>{
    try{
        //extract aadharcardno and password from request body
        const {aadharCardNumber, password} = req.body;

        //find the user by aadharcardno
        const user = await User.findOne({aadharCardNumber: aadharCardNumber});

        //if user doesnot exist or password does not match, return error
        if(!user || !(await user.comparePassword(password))){
            return res.status(401).json({error: 'invalid username or password'});
        }

        //generate token
        const payload = {
            id: user.id
        }
        const token = generateToken(payload);

        //return token as response
        res.json({token})
       
    }catch(err){
        console.log(err);
        res.status(500).json({error: 'internal server error'});
    }
});

//profile route
router.put('/profile/password', jwtAuthMiddleware, async (req, res) => {
    try {
        const userId = req.user.id; // Extract the id from the token
        const { currentPassword, newPassword } = req.body; // Extract current and new passwords from request body

        // Check if currentPassword and newPassword are present in the request body
        if (!currentPassword || !newPassword) {
            return res.status(400).json({ error: 'Both currentPassword and newPassword are required' });
        }

        // Find the user by userID
        const user = await User.findById(userId);

        // If user does not exist or password does not match, return error
        if (!user || !(await user.comparePassword(currentPassword))) {
            return res.status(401).json({ error: 'Invalid current password' });
        }

        // Update the user's password
        user.password = newPassword;
        await user.save();

        console.log('password updated');
        res.status(200).json({ message: 'Password updated' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

module.exports = router;