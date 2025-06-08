const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
// const { type } = require('os');

// define the person schema

const UserSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    age: {
        type: Number,
        required: true
    },

    mobile: {
        type: String
        // required: true
    },
    email: {
        type: String
        // required: true,
        // unique: true
    },
    address: {
        type: String,
        required: true
    },
    aadharCardNumber: {
        type: Number,
        required: true,
        unique: true
    }, 
    password: {
        type: String,
        required: true
    },
    role: {
        type: String,
        enum: ['voter', 'admin', ],
        default: 'voter'
    },
    isVoted: { 
        type: Boolean,
        default: false
    }
     
});

UserSchema.pre('save', async function(next){
    const user = this;

    // Hash the password only if it has been modified (or is new)
    if(!user.isModified('password')) return next();
    try{
        // hash password generation
        const salt = await bcrypt.genSalt(10);

        // hash password
        const hashedPassword = await bcrypt.hash(user.password, salt);
        
        // Override the plain password with the hashed one
        user.password = hashedPassword;
        next();
    }catch(err){
        return next(err);
    }
})

UserSchema.methods.comparePassword = async function(candidatePassword){
    try{
        // Use bcrypt to compare the provided password with the hashed password
        const isMatch = await bcrypt.compare(candidatePassword, this.password);
        return isMatch;
    }catch(err){
        throw err;
    }
}

const User = mongoose.model('User', UserSchema);
module.exports = User;