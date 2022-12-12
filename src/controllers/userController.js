const bcrypt = require('bcrypt')
const jwt=require('jsonwebtoken')
const userModel=require('../models/userModel')
const userProfileModel=require('../models/userProfileModel')
const {uploadFile}= require('../util/aws_sdk')
const validator=require('../util/validatons')

const signup = async function (req, res) {
    try {
        let files = req.files;
        let userDetails = req.body
        let {name,email,password}=userDetails

        if (!validator.isValidRequestBody(userDetails)) {
            return res.status(400).send({ status: false, message: "please provide valid user Details" })
        }

        if (!validator.isValid(name)) {
            return res.status(400).send({ status: false, message: "user name is required" })
        }
     
        if (!validator.isValid(email)) {
            return res.status(400).send({ status: false, message: "Email-ID is required" })
        }

        if (!validator.isValidEmail(userDetails.email))
            return res.status(400).send({ status: false, message: "Invalid Email id." })

        const checkEmailFromDb = await userModel.findOne({ email })

        if (checkEmailFromDb) {
            return res.status(400).send({ status: false, message: `emailId is Exists. Please try another email Id.` })
        }

        if (!files.length) {
            return res.status(400).send({ status: false, message: "Profile Image is required" })
        }

        if (!validator.isValid(password)) {
            return res.status(400).send({ status: false, message: "password is required" })
        }

      
        let userImage = await uploadFile(files[0]);

        const hashedPassword = await bcrypt.hash(password, 10)

        userDetails.profileImage = userImage
        userDetails.password = hashedPassword

        const saveUserInDb = await userModel.create(userDetails);
        await userProfileModel.create({user:saveUserInDb._id})

        return res.status(201).send({ status: true, message: "user created successfully!!", data: saveUserInDb });

    } catch (err) {

        return res.status(500).send({ status: false, error: err.message })

    }

}

/**Login Api */

const login = async function (req, res) {

    try {

        const loginDetails = req.body;

        const { email, password } = loginDetails;

        if (!validator.isValidRequestBody(loginDetails)) {
            return res.status(400).send({ status: false, message: 'Please provide login details' })
        }
        if (!validator.isValid(email)) {
            return res.status(400).send({ status: false, message: 'Email-Id is required' })
        }
        if (!validator.isValid(password)) {
            return res.status(400).send({ status: false, message: 'Password is required' })
        }
        const userData = await userModel.findOne({ email });

        if (!userData) {
            return res.status(401).send({ status: false, message: `Login failed!! Email-Id is incorrect!` });
        }

        const checkPassword = await bcrypt.compare(password, userData.password)

        if (!checkPassword) return res.status(401).send({ status: false, message: `Login failed!! password is incorrect.` });
        let userId=userData._id
        const token = jwt.sign({
            userId: userId,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + 24 * 60 * 60
        }, "BYRD87KJVUV%^%*CYTC")

        return res.status(200).send({ status: true, message: "LogIn Successful!!", data: {userId:userId,Token:token} });

    } catch (err) {
        return res.status(500).send({ status: false, error: err.message });
    }
}

/**get profile Api */

const getProfile = async function (req, res) {
    try {
        const userId = req.params.userId
        const userIdFromToken = req.userId

        if (!validator.isValidObjectId(userId)) {
            return res.status(400).send({ status: false, message: "Invalid userId" })
        }

        const findUserDetails = await userModel.findById(userId)
        if (!findUserDetails) {
            return res.status(404).send({ status: false, message: "User Not Found!!" })
        }

        if (findUserDetails._id.toString() != userIdFromToken) {
            return res.status(403).send({ status: false, message: "You Are Not Authorized!!" });
        }

        return res.status(200).send({ status: true, message: "Profile Fetched Successfully!!", data: findUserDetails })

    } catch (err) {
        return res.status(500).send({ status: false, error: err.message })
    }
}

/**get All user Api */

const getAllUserProfile = async function (req, res) {
    try {
        const findUserDetails = await userModel.find()

        if (!findUserDetails) {
            return res.status(404).send({ status: false, message: "No Data Found!!" })
        }

        return res.status(200).send({ status: true, message: "Profile Fetched Successfully!!", data: findUserDetails })

    } catch (err) {
        return res.status(500).send({ status: false, error: err.message })
    }
}

/**Edit User */

const editUser = async function (req, res) {
    try {
        let files = req.files
        let userDetails = req.body
        let userId = req.params.userId
        let userIdFromToken = req.userId

        if (!validator.isValidObjectId(userId)) {
            return res.status(400).send({ status: false, message: "Invalid UserId" })
        }
        const findUserData = await userModel.findById(userId)
        if (!findUserData) {
            return res.status(404).send({ status: false, message: "user not found" })
        }
        if (findUserData._id.toString() != userIdFromToken) {
            return res.status(403).send({ status: false, message: "You Are Not Authorized!!" })
        }

        let { name,email,password} = userDetails
        
        if (!validator.isValidRequestBody(userDetails)) {
            return res.status(400).send({ status: false, message: "Please provide user's details to update." })
        }
        if (!validator.validString(name)) {
            return res.status(400).send({ status: false, message: 'first name is Required' })
        }
        if (!validator.validString(email)) {
            return res.status(400).send({ status: false, message: 'email is Required' })
        }
        if (email) {
            if (!validator.isValidEmail(email))
                return res.status(400).send({ status: false, message: "Invalid Email id." })

            const checkEmailFromDb = await userModel.findOne({ email: userDetails.email })

            if (checkEmailFromDb)
                return res.status(404).send({ status: false, message: `emailId is Exists. Please try another email Id.` })
        }


        if (!validator.validString(password)) {
            return res.status(400).send({ status: false, message: 'password is Required' })
        }

        if (password) {

            if (!(password.length >= 8 && password.length <= 15)) {
                return res.status(400).send({ status: false, message: "Password should be Valid min 8 and max 15 " })
            }
            var hashedPassword = await bcrypt.hash(password, 10)
            
        }

        if (files&&files.length) {
            var userImage = await uploadFile(files[0])
        }
     
        let updatedData={
            name:name,
            email:email,
            password:hashedPassword,
            profileImage:userImage,
        }
    

        let updateProfileDetails = await userModel.findOneAndUpdate(
            { _id: userId },
              updatedData,
            { new: true })

        return res.status(200).send({ status: true, msg: "User Update Successful!!", data: updateProfileDetails })

    } catch (err) {
        return res.status(500).send({ status: false, error: err.message })
    }
}
module.exports={signup,login,getProfile,getAllUserProfile,editUser}