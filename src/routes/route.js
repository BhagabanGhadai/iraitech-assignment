const express=require('express')
const router=express.Router()

const {signup,
    login,
    getProfile,
    getAllUserProfile,
    editUser}=
    require('../controllers/userController')

const {authentication}=require('../middleware/auth')

router.post('/signup',signup)
router.post('/login',login)
router.get('/user',getAllUserProfile)
router.get('/user/:userId',authentication,getProfile)
router.put('/user/:userId',authentication,editUser)

module.exports=router