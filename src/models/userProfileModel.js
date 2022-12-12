const mongoose = require("mongoose");

const userProfileSchema = new mongoose.Schema({

  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref:"user"
  }
}, { timestamps: true })


module.exports = mongoose.model('userProfile', userProfileSchema)