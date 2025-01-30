const mongoose = require("mongoose");
var bcrypt = require("bcryptjs");
var jwt = require("jsonwebtoken");

const userSchema = new mongoose.Schema(
  {
    username:{
      type:String,
      required: [true, "Email is required"],
    },
    email: {
      type: String,
      unique: true,
      required: [true, "Email is required"],
      match: [
        /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/,
        "Please provide a valid email address",
      ],
    },
    BusinessName:{
      type:String,

    },
    password: {
      type: String,
      select: false,
      required: [true, "Password is required"],
      
    },

    // gender: {
    //   type: String,
    //   required: [true, "Gender is required"],
    // },
   
   
    // contact: {
    //   type: Number,
    //   required: [true, "Contact is required"],
    // },
    // dateOfBirth: {
    //   type: Date, // Adding the date of birth field
    //   required: [true, "Date of birth is required"],
    // },
    resetPasswordToken: {
      type: String,
      default: "0",
    },
},
  { timestamps: true }
);

// Pre-save middleware to hash password
userSchema.pre("save", function () {
  if (!this.isModified("password")) {
    return;
  }
  let salt = bcrypt.genSaltSync(10);
  this.password = bcrypt.hashSync(this.password, salt);
});

// Method to compare passwords
userSchema.methods.comparepassword = function (password) {
  return bcrypt.compareSync(password, this.password);
};

// Method to generate JWT token
userSchema.methods.getjwttoken = function () {
  return jwt.sign({ id: this._id }, process.env.JWT, {
    expiresIn: process.env.JWT_EXPIRE,
  });
};

const user = mongoose.model("user", userSchema);

module.exports = user;
