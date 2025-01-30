const { catchAsyncError } = require("../middleware/CatchAsyncError");

const { sendtoken } = require("../utlis/SendToken");
const ErrorHandler = require("../utlis/Errorhandler");
const User = require("../models/usermodel");
const Invoice = require("../models/Invoice,");



exports.home = catchAsyncError(async (req, res) => {
  res.json({ message: "Secure homepage" });

});


exports.register = catchAsyncError(async (req, res, next) => {
    try {
 
  
      const user = await new User(req.body).save();
      sendtoken(user, 200, res);
  
    } catch (error) {
      next(error);
    }
  });
  exports.loggedin = catchAsyncError(async (req, res) => {
    const user = await User.findById(req.id.id).exec();
 
    res.status(200).json({ user});

  });
  exports.login = catchAsyncError(async (req, res, next) => {
    const user = await User.findOne({ email: req.body.email })
      .select("+password") // Ensure the password is included
      .exec();
  
    if (!user) {
      return next(new ErrorHandler("User with this email not found", 404));
    }
  
    // Compare the provided password with the stored hashed password
    const isMatch = await user.comparepassword(req.body.password);
  
    if (!isMatch) {
      return next(new ErrorHandler("Wrong credentials", 401));
    }
  
    sendtoken(user, 200, res);
  });
  
  
  exports.signout = catchAsyncError(async (req, res) => {
    res.clearCookie("token");
    res.json({ message: "Signed out successfully" });
  });
  exports.createInvoice = catchAsyncError(async (req, res) => {
    try {
     
      
      
      const { customer, invoiceNumber, total, items } = req.body;
      
      if (!customer || !customer.name || !customer.address) {
        return res.status(400).json({ message: "Customer name and address are required." });
      }
      if (!invoiceNumber) {
        return res.status(400).json({ message: "Invoice number is required." });
      }
      if (!total) {
        return res.status(400).json({ message: "Total amount is required." });
      }
      if (!items) {
        return res.status(400).json({ message: "Total amount is required." });
      }
  
      const newInvoice = await new Invoice(req.body).save();
  
      res.status(200).json(newInvoice);
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Failed to create invoice", error });
    }
  });
  
 // Get all invoices
exports.getAllInvoices = async (req, res) => {
  try {
    const invoices = await Invoice.find();
    res.status(200).json({invoices});
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to get invoices", error });
  }
};