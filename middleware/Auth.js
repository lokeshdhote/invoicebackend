const jwt = require('jsonwebtoken');
const { catchAsyncError } = require('./CatchAsyncError');
const Errorhandler = require('../utlis/Errorhandler');
const user = require('../models/usermodel');


exports.isLoggedIn = catchAsyncError(async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer")) {
    return next(new Errorhandler("Please log in to access this resource", 401));
  }

  // Extract the token (remove 'Bearer ' from the beginning)
  const token = authHeader.split(" ")[1];

  if (!token || token === "null") {
    return next(new Errorhandler("Please log in to access this resource", 401));
  }

  // Verify the token
  const decodedData = jwt.verify(token, process.env.JWT_SECRET);
  req.user = await user.findById(decodedData.id);

  next();
});
