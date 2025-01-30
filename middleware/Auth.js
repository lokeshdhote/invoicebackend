const jwt = require('jsonwebtoken');
const ErrorHandler = require("../utlis/Errorhandler");
const { catchAsyncError } = require('./CatchAsyncError');


exports.isLoggedIn = catchAsyncError(async (req, res, next) => {
  const { token } = req.cookies;

  // Check if token exists in cookies
  if (!token) {
    return next(new ErrorHandler("Please login to access the resource", 401));
  }

  try {
    // Verify JWT
    const decoded = jwt.verify(token, process.env.JWT);

    // Add user information to the request object
    req.id = decoded;

    next();
  } catch (error) {
    // Handle errors (e.g., token expired, invalid token)
    return next(new ErrorHandler("Invalid or expired token", 401));
  }
});
