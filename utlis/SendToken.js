exports.sendtoken = function (data, statusCode, res) {
  try {
    // Generate JWT token
    const token = data.getjwttoken();
    console.log(token + "send");

    // Ensure the environment variable is defined and convert it to a number
    if (!process.env.COOKIE_EXPIRE) {
      throw new Error("COOKIE_EXPIRE environment variable is not set");
    }      

    // Calculate cookie expiration time
    const options = {
      expires: new Date(
        Date.now() + Number(process.env.COOKIE_EXPIRE * 1000 * 60 * 60 * 24)
      ),
      httpOnly: true,
      // secure: true,  // Uncomment this line when using HTTPS in production
    };

    // Set the cookie and respond with success
    res.status(statusCode).cookie("token", token, options).json({
      Success: true,
      token,
      data,
      message: "User logged in successfull",
    });
  } catch (error) {
    console.error("Error in sendtoken function:", error.message); // Log the error for debugging

    // Respond with an error message
    res.status(500).json({
      Success: false,
      message:
        "An error occurred while generating or setting the token. Please try again.",
      error: error.message, // Optionally provide the error message
    });
  }
};
