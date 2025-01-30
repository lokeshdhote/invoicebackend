const express = require('express');

const router = express.Router();
const {
    home,
    loggedin,
    register,
    login,
    signout,
    createInvoice,
    getAllInvoices,
    
} = require("../controllers/indexcontroller");
const {isLoggedIn} = require("../middleware/Auth")

router.get('/',isLoggedIn,home );


// // for find Loggedin user 
router.get("/loggedin",isLoggedIn,loggedin)


// Registration route for freelancer
router.post('/register',register );


 // Login route for freelancer
router.post('/login',login );
//create the invoice 
router.post("/createinvoice",isLoggedIn, createInvoice);

router.get("/getallinvoice",isLoggedIn, getAllInvoices);
// Signout route for freelancer
router.get("/signout",isLoggedIn,signout)

module.exports = router;
