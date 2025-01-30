const mongoose = require("mongoose");

const InvoiceSchema = new mongoose.Schema({
  invoiceNumber: {
    type: Number,
    required: true,
    unique: true,
  },
  date: {
    type: Date,
    required: true,
    default: Date.now,
  },
  customer: {
    name: { type: String, required: true },
    address: { type: String, required: true },
    number: { type: String, default: "NA" }, // Optional
  },
  items: [
    {
      name: { type: String, required: true },
      quantity: { type: Number, required: true, min: 1 },
      price: { type: Number, required: true, min: 0.01 },
    },
  ],
  total: {
    type: Number,
    required: true,
  },
});

const Invoice = mongoose.model("Invoice", InvoiceSchema);
module.exports = Invoice;
