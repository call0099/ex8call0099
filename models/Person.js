const mongoose = require('mongoose')

const schema = new mongoose.Schema({
  name: {
    first: { type: String, trim: true, maxlength: 64, required: true },
    last: { type: String, trim: true, maxlength: 64, required: true },
    nick: { type: String, trim: true, maxlength: 64 }
  },
  email: { type: String, trim: true, maxlength: 512 },
  birthDate: Date
})

const Model = mongoose.model('Person', schema)

module.exports = Model
