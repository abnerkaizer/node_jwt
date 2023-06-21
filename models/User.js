const mongoose = require("mongoose");

//mongoose precisa ter um modelo do dado a ser armazenado.
const User = mongoose.model("User", {
  name: String,
  email: String,
  password: String,
});

module.exports = User;
