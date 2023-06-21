require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
//Config JSON response
app.use(express.json());

//Models

const User = require("./models/User");

//Public route
app.get("/", (req, res) => {
  res.status(200).json({ message: "Bem-vindo à nossa API" });
});

//Resgistrar usuario

app.post("/auth/register/", async (req, res) => {
  const { name, email, password, confirmpassword } = req.body;
  //validações
  if (!name) {
    return res.status(422).json({ message: "O nome é obrigatório." });
  }
  if (!email) {
    return res.status(422).json({ message: "O email é obrigatório." });
  }
  if (!password) {
    return res.status(422).json({ message: "O senha é obrigatória." });
  }
  if (!(password == confirmpassword)) {
    return res
      .status(422)
      .json({ message: "Confirmar senha precisa ser igual." });
  }
  //Checar se o usuario já existe
  const userExists = await User.findOne({ email: email });
  if (userExists) {
    return res
      .status(422)
      .json({ message: "Usuário já existe, utilize outro email." });
  }
  //Criar senha
  const salt = await bcrypt.genSalt(12);
  const passHash = await bcrypt.hash(password, salt);
  //Criar usuário

  const user = new User({
    name,
    email,
    password: passHash,
  });

  try {
    await user.save();
    res.status(201).json({ message: "Usuário criado com sucesso." });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      error: "Ocorreu um erro no servidor, tente novamente mais tarde !",
    });
  }
});

//Login

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email) {
    return res.status(422).json({ message: "O email é obrigatório." });
  }
  if (!password) {
    return res.status(422).json({ message: "O senha é obrigatória." });
  }
  //Checar se o usuario já existe
  const user = await User.findOne({ email: email });
  if (!user) {
    return res.status(404).json({ message: "Usuário não existe." });
  }

  //Checar a senha
  const checkPass = await bcrypt.compare(password, user.password);
  if (!checkPass) {
    return res.status(422).json({ message: "Senha inválida." });
  }
  try {
    const secret = process.env.SECRET;
    const token = jwt.sign(
      {
        id: user._id,
      },
      secret
    );
    res
      .status(200)
      .json({ message: "Autenticação realizada com sucesso.", token });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      error: "Ocorreu um erro no servidor, tente novamente mais tarde !",
    });
  }
});
//Private route

app.get("/user/:id", checkToken, async (req, res) => {
  const id = req.params.id;

  const user = await User.findById(id, "-password");
  if (!user) {
    return res.status(404).json({ message: "Usuário não encontrado." });
  }
  res.status(200).json({ user });
});

function checkToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "Acesso negado." });
  }
  try {
    const secret = process.env.SECRET;

    jwt.verify(token, secret);

    next();
  } catch (error) {
    res.status(400).json({ message: "Token inválido" });
  }
}
//Credenciais
const dbUser = process.env.DB_USER;
const dbPass = process.env.DB_PASSWORD;

mongoose
  .connect(
    `mongodb+srv://${dbUser}:${dbPass}@nodejwt.cw8mieu.mongodb.net/database?retryWrites=true&w=majority`
  )
  .then(() => {
    app.listen(3000);
    console.log("Conectou ao MongoDB.");
  })
  .catch((err) => console.log(err));
//mongodb+srv://:@nodejwt.cw8mieu.mongodb.net/?retryWrites=true&w=majority
