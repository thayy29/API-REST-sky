const express = require('express')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const authConfig = require('../config/auth')

const User = require('../models/User')

const router = express.Router()


function generateToken(params = {}) {
  return jwt.sign(params, authConfig.secret, {
    expiresIn: 1800,
  })
}

// Rota de registro
router.post('/register', async (req, res) => {

  const {
    email
  } = req.body;

  try {

    if (await User.findOne({
        email
      }))

      return res.status(400).send({
        error: 'E-mail já existente'
      });


    const user = await User.create(req.body)

    user.password = undefined;



    return res.send({
      user,
      token: generateToken({
        id: user.id
      }),
    });

  } catch (err) {
    return res.status(400).send({
      error: 'Registration failed'
    });
  }
});


// Rota de autenticação
router.post('/authenticate', async (req, res) => {
  const {
    email,
    password
  } = req.body
  const user = await User.findOne({
    email
  }).select('+password');


  // Verificação se o usuário existe

  if (!user)
    return res.status(400).send({
      error: 'Usuário e/ou senha inválidos'
    });

  // Verificar se a senha inserida é a mesma que foi cadastrada
  if (!await bcrypt.compare(password, user.password))
    return res.status(400).send({
      error: 'Usuário e/ou senha inválidos'
    });


  user.password = undefined;

  // Gerar token
  const token = jwt.sign({
    id: user.id
  }, authConfig.secret, {
    expiresIn: 1800,
  })


  res.send({
    user,
    token: generateToken({
      id: user.id
    }),
  });
});






module.exports = app => app.use('/auth', router)