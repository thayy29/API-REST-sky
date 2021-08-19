const jwt = require('jsonwebtoken');
const authConfig = require('../config/auth')

// Verificar se o token está com erro de formatação
module.exports = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader)
    return res.status(401).send({
      error: 'Não autorizado'
    });

  const parts = authHeader.split(' ');

  if (!parts.length === 2)
    return res.status(401).send({
      error: 'Erro Token'
    })

  const [scheme, token] = parts;

  if (!/^Bearer$/i.test(scheme))
    return res.status(401).send({
      error: 'Token malformatted'
    });


  // Verificar se o token é o mesmo do usuário que está pedindo a requisição
  jwt.verify(token, authConfig.secret, (err, decoded) => {
    if (err) return res.status(401).send({
      error: 'Token inválido'
    });

    req.userId = decoded.id;
    return next();
  })
}