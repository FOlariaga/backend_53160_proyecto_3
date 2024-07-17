import bcrypt from 'bcrypt';

import config from '../config.js';

export const createHash = password => bcrypt.hashSync(password, bcrypt.genSaltSync(10));

export const isValidPassword = (passwordToVerify, storedHash) => bcrypt.compareSync(passwordToVerify, storedHash);

export const verifyRequiredBody = (requiredFields) => {
    return (req, res, next) => {
        const allOk = requiredFields.every(field => 
            req.body.hasOwnProperty(field) && req.body[field] !== '' && req.body[field] !== null && req.body[field] !== undefined
        );
        
        if (!allOk) return res.status(400).send({ origin: config.SERVER, payload: 'Faltan propiedades', requiredFields });
  
      next();
    };
};

export const authorizationRole = (authorized) => {
    return (req, res, next) => {
        let access = false
        if (!req.session.user) {
            return res.redirect("login")
        }
        const role = req.session.user.role
        console.log(role);

        authorized.forEach(e => {
            if (e == role) {
                access = true
                return next()
            }
        })

        if (!access) {
            return res.send("usuario no autorizado")
        }
    }
}
