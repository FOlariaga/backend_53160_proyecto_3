import { Router } from "express";
import passport from 'passport';


import config from "../config.js";
import UserController from "../controller/user.controller.js";
import { createHash, verifyRequiredBody } from "../services/utils.js";
import initAuthStrategies from '../auth/passport.strategies.js';

const controller = new UserController()
const router = Router()
initAuthStrategies();

router.get("/", async (req, res) => {
    try {
        const users = await controller.get()

        res.status(200).send({ origin: config.SERVER, payload: users })
    } catch (error) {
        res.status(500).send({ origin: config.SERVER, payload: null })
    }
})

router.get("/:pid", async (req, res) => {
    try {
        const pid = req.params.pid
        const user = await controller.getById(pid)

        res.status(200).send({ origin: config.SERVER, payload: user })
    } catch (error) {
        res.status(500).send({ origin: config.SERVER, payload: null })
    }
})

// router.post("/register", verifyRequiredBody(['firstName', 'lastName', 'email', 'password']), async (req, res) => {
//     try {
//         const { firstName, lastName, email, password } = req.body
//         const user = await usersManager.add({ firstName, lastName, email, password: createHash(password)})

//         console.log(user);
//         console.log(user.exist);
//         if (user.exist) {
//            return  res.status(200).send({ origin: config.SERVER, payload: user.payload });
//         }
//         res.redirect("/login")

//     } catch (error) {
//         res.status(500).send({ origin: config.SERVER, payload: null })
//     }
// })


router.post("/register", verifyRequiredBody(['firstName', 'lastName', 'email', 'password']), passport.authenticate("register",{ failureRedirect: `/register?error=${encodeURI('error para registrar al usuario')}`}), async (req, res) => {
    try {
        res.redirect("/login")
    } catch (err) {
        res.status(500).send({ origin: config.SERVER, payload: null })
    }
})


router.put("/:pid", async (req, res) => {
    try {
        const filter = { _id: req.params.pid };
        const update = req.body;
        const options = { new: true };
        const user = await controller.update(filter, update, options);

        res.status(200).send({ origin: config.SERVER, payload: user });
    } catch (error) {
        res.status(500).send({ origin: config.SERVER, payload: null })
    }
})

router.delete("/:uid", async (req, res) => {
    try {
        const uid = { _id: req.params.uid }
        await controller.delete(uid);
        console.log(`usuario eliminado de la base de datos`);

        res.status(200).send({ origin: config.SERVER, payload: "eliminado" });
    } catch (error) {
        res.status(500).send({ origin: config.SERVER, payload: null })
    }
})

export default router