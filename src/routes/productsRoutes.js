import { Router } from "express";
import config  from "../config.js";
import { uploader } from '../services/uploader.js';
import ProductController from "../controller/product.controller.js";
import { authorizationRole } from "../services/utils.js";
// import productsModel from "../dao/models/products.model.js"

const controller = new ProductController()
const router = Router()

router.get("/", async (req, res) => {
    try {
            const products = await controller.get({limit: req.query.limit || 10, page: req.query.page || 1, query : req.query.query || ""})
            res.status(200).send({origin: config.SERVER, payload: products})
        

    } catch (error) {
        res.status(500).send({origin: config.SERVER, payload: null})
    }
})

router.get("/:pid", async (req, res) => {
    try {
        const pid = req.params.pid
        const product = await controller.getById(pid)
        console.log(product);

        res.status(200).send({origin: config.SERVER, payload: product})
    } catch (error) {
        res.status(500).send({origin: config.SERVER, payload: null})
    }
})

router.post("/",authorizationRole(["admin"]), uploader.single('thumbnails'), async (req, res) => {
    try {
        if (req.file) {
            const thumbnail = {thumbnail: req.file.originalname || ""}
            const data = {...req.body, ...thumbnail}
            const process = await controller.add(data)
            res.status(200).send({ origin: config.SERVER, payload: process });
        } else {
            const process = await controller.add(req.body)     
            res.status(200).send({ origin: config.SERVER, payload: process });
        }
        
    } catch (error) {
        res.status(500).send({origin: config.SERVER, payload: null})
    }
})

router.put("/:pid", async (req, res) => {
    try {
        const filter = { _id: req.params.pid };
        const update = req.body;
        const options = { new: true };
        const process = await controller.update(filter, update, options);
        
        res.status(200).send({ origin: config.SERVER, payload: process });
    } catch (error) {
        res.status(500).send({origin: config.SERVER, payload: null})
    }
})

router.delete("/:id", authorizationRole(["admin"]), async (req, res) => {
    try {
        const pid = {_id : req.params.id } 
        await controller.delete(pid);
        console.log(`producto eliminado de la base de datos`);

        res.status(200).send({ origin: config.SERVER, payload: "eliminado" });
    } catch (error) {
        res.status(500).send({origin: config.SERVER, payload: null})
    }
})

export default router