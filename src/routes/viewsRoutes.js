import { Router} from "express";
import ProductController from "../controller/product.controller.js";
import CartController from "../controller/cart.controller.js";
import { authorizationRole } from "../services/utils.js";

const productController = new ProductController()
const cartController = new CartController()

const router = Router()

router.get("/products", async (req, res) => {
    const products = await productController.get({limit: req.query.limit || 10, page: req.query.page || 1, query : req.query.query || "" });

    res.render("products", {data: Object.assign(products,{category : req.query.query || ""})})
})

router.get("/product/:pid", async (req, res) => {
    const pid = req.params.pid
    const product = await productController.getById(pid)

    res.render("detail", { data: product })
})


router.get("/chat", authorizationRole(["user"]), async (req, res) => {
    res.render("chat", {})
})

router.get("/cart", async (req, res) => {
    if (!req.session.user) {
        return res.redirect("/login")
    }

    const cart = await cartController.getByuser(req.session.user._id)
    res.render("cart", {data: cart})
})

router.get("/cart/:cid", async (req, res) => {
    const cid = req.params.cid
    const cart = await cartController.getById(cid)
    console.log(cart);
    res.render("cart", {data: cart})
})

router.get("/login", async (req, res) => {
    if(req.session.user){
        return res.redirect("/products")
    }
    res.render("login", {})
})

router.get("/register", async (req, res) => {
    res.render("register", {})
})

router.get("/profile", async (req, res) => {

    if(!req.session.user){
        return res.redirect("/login")
    }
    res.render("profile", {user: req.session.user})
})

export default router