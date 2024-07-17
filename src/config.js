import * as url from 'url';
import dotenv from "dotenv";

dotenv.config()

const config = {
    SERVER: "atlas",
    PORT: process.env.PORT || 5050,
    DIRNAME: url.fileURLToPath(new URL('.', import.meta.url)),
    get UPLOAD_DIR() { return `${this.DIRNAME}/public/img` },
    MONGODB_URI: process.env.MONGODB_URI,
    SECRET: process.env.SECRET,
    GITHUB_CLIENT_ID: process.env.GITHUB_CLIENT_ID,
    GITHUB_CLIENT_SECRET: process.env.GITHUB_CLIENT_SECRET,
    GITHUB_CALLBACK_URL : process.env.GITHUB_CALLBACK_URL,
    PERSISTENCE: process.env.PERSISTENCE || "mongo"
}

export default config;