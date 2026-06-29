import "dotenv/config";
import Fastify from "fastify";
import { registerRoutes } from "./routes.js";

const app = Fastify({ logger: { redact: ["req.headers.authorization", "*.privateKey", "*.secret", "*.note_secret"] } });
await registerRoutes(app);

const port = Number(process.env.API_PORT ?? 8080);
await app.listen({ port, host: "0.0.0.0" });
