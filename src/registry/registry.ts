// Import dependencies
import express, { Request, Response } from "express";
import { REGISTRY_PORT } from "../config"; // Import the server's port configuration

// Type definitions
export type Node = { nodeId: number; pubKey: string }; // Node structure
export type RegisterNodeBody = Node; // Request body for node registration
export type GetNodeRegistryBody = { nodes: Node[] }; // Response body for getting registered nodes

// Function to launch the registry server
export async function launchRegistry() {
    const _registry = express();
    _registry.use(express.json()); // Enable JSON parsing for request bodies

    let registeredNodes: Node[] = []; // Store for registered nodes

    // GET /status - Server status endpoint
    _registry.get("/status", (req: Request, res: Response) => {
        res.send("live");
    });

    // POST /registerNode - Register a node endpoint
    _registry.post("/registerNode", (req: Request<{}, {}, RegisterNodeBody>, res: Response) => {
        const newNode: Node = { nodeId: req.body.nodeId, pubKey: req.body.pubKey };
        registeredNodes.push(newNode); // Add new node to the registry
        res.status(200).json({ message: "Node registered successfully." });
    });

    // GET /getNodeRegistry - Retrieve all registered nodes endpoint
    _registry.get("/getNodeRegistry", (req, res) => {
        res.json({ nodes: registeredNodes });
    });

    // Start the server and listen on the configured port
    const server = _registry.listen(REGISTRY_PORT, () => {
        console.log(`Registry is listening on port ${REGISTRY_PORT}`);
    });

    return server;
}