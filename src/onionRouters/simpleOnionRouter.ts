import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import http from "http";
import { generateRsaKeyPair, exportPubKey, exportPrvKey, rsaDecrypt, symDecrypt } from "../crypto";

// This function initializes an onion router with a given node ID and sets up its routes and functionality.
export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json()); // Middleware for parsing JSON requests
  onionRouter.use(bodyParser.json()); // Additional middleware for parsing JSON requests

  // RSA key pair generation for secure communication
  const { publicKey, privateKey } = await generateRsaKeyPair();

  // Conversion of RSA keys to base64 strings for network transmission
  let privateKeyBase64 = await exportPrvKey(privateKey);
  let pubKeyBase64 = await exportPubKey(publicKey);

  // Node registration with the network's registry service
  const data = JSON.stringify({ nodeId, pubKey: pubKeyBase64 });
  const options = {
    hostname: 'localhost',
    port: REGISTRY_PORT,
    path: '/registerNode',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': data.length,
    },
  };

  // Send registration data to the registry
  const req = http.request(options, (res) => {
    // Handle the registry's response
    res.on('data', (chunk) => {
      console.log(`Response: ${chunk}`);
    });
  });
  req.on('error', (error) => {
    // Handle any errors during registration
    console.error(`Problem with request: ${error.message}`);
  });
  req.write(data);
  req.end();

  // Route to check the operational status of the router
  onionRouter.get("/status/", (req, res) => {
    res.send("live");
  });

  // State variables to store message data
  let lastReceivedEncryptedMessage: string | null = null;
  let lastReceivedDecryptedMessage: string | null = null;
  let lastMessageDestination: number | null = null;

  // Routes to retrieve the last processed message information
  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
    res.json({ result: lastReceivedEncryptedMessage });
  });
  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
    res.json({ result: lastReceivedDecryptedMessage });
  });
  onionRouter.get("/getLastMessageDestination", (req, res) => {
    res.json({ result: lastMessageDestination });
  });

  // Route to expose the router's private key (security risk in a real-world scenario)
  onionRouter.get("/getPrivateKey", (req, res) => {
    res.json({ result: privateKeyBase64 });
  });

  // Route to handle incoming encrypted messages
  onionRouter.post("/message", async (req, res) => {
    const { message } = req.body; // Retrieve the message from the request body

    // Decrypt message components and determine the next destination
    const decryptedKey = await rsaDecrypt(message.slice(0, 344), privateKey);
    const decryptedMessage = await symDecrypt(decryptedKey, message.slice(344));
    const nextDestination = parseInt(decryptedMessage.slice(0, 10), 10);
    const remainingMessage = decryptedMessage.slice(10);

    // Update state with the latest message information
    lastReceivedEncryptedMessage = message;
    lastReceivedDecryptedMessage = remainingMessage;
    lastMessageDestination = nextDestination;

    // Forward the remaining message to the next router in the chain
    await fetch(`http://localhost:${nextDestination}/message`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: remainingMessage }),
    });
    res.status(200).send("success");
  });

  // Start the onion router server on a port derived from the node ID
  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(`Onion router ${nodeId} is listening on port ${BASE_ONION_ROUTER_PORT + nodeId}`);
  });

  return server;
}