// Import necessary modules and configuration items
import express from "express";
import bodyParser from "body-parser";
import { BASE_USER_PORT, BASE_ONION_ROUTER_PORT } from "../config";
import {
  createRandomSymmetricKey,
  symEncrypt,
  rsaEncrypt,
  exportSymKey
} from "../crypto";
import { Node, GetNodeRegistryBody } from "@/src/registry/registry";

// Define the user function which creates an express application
export async function user(userId: number) {
  const app = express();
  app.use(express.json()); // Use middleware to parse JSON request bodies
  app.use(bodyParser.json()); // Use bodyParser to parse JSON request bodies (might be redundant)

  // Initialize state variables to store message and circuit information
  let lastReceivedMessage: string | null = null;
  let lastSentMessage: string | null = null;
  let lastCircuit: Node[] = [];

  // Define a route to check if the user's server is running
  app.get("/status", (req, res) => {
    res.send("live");
  });

  // Define a route to handle incoming messages
  app.post("/message", (req, res) => {
    // Store the last received message and log it
    lastReceivedMessage = req.body.message;
    console.log(`Received message: ${lastReceivedMessage}`);
    res.status(200).send("Message received successfully");
  });

  // Define routes to retrieve the last received and sent messages
  app.get("/getLastReceivedMessage", (req, res) => {
    res.status(200).json({ result: lastReceivedMessage });
  });

  app.get("/getLastSentMessage", (req, res) => {
    res.status(200).json({ result: lastSentMessage });
  });

  // Define a route to retrieve the last circuit used for sending a message
  app.get("/getLastCircuit", (req, res) => {
    // Map the circuit to just node IDs for the response
    res.status(200).json({ result: lastCircuit.map((node) => node.nodeId) });
  });

  // Define a route for sending a message to another user
  app.post("/sendMessage", async (req, res) => {
    // Extract the message and destination user ID from the request body
    const { message, destinationUserId } = req.body;

    // Fetch the list of available nodes from the node registry
    const nodes = await fetch(`http://localhost:8080/getNodeRegistry`)
      .then((res) => res.json() as Promise<GetNodeRegistryBody>)
      .then((body) => body.nodes);

    // Randomly select a circuit of 3 unique nodes
    let circuit: Node[] = [];
    while (circuit.length < 3) {
      const randomNode = nodes[Math.floor(Math.random() * nodes.length)];
      if (!circuit.includes(randomNode)) {
        circuit.push(randomNode);
      }
    }

    // Prepare the message for encryption and routing
    let destination = `${BASE_USER_PORT + destinationUserId}`.padStart(10, "0");
    let finalMessage = message;
    for (const node of circuit) {
      // Encrypt the message and destination with a new symmetric key
      const symmetricKey = await createRandomSymmetricKey();
      const symmetricKey64 = await exportSymKey(symmetricKey);
      const encryptedMessage = await symEncrypt(symmetricKey, `${destination}${finalMessage}`);
      // Update the destination to the next node in the circuit
      destination = `${BASE_ONION_ROUTER_PORT + node.nodeId}`.padStart(10, '0');
      // Encrypt the symmetric key with the node's public key
      const encryptedSymKey = await rsaEncrypt(symmetricKey64, node.pubKey);
      // Combine the encrypted symmetric key and message for the next node
      finalMessage = encryptedSymKey + encryptedMessage;
    }

    // Reverse the circuit for proper routing and store the sent message and circuit
    circuit.reverse();
    lastCircuit = circuit;
    lastSentMessage = message;
    // Send the layered encrypted message to the first node in the circuit
    await fetch(`http://localhost:${BASE_ONION_ROUTER_PORT + circuit[0].nodeId}/message`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ message: finalMessage }),
    });

    // Respond that the message has been sent successfully
    res.status(200).send("Message sent successfully");
  });

  // Start the express server for the user and log the listening port
  const server = app.listen(BASE_USER_PORT + userId, () => {
    console.log(`User ${userId} is listening on port ${BASE_USER_PORT + userId}`);
  });

  // Return the express server```javascript
// Return the express server object for future use if needed
  return server;
}