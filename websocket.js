const WebSocket = require('ws');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET || "supersecret";

function verifyAccessToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (err) {
    return null;
  }
}

function initWebSocket(server) {
  const wss = new WebSocket.Server({ server });
  const clients = new Map();

  wss.on('connection', (ws) => {
    ws.on('message', async (message) => {
      try {
        const data = JSON.parse(message);

        // Identification: { type: 'identify', accessToken, targetId }
        if (data.type === 'identify' && data.accessToken && data.targetId) {
          const userInfo = verifyAccessToken(data.accessToken);
          if (!userInfo) {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid or expired access token.' }));
            ws.close();
            return;
          }
          clients.set(ws, {
            userId: userInfo.userId,
            role: userInfo.role,
            targetId: data.targetId,
            location: null
          });
          ws.send(JSON.stringify({ type: 'identified', userId: userInfo.userId }));
          return;
        }

        // Location update: { type: 'location', lat, lng, targetId }
        if (
          data.type === 'location' &&
          typeof data.lat === 'number' &&
          typeof data.lng === 'number' &&
          typeof data.targetId === 'string' && data.targetId.length > 0
        ) {
          const clientInfo = clients.get(ws);
          if (!clientInfo) {
            ws.send(JSON.stringify({ type: 'error', message: 'Not identified.' }));
            return;
          }
          clientInfo.location = { lat: data.lat, lng: data.lng };
          console.log(`Received location from ${clientInfo.userId} for target ${data.targetId}: lat=${data.lat}, lng=${data.lng}`);

          // Find the target client to share location with
          for (const [client, info] of clients.entries()) {
            console.log(`Checking client ${info.userId} against targetId ${data.targetId}`);
            if (info.userId == data.targetId) {
              client.send(JSON.stringify({
                type: 'location-update',
                from: clientInfo.userId,
                lat: data.lat,
                lng: data.lng
              }));
              console.log(`Sent location to ${info.userId}`);
            }
          }
        }
      } catch (err) {
        ws.send(JSON.stringify({ type: 'error', message: 'Invalid message format.' }));
      }
    });

    ws.on('close', () => {
      clients.delete(ws);
    });
  });

  console.log('WebSocket server initialized');
}

module.exports = { initWebSocket };
