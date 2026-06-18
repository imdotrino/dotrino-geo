# Imagen del servidor geo (Node + pg). Sin dependencias nativas → alpine va bien.
FROM node:22-alpine

WORKDIR /app

# Instalar deps primero (cache de capa).
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

# Código del servidor (server.js, db.js, schema.sql, signature.js, rateLimiter.js).
COPY . .

ENV PORT=8090
EXPOSE 8090

CMD ["node", "server.js"]
