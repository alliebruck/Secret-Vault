FROM node:24-bookworm-slim

WORKDIR /app

ENV NODE_ENV=development
ENV NODE_OPTIONS=--experimental-sqlite

COPY package*.json ./
RUN npm install

COPY . .

EXPOSE 4000 5173

CMD ["npm", "run", "dev:docker"]
