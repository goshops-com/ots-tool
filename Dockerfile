FROM node:alpine

WORKDIR /app

# Install dependencies
COPY package.json package-lock.json ./
RUN npm install

# Copy source code and frontend
COPY index.js .
COPY public public/

EXPOSE 3000

CMD ["node", "index.js"]
