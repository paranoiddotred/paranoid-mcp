FROM node:22-alpine
WORKDIR /app
COPY connect.mjs .
CMD ["node", "connect.mjs", "mcp"]
