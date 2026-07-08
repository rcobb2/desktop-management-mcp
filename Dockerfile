# Builds both MCP servers from one image. The JAMF server runs by default;
# the Intune container overrides the command via the Podman quadlet's Exec=
# (see IAC/ansible-servers/linux/apps/desktop-management-mcp.yml).
FROM node:24-alpine
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci
COPY src ./src
RUN npm run build && npm prune --omit=dev
USER node
EXPOSE 3001 3002
CMD ["node", "dist/src/mcp/jamf-server.js"]
