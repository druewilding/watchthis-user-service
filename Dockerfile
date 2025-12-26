# Multi-stage build for TypeScript compilation
# Build stage
FROM node:24-alpine AS builder

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install ALL dependencies (including devDependencies for TypeScript)
RUN npm ci

# Copy source code
COPY . .

# Generate Prisma client in builder stage
RUN npx prisma generate

# Build the TypeScript application
RUN npm run build

# Production stage
FROM node:24-alpine AS production

# Install curl and OpenSSL for health checks and Prisma
RUN apk add --no-cache curl openssl

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install only production dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy built application from builder stage
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/prisma ./prisma
COPY --from=builder /app/public ./public
COPY --from=builder /app/views ./views

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs
RUN adduser -S watchthis -u 1001

# Change ownership of app directory
RUN chown -R watchthis:nodejs /app
USER watchthis

# Expose port
EXPOSE 8583

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD curl -f http://localhost:8583/health || exit 1

# Start the application
CMD ["npm", "start"]
