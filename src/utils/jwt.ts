import crypto from "crypto";
import jwt, { type SignOptions } from "jsonwebtoken";

import type { IUser } from "../models/user.js";

// JWT configuration
const JWT_SECRET = process.env.JWT_SECRET ?? crypto.randomBytes(64).toString("hex");
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN ?? "24h";
const JWT_REFRESH_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN ?? "7d";

export interface JWTPayload {
  userId: string;
  username: string;
  type: "access" | "refresh";
  iat?: number; // issued at
  exp?: number; // expires at
  iss?: string; // issuer
  aud?: string; // audience
}

/**
 * Generate an access token for a user
 */
export function generateAccessToken(user: IUser): string {
  const payload: JWTPayload = {
    userId: user.id,
    username: user.username,
    type: "access",
  };

  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
    issuer: "watchthis-user-service",
    audience: "watchthis-services",
  } as SignOptions);
}

/**
 * Generate a refresh token for a user
 */
export function generateRefreshToken(user: IUser): string {
  const payload: JWTPayload = {
    userId: user.id,
    username: user.username,
    type: "refresh",
  };

  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: JWT_REFRESH_EXPIRES_IN,
    issuer: "watchthis-user-service",
    audience: "watchthis-services",
  } as SignOptions);
}

/**
 * Verify and decode a JWT token
 */
export function verifyToken(token: string): JWTPayload {
  return jwt.verify(token, JWT_SECRET, {
    issuer: "watchthis-user-service",
    audience: "watchthis-services",
  }) as JWTPayload;
}

/**
 * Generate both access and refresh tokens for a user
 */
export function generateTokenPair(user: IUser) {
  return {
    accessToken: generateAccessToken(user),
    refreshToken: generateRefreshToken(user),
    expiresIn: JWT_EXPIRES_IN,
  };
}
