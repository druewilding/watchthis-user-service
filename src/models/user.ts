import { PrismaPg } from "@prisma/adapter-pg";
import bcrypt from "bcrypt";
import dotenv from "dotenv";

import { PrismaClient } from "../generated/prisma/client.js";

// Load environment variables based on NODE_ENV
const envFile = process.env.NODE_ENV === "test" ? ".env.test" : ".env";
dotenv.config({ path: envFile });

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  throw new Error("DATABASE_URL environment variable is required");
}

const url = new URL(databaseUrl);
if (!url.password) {
  throw new Error(
    "DATABASE_URL must include a password in the format: postgresql://username:password@host:port/database"
  );
}

const adapter = new PrismaPg({
  connectionString: databaseUrl,
});
const prisma = new PrismaClient({ adapter });

export interface IUser {
  id: string;
  username: string;
  password: string;
  createdAt: Date;
  updatedAt: Date;
}

export class User {
  static async findById(id: string): Promise<IUser | null> {
    return await prisma.user.findUnique({
      where: { id },
    });
  }

  static async findOne(query: { username: string }): Promise<IUser | null> {
    return await prisma.user.findUnique({
      where: { username: query.username },
    });
  }

  static async find(): Promise<IUser[]> {
    return await prisma.user.findMany({
      orderBy: { createdAt: "desc" },
    });
  }

  static async create(userData: { username: string; password: string }): Promise<IUser> {
    const hashedPassword = await bcrypt.hash(userData.password, 10);

    return await prisma.user.create({
      data: {
        username: userData.username,
        password: hashedPassword,
      },
    });
  }

  static async deleteMany(query: Record<string, unknown> = {}): Promise<void> {
    // For test cleanup - delete all users if no query provided
    if (Object.keys(query).length === 0) {
      await prisma.user.deleteMany();
    } else {
      // Handle specific queries if needed
      throw new Error("Specific delete queries not implemented yet");
    }
  }

  static async findByIdAndDelete(id: string): Promise<IUser | null> {
    try {
      return await prisma.user.delete({
        where: { id },
      });
    } catch {
      return null; // User not found
    }
  }

  // Instance methods simulation
  static async comparePassword(user: IUser, candidatePassword: string): Promise<boolean> {
    try {
      return await bcrypt.compare(candidatePassword, user.password);
    } catch {
      return false;
    }
  }

  static async updatePassword(user: IUser, newPassword: string): Promise<IUser> {
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    return await prisma.user.update({
      where: { id: user.id },
      data: { password: hashedPassword },
    });
  }
}

export { prisma };
