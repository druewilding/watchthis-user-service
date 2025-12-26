import { PrismaPg } from "@prisma/adapter-pg";
import bcrypt from "bcrypt";

import { PrismaClient } from "../generated/prisma/client";

const adapter = new PrismaPg({
  connectionString: process.env.DATABASE_URL,
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
