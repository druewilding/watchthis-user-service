import appRootPath from "app-root-path";
import express from "express";
import helmet from "helmet";
import path from "path";

import packageJson from "../package.json" with { type: "json" };
import { applyAuthenticationMiddleware, authenticate, ensureAuthenticated } from "./auth.js";
import { getCurrentUser, loginWithJWT, refreshToken } from "./controllers/auth.js";
import { authenticateJWT, requireJWT } from "./middleware/jwt.js";
import { validateLogin, validateSignup } from "./middleware/validation.js";
import { prisma, User } from "./models/user.js";
import { asyncHandler } from "./utils/asyncHandler.js";
import { generateTokenPair } from "./utils/jwt.js";

// Parse allowed redirect hosts from environment variable
const getAllowedHosts = (): string[] => {
  const envHosts = process.env.ALLOWED_REDIRECT_HOSTS;
  const defaultHosts = ["localhost", "127.0.0.1"];

  if (envHosts && envHosts.trim()) {
    const parsedHosts = envHosts
      .split(",")
      .map((host) => host.trim())
      .filter((host) => host.length > 0);
    // Ensure localhost and 127.0.0.1 are always included for development/testing
    const allHosts = [...new Set([...defaultHosts, ...parsedHosts])];
    return allHosts;
  }

  return defaultHosts;
};

const allowedRedirectHosts = getAllowedHosts();

// Test database connection
prisma
  .$connect()
  .then(() => {
    console.log("Database connected!");
  })
  .catch((err: Error) => {
    console.log(err);
  });

const app = express();

// Security headers
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"], // Allow inline styles for TailwindCSS
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "https:"],
        fontSrc: ["'self'"],
      },
    },
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

applyAuthenticationMiddleware(app);
app.set("view engine", "pug");
app.set("views", path.join(appRootPath.path, "views"));
app.use(express.static(path.join(appRootPath.path, "public")));

app.get("/signup", (req, res) => {
  const messages = req.flash("error");
  res.render("signup", { callbackUrl: req.query.callbackUrl, messages });
});

app.post(
  "/signup",
  validateSignup,
  asyncHandler(async (req, res) => {
    try {
      const user = await User.create({
        username: req.body.username,
        password: req.body.password,
      });

      req.login(user, function (err) {
        if (err !== null && err !== undefined) {
          console.log(err);
          return res.status(500).send();
        }

        // Use intermediate redirect to avoid CSP issues
        const callbackUrl = req.body.callbackUrl;

        if (callbackUrl && callbackUrl !== "/dashboard") {
          res.redirect(`/redirect?to=${encodeURIComponent(callbackUrl)}`);
        } else {
          res.redirect("/dashboard");
        }
      });
    } catch (error) {
      console.error("Signup error:", error);
      // Check for MongoDB duplicate key error (username already exists)
      if (error && typeof error === "object" && "code" in error && error.code === 11000) {
        req.flash("error", "Username already exists. Please choose a different username.");
        return res.redirect("/signup");
      }
      req.flash("error", "An error occurred during signup. Please try again.");
      res.redirect("/signup");
    }
  })
);

app.get("/login", (req, res) => {
  const messages = req.flash("error");
  res.render("login", { messages, callbackUrl: req.query.callbackUrl });
});

app.post("/login", validateLogin, authenticate);

app.get(
  "/dashboard",
  ensureAuthenticated,
  asyncHandler(async (req, res) => {
    const users = await User.find();
    res.render("dashboard", { users, currentUser: req.user });
  })
);

app.post("/logout", (req, res) => {
  req.logout({}, (err: unknown) => {
    if (err !== null && err !== undefined) {
      // Handle the error as needed, perhaps logging it or sending a different response
      console.error(err);
      return res.status(500).send("An error occurred while logging out");
    }

    // Use intermediate redirect to avoid CSP issues
    const callbackUrl = req.body?.callbackUrl;
    if (callbackUrl && callbackUrl !== "/") {
      res.redirect(`/redirect?to=${encodeURIComponent(callbackUrl)}`);
    } else {
      res.redirect("/");
    }
  });
});

app.get("/redirect", (req, res) => {
  const targetUrl = req.query.to as string;

  if (!targetUrl) {
    return res.redirect("/dashboard");
  }

  // Basic validation to ensure we're redirecting to allowed domains
  try {
    const url = new URL(targetUrl);
    const isAllowed = allowedRedirectHosts.some((host) => url.hostname === host || url.hostname.endsWith(`.${host}`));

    if (isAllowed) {
      // Use meta refresh redirect instead of HTTP redirect to bypass CSP
      res.send(`
        <!DOCTYPE html>
        <html>
        <head>
          <meta http-equiv="refresh" content="0; url=${targetUrl}">
          <title>Redirecting...</title>
        </head>
        <body>
          <p>Redirecting to <a href="${targetUrl}">${targetUrl}</a>...</p>
          <script>window.location.href = "${targetUrl}";</script>
        </body>
        </html>
      `);
    } else {
      console.warn(`Redirect to unauthorized domain attempted: ${url.hostname}`);
      res.redirect("/dashboard");
    }
  } catch (error) {
    console.error("Invalid redirect URL:", targetUrl);
    res.redirect("/dashboard");
  }
});

app.get("/", (req, res) => {
  if (req.isAuthenticated && req.isAuthenticated()) {
    res.redirect("/dashboard");
  } else {
    res.render("welcome-page");
  }
});

app.post("/andre", (_req, res) => {
  res.send("potato");
});

app.get("/hello/:name", (req, res) => {
  res.send(`Hello ${req.params.name}!`);
});

app.get("/ping", (_req, res) => {
  res.send(`${packageJson.name} ${packageJson.version}`);
});

// API endpoint for session validation (used by other services)
// Define a type for the user session object
interface UserSession {
  _id?: string;
  id?: string;
  username?: string;
}

// Helper to safely get user ID
function getUserId(user: UserSession): string | undefined {
  return user._id ?? user.id;
}

app.get("/api/v1/session", (req, res) => {
  const user = req.user as UserSession | undefined;
  if (user) {
    res.json({
      user: {
        _id: getUserId(user),
        username: user.username,
      },
    });
  } else {
    res.status(401).json({ error: "Not authenticated" });
  }
});

// JWT Authentication API routes
app.post("/api/v1/auth/login", loginWithJWT);
app.post("/api/v1/auth/refresh", refreshToken);
app.get("/api/v1/auth/me", authenticateJWT as any, getCurrentUser as any);
app.get(
  "/api/v1/auth/session-to-jwt",
  asyncHandler(async (req, res) => {
    try {
      // Check if user has valid session (API version - returns JSON instead of redirect)
      const user = req.user as UserSession | undefined;
      if (!user || !req.isAuthenticated?.()) {
        res.status(401).json({
          success: false,
          error: { code: "NO_SESSION", message: "No valid session found" },
        });
        return;
      }

      // Find the full user document to generate JWT tokens
      const userId = getUserId(user);
      if (!userId) {
        res.status(401).json({
          success: false,
          error: { code: "USER_ID_MISSING", message: "User ID missing" },
        });
        return;
      }

      const userDoc = await User.findById(userId);
      if (!userDoc) {
        res.status(401).json({
          success: false,
          error: { code: "USER_NOT_FOUND", message: "User not found" },
        });
        return;
      }

      // Generate JWT tokens for the authenticated user
      const tokens = generateTokenPair(userDoc);

      res.json({
        success: true,
        data: {
          user: { _id: getUserId(user), username: user.username },
          ...tokens,
        },
      });
    } catch (error) {
      console.error("Session to JWT conversion error:", error);
      res.status(500).json({
        success: false,
        error: { code: "CONVERSION_ERROR", message: "Failed to convert session to JWT" },
      });
    }
  })
);

// Protected API endpoint example (requires JWT)
app.get(
  "/api/v1/profile",
  authenticateJWT as any,
  requireJWT as any,
  asyncHandler(async (req, res) => {
    const user = (req as any).user as UserSession;
    res.json({
      success: true,
      data: {
        user: {
          _id: getUserId(user),
          username: user.username,
        },
      },
    });
  })
);

app.get(
  "/health",
  asyncHandler(async (_req, res) => {
    try {
      // Check database connection
      await prisma.$queryRaw`SELECT 1`;
      res.json({
        status: "healthy",
        service: packageJson.name,
        version: packageJson.version,
        database: "connected",
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      console.error("Health check failed:", error);
      res.status(503).json({
        status: "unhealthy",
        service: packageJson.name,
        version: packageJson.version,
        database: "disconnected",
        timestamp: new Date().toISOString(),
      });
    }
  })
);

export { app };
