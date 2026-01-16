import assert from "node:assert";
import type { Server } from "node:http";
import { after, before, beforeEach, describe, it } from "node:test";

import request, { SuperTest, Test } from "supertest";
import session from "supertest-session";

import { app } from "../src/app.js";
import { pgStore } from "../src/auth.js";
import { prisma } from "../src/models/user.js";
import { User } from "../src/models/user.js";
import { generateTokenPair, verifyToken } from "../src/utils/jwt.js";
import { generateValidPassword, generateValidUsername } from "./helpers/testData.js";

const port = 18583;
let server: Server;

describe("Watch This User Service - All Tests", () => {
  before(() => {
    server = app.listen(port);
  });

  beforeEach(async () => {
    // Clean up test data before each test
    await User.deleteMany({});
  });

  after(async () => {
    server.close();
    await User.deleteMany({});
    await prisma.$disconnect();
    if (pgStore !== undefined) {
      pgStore.close();
    }
  });

  // ===== APP TESTS =====
  describe("App", () => {
    describe("Dashboard", () => {
      it("should require authentication", async () => {
        const res = await request(app).get("/dashboard");
        assert.equal(res.statusCode, 302);
        assert.equal(res.headers.location, "/login");
      });
    });

    describe("Sign up page", () => {
      it("should render the signup page", async () => {
        const res = await request(app).get("/signup");
        assert.equal(res.statusCode, 200);
        assert.ok(res.text.includes("form"));
      });

      it("should include a callbackUrl if one is set", async () => {
        const callbackUrl = "/test";
        const res = await request(app).get("/signup").query({ callbackUrl });
        assert.equal(res.statusCode, 200);
        assert.ok(res.text.includes(`<input type="hidden" name="callbackUrl" value="${callbackUrl}">`));
      });
    });

    describe("Sign up", () => {
      it("should create a user and redirect to the dashboard", async () => {
        const res = await request(app)
          .post("/signup")
          .type("form")
          .send({ username: generateValidUsername(), password: generateValidPassword() });
        assert.equal(res.statusCode, 302);
        assert.equal(res.headers.location, "/dashboard");
      });

      it("should redirect to intermediate redirect when callbackUrl is external", async () => {
        const callbackUrl = "http://localhost:7279/";
        const res = await request(app)
          .post("/signup")
          .type("form")
          .send({ username: generateValidUsername(), password: generateValidPassword(), callbackUrl });
        assert.equal(res.statusCode, 302);
        assert.equal(res.headers.location, `/redirect?to=${encodeURIComponent(callbackUrl)}`);
      });

      it("should redirect directly when callbackUrl is internal", async () => {
        const callbackUrl = "/dashboard";
        const res = await request(app)
          .post("/signup")
          .type("form")
          .send({ username: generateValidUsername(), password: generateValidPassword(), callbackUrl });
        assert.equal(res.statusCode, 302);
        assert.equal(res.headers.location, callbackUrl);
      });

      it("should redirect back to signup with validation errors for invalid password", async () => {
        const res = await request(app)
          .post("/signup")
          .type("form")
          .send({ username: generateValidUsername(), password: "weak" }); // Invalid password
        assert.equal(res.statusCode, 302);
        assert.equal(res.headers.location, "/signup");
      });

      it("should redirect back to signup with validation errors for invalid username", async () => {
        const res = await request(app)
          .post("/signup")
          .type("form")
          .send({ username: "ab", password: generateValidPassword() }); // Username too short
        assert.equal(res.statusCode, 302);
        assert.equal(res.headers.location, "/signup");
      });

      it("should show validation error messages on signup page after invalid submission", async () => {
        const agent = session(app);

        // First, submit invalid data
        const postRes = await agent.post("/signup").type("form").send({ username: "ab", password: "weak" }); // Both invalid
        assert.equal(postRes.statusCode, 302);
        assert.equal(postRes.headers.location, "/signup");

        // Then, get the signup page to see the error messages
        const getRes = await agent.get("/signup");
        assert.equal(getRes.statusCode, 200);
        assert.ok(getRes.text.includes("Username must be between 3 and 30 characters"));
        assert.ok(getRes.text.includes("Password must be at least 8 characters long"));
      });
    });

    describe("Log in page", () => {
      it("should render the login page", async () => {
        const res = await request(app).get("/login");
        assert.equal(res.statusCode, 200);
        assert.ok(res.text.includes("form"));
      });

      it("should include a callbackUrl if one is set", async () => {
        const callbackUrl = "/test";
        const res = await request(app).get("/login").query({ callbackUrl });
        assert.equal(res.statusCode, 200);
        assert.ok(res.text.includes(`<input type="hidden" name="callbackUrl" value="${callbackUrl}">`));
      });
    });

    describe("Log in", () => {
      let username: string;
      let password: string;

      beforeEach(async () => {
        username = generateValidUsername();
        password = generateValidPassword();

        const user = await User.create({
          username,
          password,
        });
      });

      it("should be able to log in with known username and password", async () => {
        const res = await request(app).post("/login").type("form").send({ username, password });
        assert.equal(res.statusCode, 302);
        assert.equal(res.headers.location, "/dashboard");
      });

      it("should redirect to intermediate redirect when callbackUrl is external", async () => {
        const callbackUrl = "http://localhost:7279/";
        const res = await request(app).post("/login").type("form").send({ username, password, callbackUrl });
        assert.equal(res.statusCode, 302);
        assert.equal(res.headers.location, `/redirect?to=${encodeURIComponent(callbackUrl)}`);
      });

      it("should redirect directly when callbackUrl is internal", async () => {
        const callbackUrl = "/dashboard";
        const res = await request(app).post("/login").type("form").send({ username, password, callbackUrl });
        assert.equal(res.statusCode, 302);
        assert.equal(res.headers.location, callbackUrl);
      });

      it("should not be able to log in with incorrect password", async () => {
        const res = await request(app).post("/login").type("form").send({ username, password: "wrongPassword" });
        assert.equal(res.statusCode, 302);
        assert.equal(res.headers.location, "/login");
      });

      it("should not be able to log in with invalid username", async () => {
        const res = await request(app).post("/login").type("form").send({ username: "invalidUsername", password });
        assert.equal(res.statusCode, 302);
        assert.equal(res.headers.location, "/login");
      });
    });

    describe("Log out", () => {
      let testSession: SuperTest<Test>;
      let username: string;
      let password: string;

      beforeEach(async () => {
        testSession = session(app);
        username = generateValidUsername();
        password = generateValidPassword();

        const user = await User.create({
          username,
          password,
        });
        const loginRes = await testSession.post("/login").type("form").send({ username, password });
        assert.equal(loginRes.statusCode, 302); // Ensure login succeeded
      });

      it("should log out", async () => {
        let res: request.Response;

        // Ensure logged in
        res = await testSession.get("/dashboard");
        assert.ok(res.text.includes("Dashboard"));

        // Log out
        res = await testSession.post("/logout");
        assert.equal(res.statusCode, 302);
        assert.equal(res.headers.location, "/");

        // Ensure logged out
        res = await testSession.get("/dashboard");
        assert.equal(res.statusCode, 302);
        assert.equal(res.headers.location, "/login");
      });

      it("should redirect to intermediate redirect when callbackUrl is external", async () => {
        const callbackUrl = "http://localhost:7279/";
        const res = await testSession.post("/logout").type("form").send({ callbackUrl });
        assert.equal(res.statusCode, 302);
        assert.equal(res.headers.location, `/redirect?to=${encodeURIComponent(callbackUrl)}`);
      });

      it("should redirect directly when callbackUrl is internal", async () => {
        const callbackUrl = "/";
        const res = await testSession.post("/logout").type("form").send({ callbackUrl });
        assert.equal(res.statusCode, 302);
        assert.equal(res.headers.location, callbackUrl);
      });
    });

    describe("Ping", () => {
      it("should respond to a ping", async () => {
        const res = await request(app).get("/ping");
        assert.equal(res.statusCode, 200);
      });
    });

    describe("Health", () => {
      it("should respond with health status", async () => {
        const res = await request(app).get("/health");
        assert.equal(res.statusCode, 200);
        assert.equal(res.type, "application/json");
        const body = JSON.parse(res.text);
        assert.equal(body.status, "healthy");
        assert.equal(body.service, "watchthis-user-service");
        assert.equal(body.database, "connected");
        assert.ok(body.version);
        assert.ok(body.timestamp);
      });
    });

    it("should show the welcome page when not logged in", async () => {
      const res = await request(app).get("/");
      assert.equal(res.statusCode, 200);
      assert.ok(res.text.includes("Welcome to Watch This!"));
    });

    it("should redirect to dashboard when logged in", async () => {
      // Create a test session and log in
      const testSession = session(app);
      const username = generateValidUsername();
      const password = generateValidPassword();

      const user = await User.create({ username, password });

      // Log in
      await testSession.post("/login").send({ username, password });

      // Visit root path - should redirect to dashboard
      const res = await testSession.get("/");
      assert.equal(res.statusCode, 302);
      assert.equal(res.headers.location, "/dashboard");
    });

    it("should give a 404 when a route is not found", async () => {
      const res = await request(app).get("/aaa");
      assert.equal(res.statusCode, 404);
    });

    it("should respond to /andre as a POST request", async () => {
      const res = await request(app).post("/andre");
      assert.ok(res.text.includes("potato"));
    });

    it("should say hello to aimee", async () => {
      const res = await request(app).get("/hello/aimee");
      assert.ok(res.text.includes("Hello aimee!"));
    });

    it("should say hello to zoe", async () => {
      const res = await request(app).get("/hello/zoe");
      assert.ok(res.text.includes("Hello zoe!"));
    });

    it("should serve static files from the public directory", async () => {
      const res = await request(app).get("/hello.txt");
      assert.ok(res.text.includes("Hello!"));
    });

    describe("API", () => {
      describe("Session", () => {
        let testSession: SuperTest<Test>;
        let username: string;
        let password: string;

        beforeEach(async () => {
          testSession = session(app);
          username = generateValidUsername();
          password = generateValidPassword();

          const user = await User.create({
            username,
            password,
          });
          const loginRes = await testSession.post("/login").type("form").send({ username, password });
          assert.equal(loginRes.statusCode, 302); // Ensure login succeeded
        });

        it("should return user details when authenticated", async () => {
          const res = await testSession.get("/api/v1/session");
          assert.equal(res.statusCode, 200);
          const responseBody = JSON.parse(res.text);
          assert(responseBody.user);
          assert(responseBody.user._id);
          assert.equal(responseBody.user.username, username);
        });

        it("should return 401 when not authenticated", async () => {
          const res = await request(app).get("/api/v1/session");
          assert.equal(res.statusCode, 401);
          const responseBody = JSON.parse(res.text);
          assert.equal(responseBody.error, "Not authenticated");
        });

        it("should return 401 after user has logged out", async () => {
          await testSession.post("/logout");
          const res = await testSession.get("/api/v1/session");
          assert.equal(res.statusCode, 401);
          const responseBody = JSON.parse(res.text);
          assert.equal(responseBody.error, "Not authenticated");
        });
      });
    });
  });

  describe("Redirect Route", () => {
    describe("GET /redirect", () => {
      it("should redirect to allowed localhost URL", async () => {
        const targetUrl = "http://localhost:7279/dashboard";
        const res = await request(app)
          .get(`/redirect?to=${encodeURIComponent(targetUrl)}`)
          .expect(200);

        // Should return HTML with meta refresh and JavaScript redirect
        assert(res.text.includes(`<meta http-equiv="refresh" content="0; url=${targetUrl}">`));
        assert(res.text.includes(`window.location.href = "${targetUrl}"`));
        assert(res.text.includes(`<a href="${targetUrl}">${targetUrl}</a>`));
      });

      it("should redirect to allowed 127.0.0.1 URL", async () => {
        const targetUrl = "http://127.0.0.1:8080/test";
        const res = await request(app)
          .get(`/redirect?to=${encodeURIComponent(targetUrl)}`)
          .expect(200);

        assert(res.text.includes(`<meta http-equiv="refresh" content="0; url=${targetUrl}">`));
        assert(res.text.includes(`window.location.href = "${targetUrl}"`));
      });

      it("should redirect to dashboard when no target URL provided", async () => {
        const res = await request(app).get("/redirect").expect(302);

        assert.equal(res.headers.location, "/dashboard");
      });

      it("should redirect to dashboard when empty target URL provided", async () => {
        const res = await request(app).get("/redirect?to=").expect(302);

        assert.equal(res.headers.location, "/dashboard");
      });

      it("should redirect to dashboard for unauthorized domain", async () => {
        const targetUrl = "http://malicious.com/steal-data";
        const res = await request(app)
          .get(`/redirect?to=${encodeURIComponent(targetUrl)}`)
          .expect(302);

        assert.equal(res.headers.location, "/dashboard");
      });

      it("should redirect to dashboard for invalid URL", async () => {
        const targetUrl = "not-a-valid-url";
        const res = await request(app)
          .get(`/redirect?to=${encodeURIComponent(targetUrl)}`)
          .expect(302);

        assert.equal(res.headers.location, "/dashboard");
      });

      it("should allow subdomain of localhost", async () => {
        const targetUrl = "http://api.localhost:3000/callback";
        const res = await request(app)
          .get(`/redirect?to=${encodeURIComponent(targetUrl)}`)
          .expect(200);

        assert(res.text.includes(`<meta http-equiv="refresh" content="0; url=${targetUrl}">`));
      });

      it("should handle URLs with query parameters and fragments", async () => {
        const targetUrl = "http://localhost:7279/dashboard?user=test&redirect=true#section";
        const res = await request(app)
          .get(`/redirect?to=${encodeURIComponent(targetUrl)}`)
          .expect(200);

        assert(res.text.includes(`<meta http-equiv="refresh" content="0; url=${targetUrl}">`));
        assert(res.text.includes(`window.location.href = "${targetUrl}"`));
      });

      it("should handle HTTPS localhost URLs", async () => {
        const targetUrl = "https://localhost:8443/secure";
        const res = await request(app)
          .get(`/redirect?to=${encodeURIComponent(targetUrl)}`)
          .expect(200);

        assert(res.text.includes(`<meta http-equiv="refresh" content="0; url=${targetUrl}">`));
      });
    });
  });

  // ===== JWT MIDDLEWARE TESTS =====
  describe("JWT Middleware", () => {
    describe("authenticateJWT middleware", () => {
      it("should authenticate valid Bearer token", async () => {
        // Create a test user
        const username = generateValidUsername();
        const password = generateValidPassword();
        const user = await User.create({ username, password });

        const tokens = generateTokenPair(user);

        // Test with valid token
        const res = await request(app)
          .get("/api/v1/auth/me")
          .set("Authorization", `Bearer ${tokens.accessToken}`)
          .expect(200);

        assert.equal(res.body.success, true);
        assert.equal(res.body.data.user.username, username);
      });

      it("should continue without user for missing Authorization header", async () => {
        // This endpoint requires auth, so it should return 401
        const res = await request(app).get("/api/v1/auth/me").expect(401);

        assert.equal(res.body.success, false);
        assert.equal(res.body.error.code, "AUTHENTICATION_REQUIRED");
      });

      it("should continue without user for malformed Authorization header", async () => {
        const res = await request(app).get("/api/v1/auth/me").set("Authorization", "NotBearer token123").expect(401);

        assert.equal(res.body.success, false);
      });

      it("should continue without user for invalid token", async () => {
        const res = await request(app)
          .get("/api/v1/auth/me")
          .set("Authorization", "Bearer invalid.jwt.token")
          .expect(401);

        assert.equal(res.body.success, false);
      });

      it("should continue without user when user no longer exists", async () => {
        // Create a test user and get token
        const username = generateValidUsername();
        const password = generateValidPassword();
        const user = await User.create({ username, password });

        const tokens = generateTokenPair(user);

        // Delete the user
        await User.findByIdAndDelete(user.id);

        // Token should be invalid now
        const res = await request(app)
          .get("/api/v1/auth/me")
          .set("Authorization", `Bearer ${tokens.accessToken}`)
          .expect(401);

        assert.equal(res.body.success, false);
      });

      it("should reject refresh tokens in access token contexts", async () => {
        // Create a test user
        const username = generateValidUsername();
        const password = generateValidPassword();
        const user = await User.create({ username, password });

        const tokens = generateTokenPair(user);

        // Try to use refresh token where access token is expected
        const res = await request(app)
          .get("/api/v1/auth/me")
          .set("Authorization", `Bearer ${tokens.refreshToken}`)
          .expect(401);

        assert.equal(res.body.success, false);
      });
    });

    describe("requireJWT middleware", () => {
      it("should allow access with valid JWT", async () => {
        // Create a test user
        const username = generateValidUsername();
        const password = generateValidPassword();
        const user = await User.create({ username, password });

        const tokens = generateTokenPair(user);

        const res = await request(app)
          .get("/api/v1/auth/me")
          .set("Authorization", `Bearer ${tokens.accessToken}`)
          .expect(200);

        assert.equal(res.body.success, true);
      });

      it("should block access without JWT", async () => {
        const res = await request(app).get("/api/v1/auth/me").expect(401);

        assert.equal(res.body.success, false);
        assert.equal(res.body.error.code, "AUTHENTICATION_REQUIRED");
        assert.equal(res.body.error.message, "Authentication required");
      });
    });

    describe("Token format validation", () => {
      it("should handle empty Authorization header", async () => {
        const res = await request(app).get("/api/v1/auth/me").set("Authorization", "").expect(401);

        assert.equal(res.body.success, false);
      });

      it("should handle Authorization header without Bearer prefix", async () => {
        const res = await request(app).get("/api/v1/auth/me").set("Authorization", "someToken").expect(401);

        assert.equal(res.body.success, false);
      });

      it("should handle Bearer without token", async () => {
        const res = await request(app).get("/api/v1/auth/me").set("Authorization", "Bearer ").expect(401);

        assert.equal(res.body.success, false);
      });

      it("should handle Bearer with empty string token", async () => {
        const res = await request(app).get("/api/v1/auth/me").set("Authorization", "Bearer ").expect(401);

        assert.equal(res.body.success, false);
      });
    });

    describe("Integration with existing authentication", () => {
      it("should not interfere with session-based endpoints", async () => {
        // Test that session-based endpoints still work
        const res = await request(app).get("/login").expect(200);

        assert.ok(res.text.includes("form"));
      });

      it("should not interfere with public endpoints", async () => {
        const res = await request(app).get("/ping").expect(200);

        assert.ok(res.text.includes("watchthis-user-service"));
      });

      it("should not affect health check endpoint", async () => {
        const res = await request(app).get("/health").expect(200);

        assert.equal(res.body.status, "healthy");
      });
    });
  });

  // ===== JWT API TESTS =====
  describe("JWT Authentication API", () => {
    describe("POST /api/v1/auth/login - JWT Login", () => {
      it("should authenticate user with valid credentials and return JWT tokens", async () => {
        // Create a test user
        const username = generateValidUsername();
        const password = generateValidPassword();
        const user = await User.create({ username, password });

        const res = await request(app).post("/api/v1/auth/login").send({ username, password }).expect(200);

        assert.equal(res.body.success, true);
        assert.ok(res.body.data);
        assert.ok(res.body.data.accessToken);
        assert.ok(res.body.data.refreshToken);
        assert.equal(res.body.data.expiresIn, "24h");
        assert.equal(res.body.data.user.username, username);
        assert.ok(res.body.data.user._id);

        // Verify the access token is valid
        const decoded = verifyToken(res.body.data.accessToken);
        assert.equal(decoded.type, "access");
        assert.equal(decoded.username, username);
        assert.equal(decoded.userId, user.id);
      });

      it("should fail with missing username", async () => {
        const res = await request(app).post("/api/v1/auth/login").send({ password: "password123" }).expect(400);

        assert.equal(res.body.success, false);
        assert.equal(res.body.error.code, "MISSING_CREDENTIALS");
        assert.equal(res.body.error.message, "Username and password are required");
      });

      it("should fail with missing password", async () => {
        const res = await request(app).post("/api/v1/auth/login").send({ username: "testUser" }).expect(400);

        assert.equal(res.body.success, false);
        assert.equal(res.body.error.code, "MISSING_CREDENTIALS");
      });

      it("should fail with invalid username", async () => {
        const res = await request(app)
          .post("/api/v1/auth/login")
          .send({ username: "nonExistent", password: "password123" })
          .expect(401);

        assert.equal(res.body.success, false);
        assert.equal(res.body.error.code, "INVALID_CREDENTIALS");
        assert.equal(res.body.error.message, "Invalid username or password");
      });

      it("should fail with invalid password", async () => {
        // Create a test user
        const username = generateValidUsername();
        const password = generateValidPassword();
        const user = await User.create({ username, password });

        const res = await request(app)
          .post("/api/v1/auth/login")
          .send({ username, password: "wrongPassword" })
          .expect(401);

        assert.equal(res.body.success, false);
        assert.equal(res.body.error.code, "INVALID_CREDENTIALS");
      });
    });

    describe("POST /api/v1/auth/refresh - Token Refresh", () => {
      it("should refresh access token with valid refresh token", async () => {
        // Create a test user and get tokens
        const username = generateValidUsername();
        const password = generateValidPassword();
        const user = await User.create({ username, password });

        const loginRes = await request(app).post("/api/v1/auth/login").send({ username, password }).expect(200);

        const { refreshToken } = loginRes.body.data;

        // Use refresh token to get new access token
        const res = await request(app).post("/api/v1/auth/refresh").send({ refreshToken }).expect(200);

        assert.equal(res.body.success, true);
        assert.ok(res.body.data.accessToken);
        assert.ok(res.body.data.refreshToken);
        assert.equal(res.body.data.user.username, username);

        // Verify the new access token is valid
        const decoded = verifyToken(res.body.data.accessToken);
        assert.equal(decoded.type, "access");
        assert.equal(decoded.username, username);

        // The tokens might be the same if generated at the exact same time
        // What's important is that the refresh endpoint works
        assert.ok(res.body.data.accessToken);
        assert.ok(res.body.data.refreshToken);
      });

      it("should fail with missing refresh token", async () => {
        const res = await request(app).post("/api/v1/auth/refresh").send({}).expect(400);

        assert.equal(res.body.success, false);
        assert.equal(res.body.error.code, "MISSING_REFRESH_TOKEN");
      });

      it("should fail with invalid refresh token", async () => {
        const res = await request(app)
          .post("/api/v1/auth/refresh")
          .send({ refreshToken: "invalid.token.here" })
          .expect(401);

        assert.equal(res.body.success, false);
        assert.equal(res.body.error.code, "INVALID_REFRESH_TOKEN");
      });

      it("should fail when using access token as refresh token", async () => {
        // Create a test user and get tokens
        const username = generateValidUsername();
        const password = generateValidPassword();
        const user = await User.create({ username, password });

        const loginRes = await request(app).post("/api/v1/auth/login").send({ username, password }).expect(200);

        const { accessToken } = loginRes.body.data;

        // Try to use access token as refresh token
        const res = await request(app).post("/api/v1/auth/refresh").send({ refreshToken: accessToken }).expect(401);

        assert.equal(res.body.success, false);
        assert.equal(res.body.error.code, "INVALID_TOKEN_TYPE");
      });

      it("should fail when user no longer exists", async () => {
        // Create a test user and get tokens
        const username = generateValidUsername();
        const password = generateValidPassword();
        const user = await User.create({ username, password });

        const tokens = generateTokenPair(user);

        // Delete the user
        await User.findByIdAndDelete(user.id);

        // Try to refresh token
        const res = await request(app)
          .post("/api/v1/auth/refresh")
          .send({ refreshToken: tokens.refreshToken })
          .expect(401);

        assert.equal(res.body.success, false);
        assert.equal(res.body.error.code, "USER_NOT_FOUND");
      });
    });

    describe("GET /api/v1/auth/me - Get Current User", () => {
      it("should return user info with valid JWT token", async () => {
        // Create a test user and get token
        const username = generateValidUsername();
        const password = generateValidPassword();
        const user = await User.create({ username, password });

        const loginRes = await request(app).post("/api/v1/auth/login").send({ username, password }).expect(200);

        const { accessToken } = loginRes.body.data;

        // Get current user info
        const res = await request(app).get("/api/v1/auth/me").set("Authorization", `Bearer ${accessToken}`).expect(200);

        assert.equal(res.body.success, true);
        assert.equal(res.body.data.user.username, username);
        assert.equal(res.body.data.user._id, user.id);
      });

      it("should fail without authorization header", async () => {
        const res = await request(app).get("/api/v1/auth/me").expect(401);

        assert.equal(res.body.success, false);
        assert.equal(res.body.error.code, "AUTHENTICATION_REQUIRED");
      });

      it("should fail with invalid token", async () => {
        const res = await request(app)
          .get("/api/v1/auth/me")
          .set("Authorization", "Bearer invalid.token.here")
          .expect(401);

        assert.equal(res.body.success, false);
        assert.equal(res.body.error.code, "AUTHENTICATION_REQUIRED");
      });

      it("should fail with malformed authorization header", async () => {
        const res = await request(app).get("/api/v1/auth/me").set("Authorization", "InvalidFormat token").expect(401);

        assert.equal(res.body.success, false);
        assert.equal(res.body.error.code, "AUTHENTICATION_REQUIRED");
      });

      it("should fail when user no longer exists", async () => {
        // Create a test user and get token
        const username = generateValidUsername();
        const password = generateValidPassword();
        const user = await User.create({ username, password });

        const tokens = generateTokenPair(user);

        // Delete the user
        await User.findByIdAndDelete(user.id);

        // Try to get current user
        const res = await request(app)
          .get("/api/v1/auth/me")
          .set("Authorization", `Bearer ${tokens.accessToken}`)
          .expect(401);

        assert.equal(res.body.success, false);
        assert.equal(res.body.error.code, "AUTHENTICATION_REQUIRED");
      });

      it("should fail when using refresh token instead of access token", async () => {
        // Create a test user and get tokens
        const username = generateValidUsername();
        const password = generateValidPassword();
        const user = await User.create({ username, password });

        const tokens = generateTokenPair(user);

        // Try to use refresh token for authenticated endpoint
        const res = await request(app)
          .get("/api/v1/auth/me")
          .set("Authorization", `Bearer ${tokens.refreshToken}`)
          .expect(401);

        assert.equal(res.body.success, false);
        assert.equal(res.body.error.code, "AUTHENTICATION_REQUIRED");
      });
    });

    describe("GET /api/v1/auth/session-to-jwt - Session to JWT Conversion", () => {
      it("should convert valid session to JWT tokens", async () => {
        // Create a test user
        const username = generateValidUsername();
        const password = generateValidPassword();
        const user = await User.create({ username, password });

        // Create a session by logging in via web interface
        const testSession = session(app);

        // Login to create session
        await testSession.post("/login").send({ username, password }).expect(302); // Redirect after successful login

        // Now convert session to JWT
        const res = await testSession.get("/api/v1/auth/session-to-jwt").expect(200);

        assert.equal(res.body.success, true);
        assert.ok(res.body.data);
        assert.ok(res.body.data.accessToken);
        assert.ok(res.body.data.refreshToken);
        assert.equal(res.body.data.expiresIn, "24h");
        assert.equal(res.body.data.user.username, username);
        assert.ok(res.body.data.user._id);

        // Verify the access token is valid
        const decoded = verifyToken(res.body.data.accessToken);
        assert.equal(decoded.type, "access");
        assert.equal(decoded.username, username);
        assert.equal(decoded.userId, user.id);
      });

      it("should fail without valid session", async () => {
        // Try to get JWT without session
        const res = await request(app).get("/api/v1/auth/session-to-jwt").expect(401);

        assert.equal(res.body.success, false);
        assert.equal(res.body.error.code, "NO_SESSION");
        assert.equal(res.body.error.message, "No valid session found");
      });

      it("should fail if user is deleted after session creation", async () => {
        // Create a test user
        const username = generateValidUsername();
        const password = generateValidPassword();
        const user = await User.create({ username, password });

        // Create a session by logging in
        const testSession = session(app);
        await testSession.post("/login").send({ username, password }).expect(302);

        // Delete the user
        await User.findByIdAndDelete(user.id);

        // Try to convert session to JWT - session becomes invalid when user is deleted
        const res = await testSession.get("/api/v1/auth/session-to-jwt").expect(401);

        assert.equal(res.body.success, false);
        assert.equal(res.body.error.code, "NO_SESSION");
        assert.equal(res.body.error.message, "No valid session found");
      });

      it("should generate different tokens on subsequent calls", async () => {
        // Create a test user and session
        const username = generateValidUsername();
        const password = generateValidPassword();
        const user = await User.create({ username, password });

        const testSession = session(app);
        await testSession.post("/login").send({ username, password }).expect(302);

        // Get first set of tokens
        const res1 = await testSession.get("/api/v1/auth/session-to-jwt").expect(200);

        // Wait at least 1 second to ensure different `iat` timestamps
        await new Promise((resolve) => setTimeout(resolve, 1100));

        // Get second set of tokens
        const res2 = await testSession.get("/api/v1/auth/session-to-jwt").expect(200);

        // Tokens should be different (new tokens generated each time)
        assert.notEqual(res1.body.data.accessToken, res2.body.data.accessToken);
        assert.notEqual(res1.body.data.refreshToken, res2.body.data.refreshToken);

        // But both should be valid for the same user
        const decoded1 = verifyToken(res1.body.data.accessToken);
        const decoded2 = verifyToken(res2.body.data.accessToken);

        assert.equal(decoded1.userId, decoded2.userId);
        assert.equal(decoded1.username, decoded2.username);

        // Verify different issued-at times
        assert.notEqual(decoded1.iat, decoded2.iat);
      });
    });

    describe("JWT Middleware Integration", () => {
      it("should work with existing session endpoint", async () => {
        // Test that the existing /api/v1/session endpoint still works
        // This should continue to work for session-based authentication
        const res = await request(app).get("/api/v1/session").expect(401);

        assert.equal(res.body.error, "Not authenticated");
      });

      it("should allow both session and JWT auth to coexist", async () => {
        // Create a test user
        const username = generateValidUsername();
        const password = generateValidPassword();
        const user = await User.create({ username, password });

        // Test JWT auth works
        const jwtRes = await request(app).post("/api/v1/auth/login").send({ username, password }).expect(200);

        assert.ok(jwtRes.body.data.accessToken);

        // Test session auth endpoints still exist
        const sessionRes = await request(app).get("/login").expect(200);

        assert.ok(sessionRes.text.includes("form"));
      });
    });

    describe("JWT Utility Functions", () => {
      it("should generate valid token pairs", async () => {
        const username = generateValidUsername();
        const password = generateValidPassword();
        const user = await User.create({ username, password });

        const tokens = generateTokenPair(user);

        assert.ok(tokens.accessToken);
        assert.ok(tokens.refreshToken);
        assert.equal(tokens.expiresIn, "24h");

        // Verify both tokens
        const accessDecoded = verifyToken(tokens.accessToken);
        const refreshDecoded = verifyToken(tokens.refreshToken);

        assert.equal(accessDecoded.type, "access");
        assert.equal(refreshDecoded.type, "refresh");
        assert.equal(accessDecoded.userId, user.id);
        assert.equal(refreshDecoded.userId, user.id);
        assert.equal(accessDecoded.username, username);
        assert.equal(refreshDecoded.username, username);
      });

      it("should verify tokens correctly", async () => {
        const username = generateValidUsername();
        const password = generateValidPassword();
        const user = await User.create({ username, password });

        const tokens = generateTokenPair(user);
        const decoded = verifyToken(tokens.accessToken);

        assert.equal(decoded.userId, user.id);
        assert.equal(decoded.username, username);
        assert.equal(decoded.type, "access");
      });

      it("should throw error for invalid tokens", () => {
        assert.throws(() => {
          verifyToken("invalid.token.here");
        });
      });
    });
  });
});
