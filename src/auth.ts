import flash from "connect-flash";
import connectPgSimple from "connect-pg-simple";
import crypto from "crypto";
import type { RequestHandler } from "express";
import type express from "express";
import session from "express-session";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";

import type { IUser } from "./models/user.js";
import { User } from "./models/user.js";

const PgSession = connectPgSimple(session);
const databaseUrl = process.env.DATABASE_URL ?? "postgresql://localhost:5432/watchthis_user_service";

export const pgStore = new PgSession({
  conString: databaseUrl,
  tableName: "sessions",
  createTableIfMissing: true,
});

const baseUrl = new URL(process.env.BASE_URL ?? "http://localhost:8583");
const sessionSecret = process.env.SESSION_SECRET ?? crypto.randomBytes(64).toString("hex");

export function applyAuthenticationMiddleware(app: express.Express): void {
  app.use(
    session({
      secret: sessionSecret,
      resave: false,
      saveUninitialized: false,
      store: pgStore,
      cookie: {
        domain: baseUrl.hostname.split(".").slice(1).join("."),
      },
    })
  );

  app.use(flash());
  app.use(passport.initialize());
  app.use(passport.session());

  passport.serializeUser(function (user, done) {
    done(null, (user as IUser).id);
  });

  passport.deserializeUser(function (id, done) {
    (async function () {
      try {
        const user = await User.findById(id as string);
        done(null, user);
      } catch (err) {
        done(err);
      }
    })();
  });

  passport.use(
    new LocalStrategy((username, password, done) => {
      (async () => {
        try {
          const user = await User.findOne({ username });

          if (user === null || user === undefined) {
            done(null, false, { message: "Incorrect username." });
            return;
          }

          const isMatch = await User.comparePassword(user, password);

          if (!isMatch) {
            done(null, false, { message: "Incorrect password." });
            return;
          }

          done(null, user);
        } catch (err) {
          done(err);
        }
      })();
    })
  );
}

export const ensureAuthenticated: RequestHandler = (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) => {
  if (req.isAuthenticated()) {
    next();
    return;
  }
  res.redirect("/login");
};

export const authenticate: RequestHandler = (req, res, next) => {
  passport.authenticate("local", (err: any, user: any, info: any) => {
    if (err) {
      return next(err);
    }
    if (!user) {
      req.flash("error", info?.message || "Login failed");
      return res.redirect("/login");
    }

    req.logIn(user, (err: any) => {
      if (err) {
        return next(err);
      }

      // Force session save before redirect to prevent race conditions
      req.session.save((err: any) => {
        if (err) {
          console.error("Session save error:", err);
          return next(err);
        }

        // Use intermediate redirect to avoid CSP issues
        const callbackUrl = req.body.callbackUrl;
        if (callbackUrl && callbackUrl !== "/dashboard") {
          res.redirect(`/redirect?to=${encodeURIComponent(callbackUrl)}`);
        } else {
          res.redirect("/dashboard");
        }
      });
    });
  })(req, res, next);
};
