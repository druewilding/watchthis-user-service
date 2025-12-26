import config from "eslint-config-plus-prettier";

export default [
  config,
  {
    ignores: ["src/generated/prisma/**"],
  },
];
