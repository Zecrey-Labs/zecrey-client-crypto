module.exports = {
  root: true,
  parserOptions: {
    ecmaVersion: 2018,
  },
  plugins: ["json"],
  overrides: [
    {
      files: ["*.js", "*.json"],
      parserOptions: {
        sourceType: "script",
      },
      rules: {
        "@typescript-eslint/no-require-imports": "off",
        "@typescript-eslint/no-var-requires": "off",
      },
    },
  ],
  ignorePatterns: ["!.eslintrc.js", "node_modules/", "dist/"],
};
