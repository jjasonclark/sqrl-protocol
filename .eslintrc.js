module.exports = {
  env: {
    es6: true,
    node: true
  },
  extends: [
    'eslint:recommended',
    'plugin:import/errors',
    'plugin:import/warnings',
    'plugin:promise/recommended',
    'plugin:node/recommended',
    'plugin:jest/recommended',
    'prettier'
  ],
  globals: {
    Atomics: 'readonly',
    SharedArrayBuffer: 'readonly'
  },
  parserOptions: {
    ecmaVersion: 2018,
    sourceType: 'module'
  },
  plugins: ['filenames', 'jest', 'import', 'promise', 'node', 'test-filenames'],
  rules: {
    'filenames/match-exported': [2, [null, 'kebab', 'snake']],
    'test-filenames/no-subdirs': 'error',
    'test-filenames/suffix': 'error'
  }
};
