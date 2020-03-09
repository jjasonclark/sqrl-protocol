const resolve = require('@rollup/plugin-node-resolve');
const commonjs = require('@rollup/plugin-commonjs');
const pkg = require('./package.json');

const nodeDependencies = ['crypto', 'os', 'querystring', 'tty', 'util', 'url'];

module.exports = [
  {
    input: 'index.js',
    external: [...nodeDependencies, ...Object.keys(pkg.dependencies)],
    output: { dir: './dist', name: 'index.js', format: 'cjs', interop: false },
    plugins: [resolve({ preferBuiltins: true }), commonjs()]
  }
];
