import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import process from 'node:process';
import test from 'node:test';
import { fileURLToPath, URL } from 'node:url';
import { ESLint } from 'eslint';
import ts from 'typescript';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(path.join(root, 'package.json'));
const compiler = path.join(root, 'node_modules/.bin/tsc');
const lintBaseline = JSON.parse(readFileSync(new URL('./fixtures/lint-scopes.json', import.meta.url), 'utf8'));
const eslint = new ESLint({ cwd: root });
const stable = value => Array.isArray(value) ? value.map(stable) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])])) : value;
const digest = value => createHash('sha256').update(JSON.stringify(stable(value))).digest('hex');
const effective = (config, ignored) => ({
  ignored, rules: config?.rules || null, globals: config?.languageOptions?.globals || null,
  ecmaVersion: config?.languageOptions?.ecmaVersion || null, sourceType: config?.languageOptions?.sourceType || null,
  parserOptions: config?.languageOptions?.parserOptions || null, linterOptions: config?.linterOptions || null,
  processor: config?.processor?.meta || null
});

function compile(text, overrides = {}) {
  const directory = mkdtempSync(path.join(tmpdir(), 'babel-tooling-'));
  try {
    writeFileSync(path.join(directory, 'control.ts'), text);
    writeFileSync(path.join(directory, 'tsconfig.json'), JSON.stringify({
      extends: path.join(root, 'tsconfig.json'),
      compilerOptions: { composite: false, typeRoots: [path.join(root, 'node_modules/@types')], ...overrides },
      files: ['control.ts'], include: [], references: []
    }));
    return spawnSync(compiler, ['--project', path.join(directory, 'tsconfig.json'), '--pretty', 'false'],
      { cwd: root, encoding: 'utf8', env: { ...process.env, FORCE_COLOR: '1' } });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test('the build tsc is native 7 while ESLint receives the supported JavaScript API', () => {
  const native = require('@typescript/native/package.json');
  const apiWrapper = require('typescript/package.json');
  assert.equal(native.version, '7.0.2');
  assert.equal(apiWrapper.name, '@typescript/typescript6');
  assert.equal(apiWrapper.version, '6.0.2');
  assert.match(realpathSync(compiler), /[\\/]@typescript[\\/]native[\\/]bin[\\/]tsc$/);
  assert.match(execFileSync(compiler, ['--version'], { encoding: 'utf8' }), /^Version 7\.0\.2\s*$/);
  assert.match(ts.version, /^6\.0\./);
  assert.equal(typeof ts.createProgram, 'function');
  assert.equal(ts.createSourceFile('valid.ts', 'export const valid: number = 1;', ts.ScriptTarget.Latest).parseDiagnostics.length, 0);
  assert.ok(ts.createSourceFile('invalid.ts', 'export const invalid = ;', ts.ScriptTarget.Latest).parseDiagnostics.length > 0);
});

test('all existing strict compiler options, source scope, and Node ambient types stay enabled', () => {
  const config = JSON.parse(readFileSync(path.join(root, 'tsconfig.json'), 'utf8'));
  assert.equal(digest(config), lintBaseline.compilerConfigSha256);
  assert.deepEqual(config.compilerOptions.types, ['node']);
  assert.deepEqual(config.include, ['src']);
  assert.deepEqual(config.references, [{ path: './tsconfig.node.json' }]);
});

test('native compiler accepts a real Node import and browser DOM types', () => {
  const result = compile('import { readFileSync } from "node:fs";\nexport const content: string = readFileSync("fixture", "utf8");\nexport const element: HTMLElement = document.body;');
  assert.equal(result.status, 0, result.stdout + result.stderr);
});

test('native compiler fails when the required Node ambient types are removed', () => {
  const result = compile('import { readFileSync } from "node:fs";\nexport const content = readFileSync("fixture", "utf8");', { types: [] });
  assert.notEqual(result.status, 0);
  assert.match(result.stdout + result.stderr, /TS2591.*node:fs/);
});

test('native compiler rejects implicit any and invalid strict null assignment even with forced color', () => {
  const result = compile('export function implicit(input) { return input; }\nexport const invalid: string = null;');
  assert.notEqual(result.status, 0);
  assert.match(result.stdout + result.stderr, /TS7006/);
  assert.match(result.stdout + result.stderr, /TS2322/);
});

test('all 23 previously linted paths retain their exact rules, globals, language and ignore behavior', async () => {
  assert.equal(lintBaseline.paths.length, 23);
  for (const entry of lintBaseline.paths) {
    const filename = path.join(root, entry.path);
    const config = await eslint.calculateConfigForFile(filename);
    assert.equal(digest(effective(config, await eslint.isPathIgnored(filename))), entry.configSha256, entry.path);
  }
  for (const ignored of ['dist/control.js', 'node_modules/control.js', 'coverage/control.js']) {
    assert.equal(await eslint.isPathIgnored(path.join(root, ignored)), true, ignored);
  }
});

test('ESLint using the JavaScript API accepts valid typed learner code', async () => {
  const [result] = await eslint.lintText('export const identity = (input: number): number => input;\n',
    { filePath: path.join(root, 'src/__tooling_control__.ts') });
  assert.equal(result.errorCount, 0, JSON.stringify(result.messages));
  assert.equal(result.warningCount, 0, JSON.stringify(result.messages));
});

test('ESLint still rejects explicit any and unused locals under the same source rules', async () => {
  const [result] = await eslint.lintText('const unused = 1;\nexport const identity = (input: any): any => input;\n',
    { filePath: path.join(root, 'src/__tooling_control__.ts') });
  assert.ok(result.messages.some(message => message.ruleId === '@typescript-eslint/no-unused-vars'));
  assert.ok(result.messages.some(message => message.ruleId === '@typescript-eslint/no-explicit-any'));
});

test('ESLint preserves the explicit smart equality rule', async () => {
  const [result] = await eslint.lintText('export const compare = (left: string, right: number) => left == right;\n',
    { filePath: path.join(root, 'src/__tooling_control__.ts') });
  assert.ok(result.messages.some(message => message.ruleId === 'eqeqeq'));
});
