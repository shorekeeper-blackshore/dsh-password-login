#!/usr/bin/env node
/**
 * dsh-passwd — set the password checked by the dsh-password-login plugin.
 *
 * The plugin reads this file on every login attempt, so a change takes effect
 * immediately: no restart, no session dropped. Only a scrypt hash is stored,
 * never the password itself.
 *
 *   dsh-passwd                            prompt twice on a TTY
 *   echo 'secret' | dsh-passwd --stdin    non-interactive (CI, scripts)
 *   dsh-passwd --file /tmp/x.json --stdin  write somewhere else
 */
import { randomBytes, scrypt as scryptCallback } from "node:crypto";
import { chmod, mkdir, rename, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { argv, stdin, stdout } from "node:process";
import { createInterface } from "node:readline/promises";
import { promisify } from "node:util";

const scrypt = promisify(scryptCallback);

/** Must stay in sync with lib/index.js: the record carries its own N/r/p. */
const N = 32768;
const R = 8;
const P = 1;
const KEYLEN = 32;
const MAXMEM = 128 * 1024 * 1024;
const MIN_LENGTH = 8;

function base64url(buffer) {
  return Buffer.from(buffer).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}

function usage(message) {
  if (message) process.stderr.write("dsh-passwd: " + message + "\n");
  process.stderr.write(
    "usage: dsh-passwd [--file <path>] [--stdin]\n" +
      "  --file <path>  password record to write (default: ~/.dsh/password-login.json)\n" +
      "  --stdin        read the password from standard input\n",
  );
  process.exit(message ? 2 : 0);
}

const args = argv.slice(2);
let file = join(homedir(), ".dsh", "password-login.json");
let fromStdin = false;
for (let index = 0; index < args.length; index += 1) {
  const arg = args[index];
  if (arg === "--file") {
    file = args[index + 1];
    index += 1;
    if (!file) usage("--file needs a path");
  } else if (arg === "--stdin") {
    fromStdin = true;
  } else if (arg === "-h" || arg === "--help") {
    usage();
  } else {
    usage("unknown argument " + JSON.stringify(arg));
  }
}

async function promptHidden(label) {
  if (!(stdin.isTTY && stdout.isTTY)) usage("no TTY for a hidden prompt; pipe the password with --stdin");
  const rl = createInterface({ input: stdin, output: stdout, terminal: true });
  const inner = typeof rl._writeToOutput === "function" ? rl._writeToOutput.bind(rl) : undefined;
  rl._writeToOutput = function muted(text) {
    if (text.includes(label)) stdout.write(text);
    else if (inner) inner(text);
  };
  const answer = await rl.question(label);
  rl.close();
  stdout.write("\n");
  return answer;
}

async function readFromStdin() {
  const chunks = [];
  for await (const chunk of stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8").replace(/\r?\n$/u, "");
}

let password = fromStdin ? await readFromStdin() : await promptHidden("新密码: ");
if (!fromStdin) {
  const again = await promptHidden("再输一次: ");
  if (password !== again) {
    process.stderr.write("dsh-passwd: 两次输入不一致\n");
    process.exit(1);
  }
}
if (password.length < MIN_LENGTH) {
  process.stderr.write("dsh-passwd: 密码至少 " + String(MIN_LENGTH) + " 个字符\n");
  process.exit(1);
}
if (password.length > 512) {
  process.stderr.write("dsh-passwd: 密码过长\n");
  process.exit(1);
}

const salt = randomBytes(16);
const hash = await scrypt(password, salt, KEYLEN, { N, r: R, p: P, maxmem: MAXMEM });
const record = {
  version: 1,
  salt: base64url(salt),
  hash: base64url(hash),
  N,
  r: R,
  p: P,
  updatedAt: new Date().toISOString(),
};

await mkdir(dirname(file), { recursive: true });
const temporary = file + ".tmp-" + String(process.pid);
await writeFile(temporary, JSON.stringify(record, null, 2) + "\n", { mode: 0o600 });
await chmod(temporary, 0o600);
await rename(temporary, file);
await chmod(file, 0o600);
process.stdout.write("密码已更新: " + file + "\n");
