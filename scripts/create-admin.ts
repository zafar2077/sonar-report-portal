import { existsSync } from "node:fs";
import { loadEnvFile } from "node:process";
import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import { createAccount } from "../lib/accounts";
import { closeDb } from "../lib/db";
import { AppError } from "../lib/security";

if (existsSync(".env.local")) loadEnvFile(".env.local");
function hiddenQuestion(prompt: string): Promise<string> {
  if (!stdin.isTTY) throw new Error("Run this command in an interactive terminal. Password input is hidden.");
  stdout.write(prompt);
  stdin.setRawMode(true); stdin.resume(); stdin.setEncoding("utf8");
  return new Promise((resolve, reject) => {
    let value = "";
    function finish() { stdin.off("data", read); stdin.setRawMode(false); stdin.pause(); stdout.write("\n"); }
    function read(chunk: string) {
      for (const char of chunk) {
        if (char === "\u0003") { finish(); reject(new Error("Cancelled.")); return; }
        if (char === "\r" || char === "\n") { finish(); resolve(value); return; }
        if (char === "\u007f" || char === "\b") { value = [...value].slice(0, -1).join(""); continue; }
        if (char >= " " && [...value].length < 128) value += char;
      }
    }
    stdin.on("data", read);
  });
}
async function main() {
  console.log("Create a portal administrator. The password is not displayed or saved in configuration.");
  const rl = createInterface({ input: stdin, output: stdout });
  let name: string, email: string;
  try { name = await rl.question("Name: "); email = await rl.question("Email: "); }
  finally { rl.close(); }
  const password = await hiddenQuestion("Password (15–128 characters, hidden): ");
  const confirmation = await hiddenQuestion("Confirm password (hidden): ");
  if (password !== confirmation) throw new AppError(400, "Passwords do not match.");
  await createAccount({ name, email, password, role: "admin" });
  console.log("Administrator created. You can now sign in to the portal.");
}
main().catch(error => {
  console.error(error instanceof AppError ? error.message : "Setup failed. Check .env.local and Atlas network access, then retry in an interactive terminal.");
  process.exitCode = 1;
}).finally(closeDb);
