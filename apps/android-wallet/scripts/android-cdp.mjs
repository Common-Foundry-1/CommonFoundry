#!/usr/bin/env node

import { readFile } from "node:fs/promises";

const port = process.env.CMFD_CDP_PORT ?? "9222";
const [action = "snapshot", ...args] = process.argv.slice(2);
const pages = await fetch(`http://127.0.0.1:${port}/json`).then((response) => response.json());
const page = pages.find((candidate) => candidate.url === "http://tauri.localhost/");
if (!page) throw new Error("Common Foundry Wallet WebView not found");

const socket = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((resolve, reject) => {
  socket.addEventListener("open", resolve, { once: true });
  socket.addEventListener("error", reject, { once: true });
});

let sequence = 0;
function evaluate(expression) {
  const id = ++sequence;
  socket.send(JSON.stringify({
    id,
    method: "Runtime.evaluate",
    params: { expression, awaitPromise: true, returnByValue: true },
  }));
  return new Promise((resolve, reject) => {
    const listener = (event) => {
      const message = JSON.parse(event.data);
      if (message.id !== id) return;
      socket.removeEventListener("message", listener);
      if (message.error || message.result?.exceptionDetails) {
        reject(new Error(JSON.stringify(message.error ?? message.result.exceptionDetails)));
        return;
      }
      resolve(message.result?.result?.value);
    };
    socket.addEventListener("message", listener);
  });
}

const js = (value) => JSON.stringify(value);
let result;

if (action === "snapshot") {
  result = await evaluate(`JSON.stringify(Array.from(document.querySelectorAll('button,input')).map((element, index) => ({
    index,
    tag: element.tagName,
    type: element.type || null,
    text: element.tagName === 'INPUT' ? null : element.textContent.trim(),
    placeholder: element.placeholder || null,
    value: element.type === 'password' ? '[redacted]' : (element.value || null),
    disabled: element.disabled,
    rect: (() => { const r = element.getBoundingClientRect(); return { x: r.x, y: r.y, width: r.width, height: r.height }; })()
  })))`);
} else if (action === "click-text") {
  const text = args.join(" ").trim();
  if (!text) throw new Error("click-text requires visible button text");
  result = await evaluate(`(() => {
    const wanted = ${js(text)};
    const button = Array.from(document.querySelectorAll('button')).find((item) => item.textContent.trim() === wanted);
    if (!button) throw new Error('button not found: ' + wanted);
    button.click();
    return true;
  })()`);
} else if (action === "set-input-from-file") {
  const [indexText, path] = args;
  const index = Number.parseInt(indexText, 10);
  if (!Number.isInteger(index) || !path) throw new Error("set-input-from-file requires an input index and path");
  const value = (await readFile(path, "utf8")).trimEnd();
  result = await evaluate(`(() => {
    const input = Array.from(document.querySelectorAll('input'))[${index}];
    if (!input) throw new Error('input not found');
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
    setter.call(input, ${js(value)});
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
    return true;
  })()`);
} else if (action === "set-input") {
  const [indexText, ...valueParts] = args;
  const index = Number.parseInt(indexText, 10);
  const value = valueParts.join(" ");
  if (!Number.isInteger(index)) throw new Error("set-input requires an input index and value");
  result = await evaluate(`(() => {
    const input = Array.from(document.querySelectorAll('input'))[${index}];
    if (!input) throw new Error('input not found');
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
    setter.call(input, ${js(value)});
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
    return true;
  })()`);
} else if (action === "click-input") {
  const index = Number.parseInt(args[0], 10);
  if (!Number.isInteger(index)) throw new Error("click-input requires an input index");
  result = await evaluate(`(() => {
    const input = Array.from(document.querySelectorAll('input'))[${index}];
    if (!input) throw new Error('input not found');
    input.click();
    return true;
  })()`);
} else if (action === "text") {
  result = await evaluate("document.body.innerText");
} else if (action === "clipboard") {
  result = await evaluate("navigator.clipboard.readText()");
} else {
  throw new Error(`Unsupported action: ${action}`);
}

if (result !== undefined) console.log(result);
socket.close();
