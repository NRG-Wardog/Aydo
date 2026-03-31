const fs = require("fs");
const orig = JSON.parse;
JSON.parse = function (s, ...rest) {
  if (typeof s === "string" && s.trimStart().startsWith("{") && s.includes('"name"')) {
    // Heuristic: show callsite stack to identify which file content is being parsed
    console.error("\n[TRACE] JSON.parse saw content starting with {\"name\"...}");
    console.error(new Error("stack").stack.split("\n").slice(0,12).join("\n"));
    console.error("[TRACE] First 120 chars:\n" + s.slice(0,120));
  }
  return orig.call(this, s, ...rest);
};
