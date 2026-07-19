import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../src/', import.meta.url));
const failures = [];
function walk(dir) {
  for (const entry of readdirSync(dir)) {
    const file = join(dir, entry);
    if (statSync(file).isDirectory()) walk(file);
    else if (file.endsWith('.ts')) {
      const text = readFileSync(file, 'utf8');
      if (/from\s+['\"]node:child_process['\"]|require\(['\"](?:node:)?child_process['\"]\)|\b(?:execSync|execFileSync|spawnSync|spawn)\s*\(/.test(text)) failures.push(`${file}: prohibited process execution API`);
      if (/\btools\/call\b|method:\s*['\"]tools\/call/.test(text)) failures.push(`${file}: tool execution is forbidden`);
    }
  }
}
walk(root);
if (failures.length) {
  console.error(failures.join('\n'));
  process.exit(1);
}
console.log('Custom security lint passed: no process-execution or MCP tool-invocation APIs found.');
