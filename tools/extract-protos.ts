// Keeper publishes no .proto sources; Commander only ships protoc-generated *_pb2.py
// modules. Each of those embeds its complete serialized FileDescriptorProto, so this
// script lifts those bytes out verbatim and concatenates them into a FileDescriptorSet
// that build.rs hands to prost. Field numbers therefore come straight from Keeper.
//
// Usage: bun tools/extract-protos.ts <path-to-Commander-checkout> [root.proto ...]

import { readFileSync, writeFileSync } from "node:fs";

const commander = process.argv[2];
if (!commander) throw new Error("usage: bun tools/extract-protos.ts <Commander checkout> [root.proto ...]");
const roots = process.argv.length > 3 ? process.argv.slice(3) : ["APIRequest.proto", "SyncDown.proto", "AccountSummary.proto"];
const protoDir = `${commander}/keepercommander/proto`;

function unescapePyBytes(src: string): Uint8Array {
  const marker = "AddSerializedFile(b'";
  const start = src.indexOf(marker);
  if (start < 0) throw new Error("no AddSerializedFile call found");
  const out: number[] = [];
  for (let i = start + marker.length; src[i] !== "'"; i++) {
    if (src[i] !== "\\") {
      out.push(src.charCodeAt(i));
      continue;
    }
    const esc = src[++i];
    if (esc === "x") {
      out.push(parseInt(src.slice(i + 1, i + 3), 16));
      i += 2;
    } else if (esc === "n") out.push(10);
    else if (esc === "r") out.push(13);
    else if (esc === "t") out.push(9);
    else if (esc === "\\" || esc === "'" || esc === '"') out.push(esc.charCodeAt(0));
    else throw new Error(`unsupported escape \\${esc}`);
  }
  return new Uint8Array(out);
}

function readVarint(buf: Uint8Array, pos: number): [number, number] {
  let value = 0;
  let shift = 0;
  for (;;) {
    const b = buf[pos++];
    value += (b & 0x7f) * 2 ** shift;
    if (b < 0x80) return [value, pos];
    shift += 7;
  }
}

function encodeVarint(n: number): number[] {
  const out: number[] = [];
  while (n >= 0x80) {
    out.push((n % 0x80) | 0x80);
    n = Math.floor(n / 0x80);
  }
  out.push(n);
  return out;
}

// FileDescriptorProto field 1 is `name`, field 3 is repeated `dependency`.
function nameAndDeps(fd: Uint8Array): { name: string; deps: string[] } {
  const decoder = new TextDecoder();
  let name = "";
  const deps: string[] = [];
  let pos = 0;
  while (pos < fd.length) {
    let key: number;
    [key, pos] = readVarint(fd, pos);
    const field = Math.floor(key / 8);
    switch (key & 7) {
      case 0:
        pos = readVarint(fd, pos)[1];
        break;
      case 1:
        pos += 8;
        break;
      case 5:
        pos += 4;
        break;
      case 2: {
        let len: number;
        [len, pos] = readVarint(fd, pos);
        if (field === 1) name = decoder.decode(fd.subarray(pos, pos + len));
        if (field === 3) deps.push(decoder.decode(fd.subarray(pos, pos + len)));
        pos += len;
        break;
      }
      default:
        throw new Error(`unexpected wire type in ${name || "descriptor"}`);
    }
  }
  return { name, deps };
}

const seen = new Set<string>();
const queue = [...roots];
const set: number[] = [];
while (queue.length > 0) {
  const file = queue.shift()!;
  if (seen.has(file)) continue;
  // google/api/annotations only decorates gRPC service methods (prost emits no services) and
  // google/protobuf/* well-known types map to prost-types, so neither needs a descriptor here.
  if (file.startsWith("google/")) continue;
  seen.add(file);
  const fd = unescapePyBytes(readFileSync(`${protoDir}/${file.replace(/\.proto$/, "_pb2.py")}`, "latin1"));
  const { name, deps } = nameAndDeps(fd);
  if (name !== file) throw new Error(`${file} describes itself as ${name}`);
  set.push(0x0a, ...encodeVarint(fd.length), ...fd);
  queue.push(...deps);
}

writeFileSync("proto/keeper.fds.bin", new Uint8Array(set));
console.log([...seen].join("\n"));
