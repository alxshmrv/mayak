#!/usr/bin/env node

import { mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const REGISTRIES = [
  {
    bits: 24,
    name: "MA-L",
    url: "https://standards-oui.ieee.org/oui/oui.csv",
  },
  {
    bits: 28,
    name: "MA-M",
    url: "https://standards-oui.ieee.org/oui28/mam.csv",
  },
  {
    bits: 36,
    name: "MA-S",
    url: "https://standards-oui.ieee.org/oui36/oui36.csv",
  },
];

const outputUrl = new URL("../src-tauri/data/ieee-ma.tsv", import.meta.url);

function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = "";
  let quoted = false;

  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (quoted) {
      if (char === '"' && text[index + 1] === '"') {
        field += '"';
        index += 1;
      } else if (char === '"') {
        quoted = false;
      } else {
        field += char;
      }
    } else if (char === '"') {
      quoted = true;
    } else if (char === ",") {
      row.push(field);
      field = "";
    } else if (char === "\n") {
      row.push(field.replace(/\r$/, ""));
      rows.push(row);
      row = [];
      field = "";
    } else {
      field += char;
    }
  }

  if (field.length > 0 || row.length > 0) {
    row.push(field.replace(/\r$/, ""));
    rows.push(row);
  }
  return rows;
}

function compactOrganization(value) {
  return value.replace(/[\t\r\n]+/g, " ").replace(/\s+/g, " ").trim();
}

async function downloadRegistry(registry) {
  const response = await fetch(registry.url, {
    headers: { "user-agent": "mayak-registry-updater/1.0" },
  });
  if (!response.ok) {
    throw new Error(
      `${registry.name}: IEEE returned ${response.status} ${response.statusText}`,
    );
  }

  const rows = parseCsv(await response.text());
  const header = rows.shift();
  const assignmentIndex = header?.indexOf("Assignment") ?? -1;
  const organizationIndex = header?.indexOf("Organization Name") ?? -1;
  if (assignmentIndex < 0 || organizationIndex < 0) {
    throw new Error(`${registry.name}: unexpected IEEE CSV header`);
  }

  const expectedLength = Math.ceil(registry.bits / 4);
  return rows
    .map((row) => ({
      bits: registry.bits,
      prefix: row[assignmentIndex]?.replace(/[^0-9A-F]/gi, "").toUpperCase(),
      organization: compactOrganization(row[organizationIndex] ?? ""),
    }))
    .filter(
      ({ prefix, organization }) =>
        prefix.length === expectedLength && organization.length > 0,
    );
}

const records = (
  await Promise.all(REGISTRIES.map((registry) => downloadRegistry(registry)))
)
  .flat()
  .sort(
    (left, right) =>
      right.bits - left.bits || left.prefix.localeCompare(right.prefix),
  );

const snapshot = new Date().toISOString().slice(0, 10);
const contents = [
  "# IEEE Registration Authority public MA-L, MA-M and MA-S listings",
  `# Snapshot: ${snapshot}`,
  "# Source: https://standards.ieee.org/products-programs/regauth/",
  "# prefix-bits<TAB>hex-prefix<TAB>organization",
  ...records.map(
    ({ bits, prefix, organization }) => `${bits}\t${prefix}\t${organization}`,
  ),
  "",
].join("\n");

await mkdir(fileURLToPath(new URL("../src-tauri/data/", import.meta.url)), {
  recursive: true,
});
await writeFile(fileURLToPath(outputUrl), contents, "utf8");
console.log(`Wrote ${records.length} IEEE assignments to ${fileURLToPath(outputUrl)}`);
