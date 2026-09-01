#!/usr/bin/env node
"use strict";

// Regression test: site.js immediately publishes an initial ?q= value to a
// newly registered workspace subscriber. Atlas must retain that value without
// inspecting its loading placeholder while records.json is still in flight.

const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const atlasPath = path.resolve(__dirname, "..", "assets", "atlas.js");
const atlasSource = fs.readFileSync(atlasPath, "utf8");

const control = () => ({ value: "", addEventListener() {} });
const nodes = {
  "#atlas-records": {
    children: [{ textContent: "Loading Atlas records" }],
    querySelectorAll() {
      throw new Error("Atlas inspected record nodes before the dataset loaded");
    },
    replaceChildren() {},
  },
  "#atlas-empty": { hidden: true },
  "#atlas-count": { textContent: "" },
  "#atlas-search": control(),
  "#atlas-country": control(),
  "#atlas-type": control(),
  "#atlas-year": control(),
  "#atlas-mapping-list": { replaceChildren() {}, append() {} },
  "#atlas-actor-context": { replaceChildren() {} },
  "#atlas-context-count": { textContent: "" },
};

const context = {
  console,
  fetch() {
    return new Promise(() => {});
  },
  URL,
  window: {
    HECAVEX_LABS: {
      bindShellSearch(subscriber) {
        subscriber("initial-query");
        return () => {};
      },
    },
  },
  document: {
    querySelector(selector) {
      return nodes[selector] || null;
    },
    querySelectorAll() {
      return [];
    },
    createElement() {
      throw new Error("Atlas rendered content before the dataset loaded");
    },
    createTextNode() {
      throw new Error("Atlas rendered content before the dataset loaded");
    },
  },
};

vm.runInNewContext(atlasSource, context, { filename: atlasPath });

if (nodes["#atlas-search"].value !== "initial-query") {
  throw new Error("Atlas did not retain the initial shell query");
}

console.log("Atlas initial shell-query regression test passed.");
