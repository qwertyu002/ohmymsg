import { readFileSync } from "node:fs";
import { debuglog } from "node:util";
import cryptoRandomString from "crypto-random-string";
import REPLACEMENT_WORDS from "./replacement-words.json" with { type: "json" };

const debug = debuglog("spamscanner");

interface RandomOptions {
  length: number;
  characters: string;
}

const randomOptions: RandomOptions = {
  length: 10,
  characters: "abcdefghijklmnopqrstuvwxyz",
};

// Simply delete the replacements.json to generate new replacements
let replacements: Record<string, string> = {};
try {
  replacements = JSON.parse(readFileSync("./replacements.json", "utf8"));
} catch (error) {
  debug(String(error));
  for (const replacement of REPLACEMENT_WORDS) {
    replacements[replacement] = `${replacement}${cryptoRandomString(randomOptions)}`;
  }
}

export default replacements;
