import ipRegex from "ip-regex";
import tlds from "tlds";

const ipv4 = ipRegex.v4().source;
const ipv6 = ipRegex.v6().source;
const host = "(?:(?:[a-z\\u00a1-\\uffff0-9][-_]*)*[a-z\\u00a1-\\uffff0-9]+)";
const domain = "(?:\\.(?:[a-z\\u00a1-\\uffff0-9]-*)*[a-z\\u00a1-\\uffff0-9]+)*";
const strictTld = "(?:[a-z\\u00a1-\\uffff]{2,})";
const defaultTlds = `(?:${tlds.sort((a, b) => b.length - a.length).join("|")})`;
const port = "(?::\\d{2,5})?";

interface UrlRegexOptions {
  exact?: boolean;
  strict?: boolean;
  auth?: boolean;
  localhost?: boolean;
  parens?: boolean;
  apostrophes?: boolean;
  trailingPeriod?: boolean;
  ipv4?: boolean;
  ipv6?: boolean;
  returnString?: boolean;
  tlds?: string[];
}

export default function urlRegexSafe(options: UrlRegexOptions = {}): RegExp | string {
  const config: Required<UrlRegexOptions> = {
    exact: false,
    strict: false,
    auth: false,
    localhost: true,
    parens: false,
    apostrophes: false,
    trailingPeriod: false,
    ipv4: true,
    ipv6: true,
    returnString: false,
    tlds: [],
    ...options,
  };

  const protocol = `(?:(?:[a-z]+:)?//)${config.strict ? "" : "?"}`;

  // Option to disable matching urls with HTTP Basic Authentication
  // <https://github.com/kevva/url-regex/pull/63>
  const auth = config.auth ? "(?:\\S+(?::\\S*)?@)?" : "";

  // Ability to pass custom list of tlds
  // <https://github.com/kevva/url-regex/pull/66>
  const tld = `(?:\\.${
    config.strict
      ? strictTld
      : config.tlds.length > 0
        ? `(?:${config.tlds.sort((a, b) => b.length - a.length).join("|")})`
        : defaultTlds
  })${config.trailingPeriod ? "\\.?" : ""}`;

  let disallowedChars = '\\s"';
  if (!config.parens) {
    // Not accept closing parenthesis
    // <https://github.com/kevva/url-regex/pull/35>
    disallowedChars += "\\)";
  }

  if (!config.apostrophes) {
    // Don't allow apostrophes
    // <https://github.com/kevva/url-regex/pull/55>
    disallowedChars += "'";
  }

  const path = config.trailingPeriod
    ? `(?:[/?#][^${disallowedChars}]*)?`
    : `(?:(?:[/?#][^${disallowedChars}]*[^${disallowedChars}.?!])|[/])?`;

  // IPv6 support
  // <https://github.com/kevva/url-regex/issues/60>
  let regex = `(?:${protocol}|www\\.)${auth}(?:`;
  if (config.localhost) regex += "localhost|";
  if (config.ipv4) regex += `${ipv4}|`;
  if (config.ipv6) regex += `${ipv6}|`;
  regex += `${host}${domain}${tld})${port}${path}`;

  if (config.returnString) return regex;

  return config.exact ? new RegExp(`(?:^${regex}$)`, "i") : new RegExp(regex, "ig");
}

// Some parts of this file are based on and significantly adapt:
// - https://github.com/spamscanner/url-regex-safe/tree/6c1e2c3 – MIT © 2020 Forward Email LLC, Kevin Mårtensson, and Diego Perini
