import ipRegex from "ip-regex";
import tlds from "tlds";

const ipv4 = ipRegex.v4().source;
const ipv6 = ipRegex.v6().source;
const host = "(?:(?:[a-z\\u00a1-\\uffff0-9][-_]*)*[a-z\\u00a1-\\uffff0-9]+)";
const domain = "(?:\\.(?:[a-z\\u00a1-\\uffff0-9]-*)*[a-z\\u00a1-\\uffff0-9]+)*";
const strictTld = "(?:[a-z\\u00a1-\\uffff]{2,})";
const defaultTlds = `(?:${tlds.sort((a, b) => b.length - a.length).join("|")})`;

interface EmailRegexOptions {
  exact?: boolean;
  strict?: boolean;
  gmail?: boolean;
  utf8?: boolean;
  localhost?: boolean;
  ipv4?: boolean;
  ipv6?: boolean;
  returnString?: boolean;
  tlds?: string[];
}

export default function emailRegexSafe(options: EmailRegexOptions = {}): RegExp | string {
  const config: Required<EmailRegexOptions> = {
    exact: false,
    strict: false,
    gmail: true,
    utf8: true,
    localhost: true,
    ipv4: true,
    ipv6: false,
    returnString: false,
    tlds: [],
    ...options,
  };

  // Ability to pass a custom list of tlds
  // <https://github.com/kevva/url-regex/pull/66>
  const tld = `(?:\\.${
    config.strict
      ? strictTld
      : config.tlds.length > 0
        ? `(?:${config.tlds.sort((a, b) => b.length - a.length).join("|")})`
        : defaultTlds
  })`;

  // <https://github.com/validatorjs/validator.js/blob/master/src/lib/isEmail.js>
  const emailUserPart = config.gmail
    ? // https://support.google.com/mail/answer/9211434?hl=en#:~:text=Usernames%20can%20contain%20letters%20(a%2Dz,in%20a%20row.
      // cannot contain: &, =, _, ', -, +, comma, brackets, or more than one period in a row
      // note that we are parsing for emails, not enforcing username match, so we allow +
      "[^\\W_](?:[\\w\\.\\+]+)" // NOTE: we don't end with `[^\\W]` here since Gmail doesn't do this in webmail
    : config.utf8
      ? "[^\\W_](?:[a-z\\d!#\\$%&'\\.\\*\\+\\-\\/=\\?\\^_`{\\|}~\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF]+)"
      : "[^\\W_](?:[a-z\\d!#\\$%&'\\.\\*\\+\\-\\/=\\?\\^_`{\\|}~]+)";

  let regex = `(?:${emailUserPart}@(?:`;
  if (config.localhost) regex += "localhost|";
  if (config.ipv4) regex += `${ipv4}|`;
  if (config.ipv6) regex += `${ipv6}|`;
  regex += `${host}${domain}${tld}))`;

  if (config.returnString) return regex;

  return config.exact ? new RegExp(`(?:^${regex}$)`, "i") : new RegExp(regex, "ig");
}

// Some parts of this file are based on and significantly adapt:
// - https://github.com/spamscanner/email-regex-safe/tree/9844448 – MIT © 2020 Forward Email LLC
