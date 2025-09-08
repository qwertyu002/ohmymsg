import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { memoryUsage } from "node:process";
import { fileURLToPath } from "node:url";
import { debuglog } from "node:util";
import NaiveBayes from "@ladjs/naivebayes";
import expandContractions from "@stdlib/nlp-expand-contractions";
import arrayJoinConjunction from "array-join-conjunction";
import AFHConvert from "ascii-fullwidth-halfwidth-convert";
import autoBind from "auto-bind";
import bitcoinRegex from "bitcoin-regex";
import ClamScan from "clamscan";
import creditCardRegex from "credit-card-regex";
import escapeStringRegexp from "escape-string-regexp";
import fileExtension from "file-extension";
import { fileTypeFromBuffer } from "file-type";
import floatingPointRegex from "floating-point-regex";
import hexaColorRegex from "hexa-color-regex";
import ipRegex from "ip-regex";
import isBuffer from "is-buffer";
import isSANB from "is-string-and-not-blank";
import lande from "lande";
import macRegex from "mac-regex";
import { simpleParser } from "mailparser";
import natural from "natural";
import normalizeUrl from "normalize-url";
import phoneRegex from "phone-regex";
import sw from "stopword";
import striptags from "striptags";
import superagent from "superagent";
import emailRegexSafe from "./email-regex-safe";
import snowball, {
  CharacterEncoding,
  getSupportedAlgorithms,
  isLanguageSupported,
  stemwordAdvanced,
} from "./node-snowball.js";

// Re-export for external use
export type { CharacterEncoding };

import urlRegexSafe from "./url-regex-safe";

// ES module compatibility
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load JSON data
// const REPLACEMENT_WORDS = JSON.parse(
//   readFileSync(join(__dirname, "replacement-words.json"), "utf8"),
// );
const executablesData = JSON.parse(readFileSync(join(__dirname, "executables.json"), "utf8"));

const EXECUTABLES = new Set(executablesData);

// Dynamic imports for modules that need to be loaded conditionally
const getReplacements = async (): Promise<Record<string, string>> => {
  const { default: replacements } = await import("./replacements.js");
  return replacements;
};

const getClassifier = async (): Promise<ClassifierData> => {
  const { default: classifier } = await import("./get-classifier.js");
  return classifier;
};

const debug = debuglog("spamscanner");

// ClassifierData interface
interface ClassifierData {
  categories: string[];
  vocabulary: Record<string, number>;
  docCount: number;
  totalDocuments: number;
  wordCount: Record<string, number>;
  wordFrequencyCount: Record<string, number>;
  options: {
    tokenizer: string;
    vocabulary: Record<string, number>;
    vocabularySize: number;
    minimumFrequency: number;
    maximumVocabularySize: number;
    minimumLength: number;
    maximumLength: number;
    caseSensitive: boolean;
    stripHtml: boolean;
    stripPunctuation: boolean;
    stripNumbers: boolean;
    stripStopWords: boolean;
    stripAccents: boolean;
    stripDiacritics: boolean;
    stripEmojis: boolean;
    stripUrls: boolean;
    stripEmails: boolean;
    stripPhoneNumbers: boolean;
    stripCreditCards: boolean;
    stripIps: boolean;
    stripMacs: boolean;
    stripBitcoins: boolean;
    stripHexColors: boolean;
    stripFloatingPoints: boolean;
    stripDates: boolean;
    stripFilePaths: boolean;
    stripArbitrary: boolean;
    stripMacros: boolean;
    stripExecutables: boolean;
    stripViruses: boolean;
    stripPhishing: boolean;
    stripIdnHomograph: boolean;
    stripPatterns: boolean;
    stripMixedLanguage: boolean;
    stripAdvancedPatterns: boolean;
    stripPerformanceMetrics: boolean;
    stripCaching: boolean;
    stripTimeout: boolean;
    stripSupportedLanguages: boolean;
    stripDebug: boolean;
    stripLogger: boolean;
    stripClamscan: boolean;
    stripClassifier: boolean;
    stripReplacements: boolean;
    stripHashTokens: boolean;
    stripStrictIdnDetection: boolean;
    stripEnableMacroDetection: boolean;
    stripEnableMalwareUrlCheck: boolean;
    stripEnablePerformanceMetrics: boolean;
    stripEnableCaching: boolean;
    stripEnableMixedLanguageDetection: boolean;
    stripEnableAdvancedPatternRecognition: boolean;
  };
}

// All tokenizers combined - improved regex pattern
const GENERIC_TOKENIZER =
  /[^a-zá-úÁ-Úà-úÀ-Úñü\dа-яёæøåàáảãạăắằẳẵặâấầẩẫậéèẻẽẹêếềểễệíìỉĩịóòỏõọôốồổỗộơớờởỡợúùủũụưứừửữựýỳỷỹỵđäöëïîûœçążśźęćńł-]+/i;

const converter = new AFHConvert();

// Regex patterns for performance optimization
const WHITESPACE_REGEX = /\s+/;
const HTML_TAG_REGEX = /^\/([a-z\d]+)$/i;
const DOMAIN_PATH_REGEX = /^\/\/[a-z\d.-]+$/i;

// Chinese tokenizer setup with proper path resolution
const chineseTokenizer = { tokenize: (text: string) => text.split(WHITESPACE_REGEX) };

// Enhanced stopwords with fallback for missing language-specific stopwords
const stopwordsMap = new Map<string, Set<string>>([
  ["ar", new Set([...(natural.stopwords || []), ...(sw.ara || [])])],
  ["bg", new Set([...(natural.stopwords || []), ...(sw.bul || [])])],
  ["bn", new Set([...(natural.stopwords || []), ...(sw.ben || [])])],
  ["ca", new Set([...(natural.stopwords || []), ...(sw.cat || [])])],
  ["cs", new Set([...(natural.stopwords || []), ...(sw.ces || [])])],
  ["da", new Set([...(natural.stopwords || []), ...(sw.dan || [])])],
  ["de", new Set([...(natural.stopwords || []), ...(sw.deu || [])])],
  ["el", new Set([...(natural.stopwords || []), ...(sw.ell || [])])],
  ["en", new Set([...(natural.stopwords || []), ...(sw.eng || [])])],
  ["es", new Set([...(natural.stopwords || []), ...(sw.spa || [])])],
  ["fa", new Set([...(natural.stopwords || []), ...(sw.fas || [])])],
  ["fi", new Set([...(natural.stopwords || []), ...(sw.fin || [])])],
  ["fr", new Set([...(natural.stopwords || []), ...(sw.fra || [])])],
  ["ga", new Set([...(natural.stopwords || []), ...(sw.gle || [])])],
  ["gl", new Set([...(natural.stopwords || []), ...(sw.glg || [])])],
  ["gu", new Set([...(natural.stopwords || []), ...(sw.guj || [])])],
  ["he", new Set([...(natural.stopwords || []), ...(sw.heb || [])])],
  ["hi", new Set([...(natural.stopwords || []), ...(sw.hin || [])])],
  ["hr", new Set([...(natural.stopwords || []), ...(sw.hrv || [])])],
  ["hu", new Set([...(natural.stopwords || []), ...(sw.hun || [])])],
  ["hy", new Set([...(natural.stopwords || []), ...(sw.hye || [])])],
  ["it", new Set([...(natural.stopwords || []), ...(sw.ita || [])])],
  ["ja", new Set([...(natural.stopwords || []), ...(sw.jpn || [])])],
  ["ko", new Set([...(natural.stopwords || []), ...(sw.kor || [])])],
  ["la", new Set([...(natural.stopwords || []), ...(sw.lat || [])])],
  ["lt", new Set([...(natural.stopwords || []), ...(sw.lit || [])])],
  ["lv", new Set([...(natural.stopwords || []), ...(sw.lav || [])])],
  ["mr", new Set([...(natural.stopwords || []), ...(sw.mar || [])])],
  ["nl", new Set([...(natural.stopwords || []), ...(sw.nld || [])])],
  ["no", new Set([...(natural.stopwords || []), ...(sw.nor || [])])],
  ["pl", new Set([...(natural.stopwords || []), ...(sw.pol || [])])],
  ["pt", new Set([...(natural.stopwords || []), ...(sw.por || [])])],
  ["ro", new Set([...(natural.stopwords || []), ...(sw.ron || [])])],
  ["sk", new Set([...(natural.stopwords || []), ...(sw.slk || [])])],
  ["sl", new Set([...(natural.stopwords || []), ...(sw.slv || [])])],
  ["sv", new Set([...(natural.stopwords || []), ...(sw.swe || [])])],
  ["th", new Set([...(natural.stopwords || []), ...(sw.tha || [])])],
  ["tr", new Set([...(natural.stopwords || []), ...(sw.tur || [])])],
  ["uk", new Set([...(natural.stopwords || []), ...(sw.ukr || [])])],
  ["vi", new Set([...(natural.stopwords || []), ...(sw.vie || [])])],
  ["zh", new Set([...(natural.stopwords || []), ...(sw.cmn || [])])],
]);

// URL ending reserved characters
const URL_ENDING_RESERVED_CHARS = /[).,;!?]+$/;

// Date pattern detection (DONE)
const DATE_PATTERNS = [
  /\b(?:\d{1,2}[/-]){2}\d{2,4}\b/g, // MM/DD/YYYY or DD/MM/YYYY
  /\b\d{4}(?:[/-]\d{1,2}){2}\b/g, // YYYY/MM/DD
  /\b\d{1,2}\s+(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\s+\d{2,4}\b/gi, // DD MMM YYYY
  /\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\s+\d{1,2},?\s+\d{2,4}\b/gi, // MMM DD, YYYY
];

// File path detection (DONE)
const FILE_PATH_PATTERNS = [
  /[a-z]:\\\\[^\\s<>:"|?*]+(?:\\[^\\s<>:"|?*]+)+/gi, // Windows paths with at least 2 segments
  /(?:^|\s)\/(?!\/)[^\s<>:"|?*]+(?:\/[^\s<>:"|?*]+)+/g, // Unix paths (avoid protocol-relative //)
  /~\/(?:[^\s<>:"|?*]+)(?:\/[^\s<>:"|?*]+)*/g, // Home directory paths
];

// Additional regex patterns
const CREDIT_CARD_PATTERN = creditCardRegex({ exact: false });
const PHONE_PATTERN = phoneRegex({ exact: false });
const EMAIL_PATTERN = emailRegexSafe({ exact: false });
const IP_PATTERN = ipRegex({ exact: false });
const URL_PATTERN = urlRegexSafe({ exact: false });
const BITCOIN_PATTERN = bitcoinRegex({ exact: false });
const MAC_PATTERN = macRegex({ exact: false });
const HEX_COLOR_PATTERN = hexaColorRegex({ exact: false });
const FLOATING_POINT_PATTERN = floatingPointRegex;

// Hoisted regular expressions
const DOCTYPE_REGEX = /<!doctype[^>]*>/gi;
const HTML_COMMENT_REGEX = /<!--[\s\S]*?-->/g;
const LEADING_DOUBLE_SLASH_REGEX = /^\s*\/\//;
const HTTP_URL_REGEX = /https?:\/\//i;
const REACT_STREAM_MARKER_REGEX = /\/\$-{0,2}/;
const W3C_DTD_REGEX = /w3\.org\/(TR|tr)\/xhtml1\/DTD\//i;
const TEMPLATE_HANDLEBARS_REGEX = /{{[\s\S]*?}}/g;
const TEMPLATE_TWIG_REGEX = /{%[\s\S]*?%}/g;
const TEMPLATE_EJS_REGEX = /<%[=-]?[\s\S]*?%>/g;
const ATTR_VALUE_DOUBLE_QUOTE_REGEX = /(\b(?:href|src|data|content)\s*=\s*")[^"]*(")/gi;
const ATTR_VALUE_SINGLE_QUOTE_REGEX = /(\b(?:href|src|data|content)\s*=\s*')[^']*(')/gi;
const NULL_UNDEFINED_REGEX = /\b(null|undefined)\b/gi;

// Sensitive directories and dangerous file extensions
const SENSITIVE_DIRS = [
  "/etc/",
  "/bin/",
  "/usr/bin/",
  "/usr/sbin/",
  "/sbin/",
  "/var/",
  "/dev/",
  "/private/",
  "C:\\Windows\\",
  "C:\\Program Files\\",
  "C:\\Users\\",
  "C:\\ProgramData\\",
];
const DANGEROUS_EXTS = new Set([
  "exe",
  "bat",
  "cmd",
  "com",
  "scr",
  "pif",
  "ps1",
  "vbs",
  "vbe",
  "js",
  "jse",
  "jar",
  "msi",
  "msp",
  "dll",
  "sys",
]);

// Type definitions
interface SpamScannerOptions {
  enableMacroDetection?: boolean;
  enableMalwareUrlCheck?: boolean;
  enablePerformanceMetrics?: boolean;
  enableCaching?: boolean;
  timeout?: number;
  supportedLanguages?: string[];
  enableMixedLanguageDetection?: boolean;
  enableAdvancedPatternRecognition?: boolean;
  debug?: boolean;
  logger?: Console;
  clamscan?: {
    removeInfected?: boolean;
    quarantineInfected?: boolean;
    scanLog?: string | null;
    debugMode?: boolean;
    fileList?: string | null;
    scanRecursively?: boolean;
    clamscanPath?: string;
    clamdscanPath?: string;
    preference?: string;
  };
  classifier?: Record<string, unknown> | null;
  replacements?: Record<string, string> | null;
  hashTokens?: boolean;
  strictIDNDetection?: boolean;
  // Enhanced stemming options
  enableAdvancedStemming?: boolean;
  stemmingEncoding?: CharacterEncoding;
  stemmingFallbackToOriginal?: boolean;
  // Path detection controls
  filePathDetection?: "off" | "benign" | "strict";
  allowlistedPaths?: RegExp[];
}

interface ScanResult {
  isSpam: boolean;
  message: string;
  results: {
    classification: {
      category: string;
      probability: number;
    };
    phishing: Array<{
      type: string;
      url: string;
      description: string;
      details?: Record<string, unknown>;
    }>;
    executables: Array<{
      type: string;
      filename: string;
      extension?: string;
      detectedType?: string;
      description: string;
    }>;
    macros: Array<{
      type: string;
      subtype: string;
      filename?: string;
      description: string;
    }>;
    arbitrary: Array<{
      type: string;
      description: string;
    }>;
    viruses: Array<{
      filename: string;
      virus: string[];
      type: string;
    }>;
    patterns: Array<{
      type: string;
      subtype?: string;
      count?: number;
      path?: string;
      description: string;
    }>;
    idnHomographAttack: {
      detected: boolean;
      domains: Array<{
        domain: string;
        originalUrl: string;
        normalizedUrl: string;
        riskScore: number;
        riskFactors: string[];
        recommendations: string[];
        confidence: number;
      }>;
      riskScore: number;
      details: string[];
    };
  };
  links: string[];
  tokens: string[];
  mail: {
    text?: string;
    html?: string;
    subject?: string;
    from?: Record<string, unknown>;
    to?: Record<string, unknown>[];
    attachments?: Array<{
      filename?: string;
      content?: Buffer;
    }>;
    headerLines?: Array<{
      line?: string;
    }>;
    headers?: Record<string, unknown>;
  };
  metrics?: {
    totalTime: number;
    classificationTime: number;
    phishingTime: number;
    executableTime: number;
    macroTime: number;
    virusTime: number;
    patternTime: number;
    idnTime: number;
    memoryUsage: NodeJS.MemoryUsage;
  };
}

interface PerformanceMetrics {
  totalScans: number;
  averageTime: number;
  lastScanTime: number;
}

class SpamScanner {
  private config: SpamScannerOptions;
  private classifier: NaiveBayes | null;
  private clamscan: ClamScan | null;
  private replacements: Map<string, string>;
  private metrics: PerformanceMetrics;
  private idnDetector: any;

  constructor(options: SpamScannerOptions = {}) {
    this.config = {
      // Enhanced configuration options
      enableMacroDetection: true,
      enableMalwareUrlCheck: true,
      enablePerformanceMetrics: false,
      enableCaching: true,
      timeout: 30_000,
      supportedLanguages: ["en"],
      enableMixedLanguageDetection: false,
      enableAdvancedPatternRecognition: true,

      // Enhanced stemming options
      enableAdvancedStemming: false,
      stemmingEncoding: CharacterEncoding.UTF_8,
      stemmingFallbackToOriginal: true,

      // Existing options
      debug: false,
      logger: console,
      clamscan: {
        removeInfected: false,
        quarantineInfected: false,
        scanLog: null,
        debugMode: false,
        fileList: null,
        scanRecursively: true,
        clamscanPath: "/usr/bin/clamscan",
        clamdscanPath: "/usr/bin/clamdscan",
        preference: "clamdscan",
      },
      classifier: null,
      replacements: null,
      // Defaults for new options
      filePathDetection: "strict",
      allowlistedPaths: [W3C_DTD_REGEX],
      ...options,
    };

    // Async loading of replacements and classifier
    this.classifier = null;
    this.clamscan = null;

    // Initialize replacements as empty Map
    this.replacements = new Map();

    // Performance metrics
    this.metrics = {
      totalScans: 0,
      averageTime: 0,
      lastScanTime: 0,
    };

    // Bind methods
    autoBind(this);
  }

  async initializeClassifier(): Promise<void> {
    if (this.classifier) {
      return;
    }

    try {
      if (this.config.classifier) {
        this.classifier = new NaiveBayes(this.config.classifier);
      } else {
        const classifierData = await getClassifier();
        this.classifier = new NaiveBayes(classifierData);
      }

      // Custom tokenizer - we handle tokenization ourselves
      this.classifier.tokenizer = (tokens: string | string[]) => {
        if (typeof tokens === "string") {
          return tokens.split(WHITESPACE_REGEX);
        }

        return Array.isArray(tokens) ? tokens : [];
      };
    } catch (error) {
      debug("Failed to initialize classifier:", error);
      // Create a fallback classifier
      this.classifier = new NaiveBayes();
    }
  }

  // Initialize replacements
  async initializeReplacements(): Promise<void> {
    if (this.replacements && this.replacements.size > 0) {
      return;
    }

    try {
      const replacements = this.config.replacements
        ? this.config.replacements
        : await getReplacements();

      // Ensure replacements is a Map
      if (replacements instanceof Map) {
        this.replacements = replacements;
      } else if (typeof replacements === "object" && replacements !== null) {
        this.replacements = new Map(Object.entries(replacements));
      } else {
        throw new Error("Invalid replacements format");
      }
    } catch (error) {
      debug("Failed to initialize replacements:", error);
      // Generate fallback replacements
      this.replacements = new Map();

      // Add some basic replacements
      const basicReplacements: Record<string, string> = {
        u: "you",
        ur: "your",
        r: "are",
        n: "and",
        "w/": "with",
        b4: "before",
        2: "to",
        4: "for",
      };

      for (const [word, replacement] of Object.entries(basicReplacements)) {
        this.replacements.set(word, replacement);
      }
    }
  }

  // Enhanced virus scanning with timeout protection
  private async getVirusResults(mail: {
    attachments?: Array<{ filename?: string; content?: Buffer }>;
  }): Promise<Array<{ filename: string; virus: string[]; type: string }>> {
    if (!this.clamscan) {
      try {
        const clamscanConfig = this.config.clamscan;
        if (clamscanConfig) {
          this.clamscan = (await new ClamScan().init(clamscanConfig)) as any;
        }
      } catch (error) {
        debug("ClamScan initialization failed:", error);
        return [];
      }
    }

    const results: Array<{ filename: string; virus: string[]; type: string }> = [];
    const attachments = mail.attachments || [];

    for (const attachment of attachments) {
      try {
        if (attachment.content && isBuffer(attachment.content)) {
          const scanResult = await Promise.race([
            (this.clamscan as any).scanBuffer(attachment.content),
            new Promise<never>((_, rejectHandler) =>
              setTimeout(() => rejectHandler(new Error("Virus scan timeout")), this.config.timeout),
            ),
          ]);

          if (scanResult.isInfected) {
            results.push({
              filename: attachment.filename || "unknown",
              virus: scanResult.viruses || ["Unknown virus"],
              type: "virus",
            });
          }
        }
      } catch (error) {
        debug("Virus scan error:", error);
      }
    }

    return results;
  }

  // Macro detection (DONE)
  private async getMacroResults(mail: {
    text?: string;
    html?: string;
    headerLines?: Array<{ line?: string }>;
    attachments?: Array<{ filename?: string }>;
  }): Promise<Array<{ type: string; subtype: string; filename?: string; description: string }>> {
    const results: Array<{
      type: string;
      subtype: string;
      filename?: string;
      description: string;
    }> = [];
    const attachments = mail.attachments || [];
    const textContent = mail.text || "";
    const htmlContent = mail.html || "";

    // VBA Macro detection
    const vbaPatterns = [
      /sub\s+\w+\s*\(/gi,
      /function\s+\w+\s*\(/gi,
      /dim\s+\w+\s+as\s+\w+/gi,
      /application\.run/gi,
      /shell\s*\(/gi,
    ];

    // PowerShell detection
    const powershellPatterns = [
      /powershell/gi,
      /invoke-expression/gi,
      /iex\s*\(/gi,
      /start-process/gi,
      /new-object\s+system\./gi,
    ];

    // JavaScript macro detection
    const jsPatterns = [
      /eval\s*\(/gi,
      /document\.write/gi,
      /activexobject/gi,
      /wscript\./gi,
      /new\s+activexobject/gi,
    ];

    // Batch file detection
    const batchPatterns = [/@echo\s+off/gi, /cmd\s*\/c/gi, /start\s+\/b/gi, /for\s+\/[lrf]/gi];

    // Get content from text, html, and header lines
    let allContent = textContent + " " + htmlContent;

    // Also check header lines for content (like macro code in raw emails)
    if (mail.headerLines && Array.isArray(mail.headerLines)) {
      for (const headerLine of mail.headerLines) {
        if (headerLine.line) {
          allContent += " " + headerLine.line;
        }
      }
    }

    // Check for VBA macros
    for (const pattern of vbaPatterns) {
      if (pattern.test(allContent)) {
        results.push({
          type: "macro",
          subtype: "vba",
          description: "VBA macro detected",
        });
        break;
      }
    }

    // Check for PowerShell
    for (const pattern of powershellPatterns) {
      if (pattern.test(allContent)) {
        results.push({
          type: "macro",
          subtype: "powershell",
          description: "PowerShell script detected",
        });
        break;
      }
    }

    // Check for JavaScript macros
    for (const pattern of jsPatterns) {
      if (pattern.test(allContent)) {
        results.push({
          type: "macro",
          subtype: "javascript",
          description: "JavaScript macro detected",
        });
        break;
      }
    }

    // Check for batch files
    for (const pattern of batchPatterns) {
      if (pattern.test(allContent)) {
        results.push({
          type: "macro",
          subtype: "batch",
          description: "Batch script detected",
        });
        break;
      }
    }

    // Check attachments for macro content
    for (const attachment of attachments) {
      if (attachment.filename) {
        const extension = fileExtension(attachment.filename).toLowerCase();
        const macroExtensions = ["vbs", "vba", "ps1", "bat", "cmd", "scr", "pif"];

        if (macroExtensions.includes(extension)) {
          results.push({
            type: "macro",
            subtype: "attachment",
            filename: attachment.filename,
            description: `Macro file attachment detected: ${extension}`,
          });
        }
      }
    }

    return results;
  }

  // File path detection (DONE)
  private async getFilePathResults(mail: {
    text?: string;
    html?: string;
  }): Promise<Array<{ type: string; path: string; description: string }>> {
    const results: Array<{ type: string; path: string; description: string }> = [];

    // Respect mode: off
    if (this.config.filePathDetection === "off") {
      return results;
    }
    const textContent = mail.text || "";
    const htmlContent = mail.html || "";
    // Strip DOCTYPE declarations and HTML comments to avoid false positives
    let allContent = (textContent + " " + htmlContent)
      .replace(DOCTYPE_REGEX, " ")
      .replace(HTML_COMMENT_REGEX, " ")
      .replace(TEMPLATE_HANDLEBARS_REGEX, " ")
      .replace(TEMPLATE_TWIG_REGEX, " ")
      .replace(TEMPLATE_EJS_REGEX, " ");

    // Blank out attribute values for safe attributes to avoid path-like content there
    allContent = allContent
      .replace(ATTR_VALUE_DOUBLE_QUOTE_REGEX, "$1$2")
      .replace(ATTR_VALUE_SINGLE_QUOTE_REGEX, "$1$2")
      .replace(NULL_UNDEFINED_REGEX, " ");

    const seen = new Set<string>();
    const collected: Array<{ path: string; suspicious: boolean }> = [];

    for (const pattern of FILE_PATH_PATTERNS) {
      const matches = allContent.match(pattern);
      if (matches) {
        for (const match of matches) {
          // Skip HTML tags and common false positives
          if (this.isValidFilePath(match)) {
            const normalized = match.trim();
            if (seen.has(normalized)) {
              continue;
            }
            seen.add(normalized);

            const suspicious = this.isSuspiciousPath(normalized, allContent);
            collected.push({ path: normalized, suspicious });
          }
        }
      }
    }

    // Cap to avoid over-weighting
    const MAX_PATHS = 10;
    for (const item of collected.slice(0, MAX_PATHS)) {
      const subtype = item.suspicious ? "suspicious" : "benign";
      const description = item.suspicious
        ? "Suspicious file path detected"
        : "Benign file path detected";

      // Respect mode: benign (report but not suspicious)
      if (this.config.filePathDetection === "benign") {
        results.push({
          type: "file_path",
          path: item.path,
          description: "Benign file path detected",
        });
        continue;
      }

      // Respect allowlist
      if (this.isAllowlisted(item.path)) {
        continue;
      }

      // In strict mode, only push suspicious; benigns are ignored
      if (subtype === "suspicious") {
        results.push({ type: "file_path", path: item.path, description });
      }
    }

    return results;
  }

  // Check if a path is a valid file path (not HTML tag or false positive)
  private isValidFilePath(path: string): boolean {
    // Skip HTML tags (common HTML elements)
    const htmlTags = [
      "a",
      "abbr",
      "address",
      "area",
      "article",
      "aside",
      "audio",
      "b",
      "base",
      "bdi",
      "bdo",
      "blockquote",
      "body",
      "br",
      "button",
      "canvas",
      "caption",
      "cite",
      "code",
      "col",
      "colgroup",
      "data",
      "datalist",
      "dd",
      "del",
      "details",
      "dfn",
      "dialog",
      "div",
      "dl",
      "dt",
      "em",
      "embed",
      "fieldset",
      "figcaption",
      "figure",
      "footer",
      "form",
      "h1",
      "h2",
      "h3",
      "h4",
      "h5",
      "h6",
      "head",
      "header",
      "hr",
      "html",
      "i",
      "iframe",
      "img",
      "input",
      "ins",
      "kbd",
      "label",
      "legend",
      "li",
      "link",
      "main",
      "map",
      "mark",
      "meta",
      "meter",
      "nav",
      "noscript",
      "object",
      "ol",
      "optgroup",
      "option",
      "output",
      "p",
      "param",
      "picture",
      "pre",
      "progress",
      "q",
      "rp",
      "rt",
      "ruby",
      "s",
      "samp",
      "script",
      "section",
      "select",
      "small",
      "source",
      "span",
      "strong",
      "style",
      "sub",
      "summary",
      "sup",
      "svg",
      "table",
      "tbody",
      "td",
      "template",
      "textarea",
      "tfoot",
      "th",
      "thead",
      "time",
      "title",
      "tr",
      "track",
      "u",
      "ul",
      "var",
      "video",
      "wbr",
    ];

    // Check if it's an HTML tag
    const tagMatch = path.match(HTML_TAG_REGEX);
    if (tagMatch?.[1] && htmlTags.includes(tagMatch[1].toLowerCase())) {
      return false;
    }

    // Skip very short paths that are likely false positives
    if (path.length < 4) {
      return false;
    }

    // Ignore obvious URL-like or protocol strings
    if (LEADING_DOUBLE_SLASH_REGEX.test(path)) {
      return false;
    }
    if (HTTP_URL_REGEX.test(path)) {
      return false;
    }

    // Ignore React streaming/server-rendering markers like <!--$--> becoming "/$--"
    if (REACT_STREAM_MARKER_REGEX.test(path)) {
      return false;
    }

    // Whitelist known safe W3C DTD references
    if (W3C_DTD_REGEX.test(path)) {
      return false;
    }

    // Skip paths that are just domain names
    if (DOMAIN_PATH_REGEX.test(path)) {
      return false;
    }

    // Must have a file extension or be a directory with multiple segments
    if (!(path.includes(".") || path.includes("/"))) {
      return false;
    }

    return true;
  }

  // Evaluate suspiciousness based on sensitive dirs, dangerous extensions, and repetition
  private isSuspiciousPath(path: string, context: string): boolean {
    // Allowlist first
    if (this.isAllowlisted(path)) {
      return false;
    }

    const lower = path.toLowerCase();
    for (const dir of SENSITIVE_DIRS) {
      if (lower.includes(dir.toLowerCase())) {
        return true;
      }
    }

    // biome-ignore lint/performance/useTopLevelRegex: <>
    const lastSegment = lower.split(/[\\/]/).pop() || "";
    const ext = lastSegment.includes(".") ? lastSegment.split(".").pop() || "" : "";
    if (ext && DANGEROUS_EXTS.has(ext)) {
      return true;
    }

    // If the same path appears multiple times, treat as more suspicious
    const occurrences = (
      context.match(new RegExp(path.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g")) || []
    ).length;
    if (occurrences >= 2) {
      return true;
    }

    return false;
  }

  private isAllowlisted(path: string): boolean {
    const list = this.config.allowlistedPaths || [];
    for (const re of list) {
      try {
        if (re.test(path)) {
          return true;
        }
        // biome-ignore lint/suspicious/noEmptyBlockStatements: <>
      } catch {}
    }
    return false;
  }

  // Optimize URL parsing with timeout protection (DONE)
  private async optimizeUrlParsing(url: string): Promise<string> {
    try {
      return await Promise.race([
        normalizeUrl(url, {
          stripHash: true,
          stripWWW: false,
          removeQueryParameters: false,
        }),
        new Promise<string>((_, rejectHandler) =>
          setTimeout(() => rejectHandler(new Error("URL parsing timeout")), 5000),
        ),
      ]);
    } catch {
      return url;
    }
  }

  // Enhanced Cloudflare blocked domain checking with timeout
  private async isCloudflareBlocked(hostname: string): Promise<boolean> {
    try {
      const response = await Promise.race([
        superagent
          .get(`https://1.1.1.3/dns-query?name=${hostname}&type=A`)
          .set("Accept", "application/dns-json")
          .timeout(5000),
        new Promise<never>((_, rejectHandler) =>
          setTimeout(() => rejectHandler(new Error("DNS timeout")), 5000),
        ),
      ]);

      return (response as any).body?.Status === 3; // NXDOMAIN indicates blocked
    } catch {
      return false;
    }
  }

  // Extract URLs from all possible sources
  private extractAllUrls(
    mail: { text?: string; html?: string; headerLines?: Array<{ line?: string }> },
    originalSource: string | Buffer,
  ): string[] {
    let allText = "";

    // Add mail text and html
    allText += (mail.text || "") + " " + (mail.html || "");

    // Add header lines content
    if (mail.headerLines && Array.isArray(mail.headerLines)) {
      for (const headerLine of mail.headerLines) {
        if (headerLine.line) {
          allText += " " + headerLine.line;
        }
      }
    }

    // Also check original source if it's a simple string
    if (typeof originalSource === "string") {
      allText += " " + originalSource;
    }

    return this.getUrls(allText);
  }

  // Enhanced URL extraction with improved parsing
  private getUrls(string_: string): string[] {
    if (!isSANB(string_)) {
      return [];
    }

    const urls: string[] = [];
    const matches = string_.match(URL_PATTERN);

    if (matches) {
      for (let url of matches) {
        // Clean up URL ending characters
        url = url.replace(URL_ENDING_RESERVED_CHARS, "");

        // Validate and normalize URL
        try {
          const normalizedUrl = normalizeUrl(url, {
            stripHash: false,
            stripWWW: false,
          });
          urls.push(normalizedUrl);
        } catch {
          // If normalization fails, keep original
          urls.push(url);
        }
      }
    }

    return [...new Set(urls)]; // Remove duplicates
  }

  // Enhanced tokenization with language detection
  private async getTokens(string_: string, locale = "en", isHtml = false): Promise<string[]> {
    if (!isSANB(string_)) {
      return [];
    }

    let text = string_;

    // Strip HTML if needed
    if (isHtml) {
      text = striptags(text);
    }

    // Detect language if not provided or if mixed language detection is enabled
    if (!locale || this.config.enableMixedLanguageDetection) {
      try {
        const detected = lande(text);
        if (detected && detected.length > 0) {
          locale = detected[0]?.[0] ?? "en";
        }
      } catch {
        locale ||= "en";
      }
    }

    // Normalize locale
    locale = this.parseLocale(locale);

    // Convert full-width to half-width characters
    text = converter.toHalfWidth(text);

    // Expand contractions
    try {
      text = expandContractions(text);
    } catch {
      // If expansion fails, continue with original text
    }

    // Tokenize based on language
    let tokens: string[] = [];

    if (locale === "ja") {
      // Japanese tokenization
      try {
        tokens = chineseTokenizer.tokenize(text);
      } catch {
        tokens = text.split(GENERIC_TOKENIZER);
      }
    } else if (locale === "zh") {
      // Chinese tokenization
      try {
        tokens = chineseTokenizer.tokenize(text);
      } catch {
        tokens = text.split(GENERIC_TOKENIZER);
      }
    } else {
      // Generic tokenization for other languages
      tokens = text.split(GENERIC_TOKENIZER);
    }

    // Process tokens
    let processedTokens = tokens
      .map((token: string) => token.toLowerCase().trim())
      .filter((token: string) => token.length > 0 && token.length <= 50); // Reasonable length limit

    // Remove stopwords
    const stopwordSet = stopwordsMap.get(locale) || stopwordsMap.get("en");
    if (stopwordSet) {
      processedTokens = processedTokens.filter((token: string) => !stopwordSet.has(token));
    }

    // Enhanced stemming using the full node-snowball capabilities
    try {
      if (isLanguageSupported(locale)) {
        const useAdvancedStemming =
          this.config.enableAdvancedStemming && this.isAdvancedStemmingSupported(locale);
        processedTokens = await this.getEnhancedStemming(processedTokens, locale, {
          encoding: this.config.stemmingEncoding || CharacterEncoding.UTF_8,
          fallbackToOriginal: this.config.stemmingFallbackToOriginal ?? true,
          useAdvancedStemming,
        });
      }
    } catch (error) {
      debug(`Enhanced stemming failed for locale '${locale}':`, error);
      // Fallback to original tokens if stemming fails
    }

    // Apply token hashing if enabled
    if (this.config.hashTokens) {
      processedTokens = processedTokens.map(
        (token: string) => createHash("sha256").update(token).digest("hex").slice(0, 16), // Use first 16 characters for efficiency
      );
    }

    return processedTokens;
  }

  // Enhanced stemming method using the full node-snowball capabilities
  private async getEnhancedStemming(
    tokens: string[],
    locale: string,
    options: {
      encoding?: CharacterEncoding;
      fallbackToOriginal?: boolean;
      useAdvancedStemming?: boolean;
    } = {},
  ): Promise<string[]> {
    if (!tokens || tokens.length === 0) {
      return [];
    }

    const {
      encoding = CharacterEncoding.UTF_8,
      fallbackToOriginal = true,
      useAdvancedStemming = false,
    } = options;

    try {
      if (!isLanguageSupported(locale)) {
        debug(`Language '${locale}' not supported for stemming, returning original tokens`);
        return tokens;
      }

      if (useAdvancedStemming) {
        // Use the advanced stemming with full configuration
        const result = stemwordAdvanced(tokens, {
          language: locale,
          encoding,
          fallbackToOriginal,
        });
        return Array.isArray(result) ? result : [result];
      } else {
        // Use the standard stemming (backward compatible)
        const result = snowball.stemword(tokens, locale, encoding);
        return Array.isArray(result) ? result : [result];
      }
    } catch (error) {
      debug(`Stemming failed for locale '${locale}':`, error);
      return fallbackToOriginal ? tokens : [];
    }
  }

  // Enhanced text preprocessing with pattern recognition
  private async preprocessText(string_: string): Promise<string> {
    if (!isSANB(string_)) {
      return "";
    }

    let text = string_;

    // Apply replacements if available
    if (this.replacements) {
      for (const [original, replacement] of this.replacements) {
        text = text.replaceAll(new RegExp(escapeStringRegexp(original), "gi"), replacement);
      }
    }

    // Advanced pattern recognition (DONE)
    if (this.config.enableAdvancedPatternRecognition) {
      // Replace patterns with normalized tokens
      const firstDatePattern = DATE_PATTERNS[0];
      if (firstDatePattern) {
        text = text.replaceAll(firstDatePattern, " DATE_PATTERN ");
      }
      text = text.replace(CREDIT_CARD_PATTERN, " CREDIT_CARD ");
      text = text.replace(PHONE_PATTERN, " PHONE_NUMBER ");
      text = text.replace(EMAIL_PATTERN, " EMAIL_ADDRESS ");
      text = text.replace(IP_PATTERN, " IP_ADDRESS ");
      text = text.replace(URL_PATTERN, " URL_LINK ");
      text = text.replace(BITCOIN_PATTERN, " BITCOIN_ADDRESS ");
      text = text.replace(MAC_PATTERN, " MAC_ADDRESS ");
      text = text.replace(HEX_COLOR_PATTERN, " HEX_COLOR ");
      text = text.replace(FLOATING_POINT_PATTERN, " FLOATING_POINT ");
    }

    // Remove standalone null/undefined tokens to prevent noise
    text = text.replace(NULL_UNDEFINED_REGEX, " ");

    return text;
  }

  // Main scan method - enhanced with performance metrics and new features
  async scan(source: string | Buffer): Promise<ScanResult> {
    const startTime = Date.now();

    try {
      // Initialize components if needed
      await this.initializeClassifier();
      await this.initializeReplacements();

      // Get tokens and mail from source
      const { tokens, mail } = await this.getTokensAndMailFromSource(source);

      // Run all detecti		// Run all detection methods in parallel
      const [
        classification,
        phishing,
        executables,
        macros,
        arbitrary,
        viruses,
        patterns,
        idnHomographAttack,
      ] = await Promise.all([
        this.getClassification(tokens),
        this.getPhishingResults(mail),
        this.getExecutableResults(mail),
        this.getMacroResults(mail),
        this.getArbitraryResults(mail),
        this.getVirusResults(mail),
        this.getPatternResults(mail),
        this.getIDNHomographResults(mail),
      ]);

      // Determine if spam
      // In benign mode, file_path findings shouldn't cause spam
      const effectivePatterns =
        this.config.filePathDetection === "benign"
          ? patterns.filter((p) => p.type !== "file_path")
          : patterns;

      const isSpam =
        classification.category === "spam" ||
        phishing.length > 0 ||
        executables.length > 0 ||
        macros.length > 0 ||
        arbitrary.length > 0 ||
        viruses.length > 0 ||
        effectivePatterns.length > 0 ||
        idnHomographAttack?.detected;

      // Generate message
      let message = "Ham";
      if (isSpam) {
        const reasons: string[] = [];
        if (classification.category === "spam") {
          reasons.push("spam classification");
        }

        if (phishing.length > 0) {
          reasons.push("phishing detected");
        }

        if (executables.length > 0) {
          reasons.push("executable content");
        }

        if (macros.length > 0) {
          reasons.push("macro detected");
        }

        if (arbitrary.length > 0) {
          reasons.push("arbitrary patterns");
        }

        if (viruses.length > 0) {
          reasons.push("virus detected");
        }

        if (effectivePatterns.length > 0) {
          reasons.push("suspicious patterns");
        }

        if (idnHomographAttack?.detected) {
          reasons.push("IDN homograph attack");
        }

        message = `Spam (${arrayJoinConjunction(reasons)})`;
      }

      const endTime = Date.now();
      const processingTime = endTime - startTime;

      // Update metrics
      this.metrics.totalScans++;
      this.metrics.lastScanTime = processingTime;
      this.metrics.averageTime =
        (this.metrics.averageTime * (this.metrics.totalScans - 1) + processingTime) /
        this.metrics.totalScans;

      const result = {
        isSpam,
        message,
        results: {
          classification,
          phishing,
          executables,
          macros,
          arbitrary,
          viruses,
          patterns,
          idnHomographAttack,
        },
        links: this.extractAllUrls(mail, source),
        tokens,
        mail,
      };

      // Add performance metrics if enabled
      if (this.config.enablePerformanceMetrics) {
        (result as any).metrics = {
          totalTime: processingTime,
          classificationTime: 0, // Would need to measure individually
          phishingTime: 0,
          executableTime: 0,
          macroTime: 0,
          virusTime: 0,
          patternTime: 0,
          idnTime: 0,
          memoryUsage: memoryUsage(),
        };
      }

      return result;
    } catch (error) {
      debug("Scan error:", error);
      throw error;
    }
  }

  // Get pattern recognition results
  private async getPatternResults(mail: {
    text?: string;
    html?: string;
  }): Promise<
    Array<{ type: string; subtype?: string; count?: number; path?: string; description: string }>
  > {
    const results: Array<{
      type: string;
      subtype?: string;
      count?: number;
      path?: string;
      description: string;
    }> = [];
    const textContent = mail.text || "";
    const htmlContent = mail.html || "";
    const allContent = textContent + " " + htmlContent;

    // Date pattern detection
    for (const pattern of DATE_PATTERNS) {
      const matches = allContent.match(pattern);
      if (matches && matches.length > 5) {
        // Suspicious if many dates
        results.push({
          type: "pattern",
          subtype: "date_spam",
          count: matches.length,
          description: "Excessive date patterns detected",
        });
      }
    }

    // File path detection
    const filePathResults = await this.getFilePathResults(mail);
    results.push(...filePathResults);

    return results;
  }

  // Enhanced mail parsing with better error handling
  private async getTokensAndMailFromSource(source: string | Buffer): Promise<{
    tokens: string[];
    mail: {
      text?: string;
      html?: string;
      subject?: string;
      from?: Record<string, unknown>;
      to?: Record<string, unknown>[];
      attachments?: Array<{ filename?: string; content?: Buffer }>;
      headerLines?: Array<{ line?: string }>;
      headers?: Record<string, unknown>;
    };
  }> {
    let mail: any;

    if (typeof source === "string" && existsSync(source)) {
      // File path
      source = readFileSync(source);
    }

    if (isBuffer(source)) {
      source = source.toString();
    }

    if (!source || typeof source !== "string") {
      source = "";
    }

    try {
      mail = await simpleParser(source);
    } catch (error) {
      debug("Mail parsing error:", error);
      // Create minimal mail object
      mail = {
        text: source,
        html: "",
        subject: "",
        from: {},
        to: [],
        attachments: [],
      } as any;
    }

    // Preprocess text content
    const textContent = await this.preprocessText(mail.text || "");
    const htmlContent = await this.preprocessText(striptags(mail.html || ""));
    const subjectContent = await this.preprocessText(mail.subject || "");

    // Get tokens from all content
    const allContent = [textContent, htmlContent, subjectContent].join(" ");
    const tokens = await this.getTokens(allContent, "en");

    return { tokens, mail };
  }

  // Enhanced classification with better error handling
  private async getClassification(
    tokens: string[],
  ): Promise<{ category: string; probability: number }> {
    if (!this.classifier) {
      await this.initializeClassifier();
    }

    try {
      // Join tokens into a string for the classifier
      const text = Array.isArray(tokens) ? tokens.join(" ") : String(tokens);
      const result = this.classifier?.categorize(text);

      return {
        category: result || "ham",
        probability: 0.5, // Default probability
      };
    } catch (error) {
      debug("Classification error:", error);
      return {
        category: "ham",
        probability: 0.5,
      };
    }
  }

  // Enhanced phishing detection
  private async getPhishingResults(mail: {
    text?: string;
    html?: string;
  }): Promise<
    Array<{ type: string; url: string; description: string; details?: Record<string, unknown> }>
  > {
    const results: Array<{
      type: string;
      url: string;
      description: string;
      details?: Record<string, unknown>;
    }> = [];
    const links = this.getUrls(mail.text || "");

    for (const url of links) {
      try {
        const normalizedUrl = await this.optimizeUrlParsing(url);
        const parsed = new URL(normalizedUrl);

        // Check for suspicious domains
        const isBlocked = await this.isCloudflareBlocked(parsed.hostname);
        if (isBlocked) {
          results.push({
            type: "phishing",
            url: normalizedUrl,
            description: "Blocked by security filters",
          });
        }

        // Enhanced IDN homograph attack detection
        const idnDetector = await this.getIDNDetector();
        if (idnDetector && parsed.hostname) {
          const context = {
            emailContent: mail.text || mail.html || "",
            displayText: url === normalizedUrl ? null : url,
            senderReputation: 0.5, // Default neutral reputation
          };

          const idnAnalysis = idnDetector.detectHomographAttack(parsed.hostname, context);

          if (idnAnalysis.riskScore > 0.6) {
            results.push({
              type: "phishing",
              url: normalizedUrl,
              description: `IDN homograph attack detected (risk: ${(idnAnalysis.riskScore * 100).toFixed(1)}%)`,
              details: {
                riskFactors: idnAnalysis.riskFactors,
                recommendations: idnAnalysis.recommendations,
                confidence: idnAnalysis.confidence,
              },
            });
          } else if (idnAnalysis.riskScore > 0.3) {
            results.push({
              type: "suspicious",
              url: normalizedUrl,
              description: `Suspicious IDN domain (risk: ${(idnAnalysis.riskScore * 100).toFixed(1)}%)`,
              details: {
                riskFactors: idnAnalysis.riskFactors,
                recommendations: idnAnalysis.recommendations,
              },
            });
          }
        }
      } catch (error) {
        debug("Phishing check error:", error);
      }
    }

    return results;
  }

  // Enhanced executable detection
  private async getExecutableResults(mail: {
    attachments?: Array<{ filename?: string; content?: Buffer }>;
  }): Promise<
    Array<{
      type: string;
      filename: string;
      extension?: string;
      detectedType?: string;
      description: string;
    }>
  > {
    const results: Array<{
      type: string;
      filename: string;
      extension?: string;
      detectedType?: string;
      description: string;
    }> = [];
    const attachments = mail.attachments || [];

    for (const attachment of attachments) {
      if (attachment.filename) {
        const extension = fileExtension(attachment.filename).toLowerCase();

        if (EXECUTABLES.has(extension)) {
          results.push({
            type: "executable",
            filename: attachment.filename,
            extension,
            description: "Executable file attachment",
          });
        }
      }

      // Check file content for executable signatures
      if (attachment.content && isBuffer(attachment.content)) {
        try {
          const fileType = await fileTypeFromBuffer(attachment.content);
          if (fileType && EXECUTABLES.has(fileType.ext)) {
            results.push({
              type: "executable",
              filename: attachment.filename || "unknown",
              detectedType: fileType.ext,
              description: "Executable content detected",
            });
          }
        } catch (error) {
          debug("File type detection error:", error);
        }
      }
    }

    return results;
  }

  // Arbitrary results (GTUBE, etc.)
  private async getArbitraryResults(mail: {
    text?: string;
    html?: string;
    headerLines?: Array<{ line?: string }>;
  }): Promise<Array<{ type: string; description: string }>> {
    const results: Array<{ type: string; description: string }> = [];

    // Get content from text, html, and header lines
    let content = (mail.text || "") + (mail.html || "");

    // Also check header lines for content (like GTUBE in raw emails)
    if (mail.headerLines && Array.isArray(mail.headerLines)) {
      for (const headerLine of mail.headerLines) {
        if (headerLine.line) {
          content += " " + headerLine.line;
        }
      }
    }

    // GTUBE test
    if (content.includes("XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X")) {
      results.push({
        type: "arbitrary",
        description: "GTUBE spam test pattern detected",
      });
    }

    return results;
  }

  // Parse and normalize locale
  private parseLocale(locale: string): string {
    if (!locale || typeof locale !== "string") {
      return "en";
    }

    // Handle locale codes like 'en-US' -> 'en'
    const normalized = locale.toLowerCase().split("-")[0] ?? "en";
    // Map some common variations
    const localeMap: Record<string, string> = {
      nb: "no", // Norwegian Bokmål
      nn: "no", // Norwegian Nynorsk
      "zh-cn": "zh",
      "zh-tw": "zh",
    };
    return localeMap[normalized] || normalized;
  }

  // Get IDN homograph attack results
  private async getIDNHomographResults(mail: {
    text?: string;
    html?: string;
    headers?: Record<string, unknown>;
  }): Promise<{
    detected: boolean;
    domains: Array<{
      domain: string;
      originalUrl: string;
      normalizedUrl: string;
      riskScore: number;
      riskFactors: string[];
      recommendations: string[];
      confidence: number;
    }>;
    riskScore: number;
    details: string[];
  }> {
    const result: {
      detected: boolean;
      domains: Array<{
        domain: string;
        originalUrl: string;
        normalizedUrl: string;
        riskScore: number;
        riskFactors: string[];
        recommendations: string[];
        confidence: number;
      }>;
      riskScore: number;
      details: string[];
    } = {
      detected: false,
      domains: [],
      riskScore: 0,
      details: [],
    };

    try {
      const idnDetector = await this.getIDNDetector();
      if (!idnDetector) {
        return result;
      }

      // Extract URLs from email content
      const textContent = mail.text || "";
      const htmlContent = mail.html || "";
      const allContent = textContent + " " + htmlContent;
      const urls = this.getUrls(allContent);

      // Analyze each domain
      for (const url of urls) {
        try {
          const normalizedUrl = await this.optimizeUrlParsing(url);
          const parsed = new URL(normalizedUrl);
          const domain = parsed.hostname;

          if (!domain) {
            continue;
          }

          // Prepare context for analysis
          const context = {
            emailContent: allContent,
            displayText: url === normalizedUrl ? null : url,
            senderReputation: 0.5, // Default neutral reputation
            emailHeaders: mail.headers || {},
          };

          // Perform IDN analysis
          const analysis = idnDetector.detectHomographAttack(domain, context);

          if (analysis.riskScore > 0.3) {
            result.detected = true;
            result.domains = [
              ...result.domains,
              {
                domain,
                originalUrl: url,
                normalizedUrl,
                riskScore: analysis.riskScore,
                riskFactors: analysis.riskFactors,
                recommendations: analysis.recommendations,
                confidence: analysis.confidence,
              },
            ];

            // Update overall risk score to highest found
            result.riskScore = Math.max(result.riskScore, analysis.riskScore);
          }
        } catch (error) {
          debug("IDN analysis error for URL:", url, error);
        }
      }

      // Add summary details
      if (result.detected) {
        result.details = [...result.details, `Found ${result.domains.length} suspicious domain(s)`];
        result.details = [
          ...result.details,
          `Highest risk score: ${(result.riskScore * 100).toFixed(1)}%`,
        ];

        // Add specific risk factors
        const allRiskFactors = new Set<string>();
        for (const domain of result.domains) {
          for (const factor of domain.riskFactors) {
            allRiskFactors.add(factor);
          }
        }

        result.details = [...result.details, ...allRiskFactors];
      }
    } catch (error) {
      debug("IDN homograph detection error:", error);
    }

    return result;
  }

  // Get IDN detector instance
  private async getIDNDetector(): Promise<any> {
    if (!this.idnDetector) {
      try {
        const { default: EnhancedIDNDetector } = await import("./idn-detector.js");
        this.idnDetector = new EnhancedIDNDetector({
          strictMode: this.config.strictIDNDetection,
          enableWhitelist: true,
          enableBrandProtection: true,
          enableContextAnalysis: true,
        });
      } catch (error) {
        debug("Failed to load IDN detector:", error);
        return null;
      }
    }

    return this.idnDetector;
  }

  // Public methods for enhanced stemming capabilities

  /**
   * Get all supported languages for stemming
   * @returns Array of supported language codes
   */
  getSupportedStemmingLanguages(): string[] {
    return getSupportedAlgorithms();
  }

  /**
   * Check if a language supports stemming
   * @param locale - The language code to check
   * @returns True if the language is supported
   */
  isStemmingSupported(locale: string): boolean {
    return isLanguageSupported(locale);
  }

  /**
   * Check if a language supports advanced stemming features
   * @param locale - The language code to check
   * @returns True if advanced stemming is supported
   */
  isAdvancedStemmingSupported(locale: string): boolean {
    return (
      isLanguageSupported(locale) &&
      ![
        "ar",
        "hy",
        "eu",
        "ca",
        "da",
        "fi",
        "el",
        "hi",
        "hu",
        "ga",
        "lt",
        "ne",
        "ro",
        "sr",
        "ta",
        "tr",
        "yi",
      ].includes(locale)
    );
  }

  /**
   * Stem text using the enhanced node-snowball capabilities
   * @param text - The text to stem
   * @param locale - The language code
   * @param options - Stemming options
   * @returns Array of stemmed tokens
   */
  async stemText(
    text: string,
    locale = "en",
    options: {
      encoding?: CharacterEncoding;
      fallbackToOriginal?: boolean;
      useAdvancedStemming?: boolean;
    } = {},
  ): Promise<string[]> {
    if (!isSANB(text)) {
      return [];
    }

    // Tokenize the text first
    const tokens = await this.getTokens(text, locale);

    // Apply enhanced stemming
    return this.getEnhancedStemming(tokens, locale, {
      encoding: this.config.stemmingEncoding || CharacterEncoding.UTF_8,
      fallbackToOriginal: this.config.stemmingFallbackToOriginal ?? true,
      useAdvancedStemming: options.useAdvancedStemming ?? this.config.enableAdvancedStemming,
      ...options,
    });
  }

  // Hybrid language detection using both lande and franc
  // private async detectLanguageHybrid(text: string): Promise<string> {
  //   if (!text || typeof text !== "string" || text.length < 3) {
  //     return "en";
  //   }

  //   // Handle edge cases for non-linguistic content
  //   const cleanText = text.trim();
  //   if (!cleanText || /^[\d\s\W]+$/.test(cleanText)) {
  //     // Only numbers, spaces, and special characters
  //     return "en";
  //   }

  //   try {
  //     // Use lande for short text (< 50 chars), franc for longer text
  //     if (text.length < 50) {
  //       const landeResult = lande(text);
  //       if (landeResult && landeResult.length > 0) {
  //         // Convert lande's 3-letter codes to 2-letter codes
  //         const detected = landeResult[0]![0]!;
  //         const normalized = this.normalizeLanguageCode(detected);

  //         // Additional validation for short text detection
  //         if (this.isValidShortTextDetection(text, normalized)) {
  //           return normalized;
  //         }

  //         // Fallback to English for ambiguous short text
  //         return "en";
  //       }

  //       return "en";
  //     }

  //     // Import franc dynamically
  //     const francModule = await import("franc");
  //     const francResult = francModule.franc(text);
  //     if (francResult === "und") {
  //       // Fallback to lande if franc can't detect
  //       const landeResult = lande(text);
  //       if (landeResult && landeResult.length > 0) {
  //         return this.normalizeLanguageCode(landeResult[0]![0]!);
  //       }

  //       return "en";
  //     }

  //     return this.normalizeLanguageCode(francResult);
  //   } catch (error) {
  //     debug("Language detection error:", error);
  //     // Fallback to lande
  //     try {
  //       const landeResult = lande(text);
  //       if (landeResult && landeResult.length > 0) {
  //         return this.normalizeLanguageCode(landeResult[0]![0]!);
  //       }

  //       return "en";
  //     } catch {
  //       return "en";
  //     }
  //   }
  // }
}

// TODO: implement OhMyMsg function and use it as a main function
// TODO: SpamScanner should be included into OhMyMsg function
// TODO: migrate from class-based to functional approach
export default SpamScanner;
