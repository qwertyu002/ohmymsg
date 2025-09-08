/**
 * Enhanced IDN Homograph Attack Detection
 * Based on comprehensive research and best practices
 */

import { createHash } from "node:crypto";

// Unicode confusable character mappings (subset for demonstration)
const CONFUSABLE_CHARS = new Map([
  // Cyrillic to Latin confusables
  ["а", "a"],
  ["е", "e"],
  ["о", "o"],
  ["р", "p"],
  ["с", "c"],
  ["х", "x"],
  ["у", "y"],
  ["А", "A"],
  ["В", "B"],
  ["Е", "E"],
  ["К", "K"],
  ["М", "M"],
  ["Н", "H"],
  ["О", "O"],
  ["Р", "P"],
  ["С", "C"],
  ["Т", "T"],
  ["Х", "X"],
  ["У", "Y"],

  // Greek to Latin confusables
  ["α", "a"],
  ["ο", "o"],
  ["ρ", "p"],
  ["υ", "u"],
  ["ν", "v"],
  ["ι", "i"],
  ["Α", "A"],
  ["Β", "B"],
  ["Ε", "E"],
  ["Ζ", "Z"],
  ["Η", "H"],
  ["Ι", "I"],
  ["Κ", "K"],
  ["Μ", "M"],
  ["Ν", "N"],
  ["Ο", "O"],
  ["Ρ", "P"],
  ["Τ", "T"],
  ["Υ", "Y"],

  // Mathematical symbols
  ["𝐚", "a"],
  ["𝐛", "b"],
  ["𝐜", "c"],
  ["𝐝", "d"],
  ["𝐞", "e"],
  ["𝟎", "0"],
  ["𝟏", "1"],
  ["𝟐", "2"],
  ["𝟑", "3"],
  ["𝟒", "4"],

  // Other common confusables
  ["ℯ", "e"],
  ["ℊ", "g"],
  ["ℎ", "h"],
  ["ℓ", "l"],
  ["ℴ", "o"],
  ["ℯ", "e"],
  ["ⅰ", "i"],
  ["ⅱ", "ii"],
  ["ⅲ", "iii"],
  ["ⅳ", "iv"],
  ["ⅴ", "v"],
]);

// Known legitimate international domains (whitelist approach)
const LEGITIMATE_IDN_DOMAINS = new Set([
  "xn--fsq.xn--0zwm56d", // 中国
  "xn--fiqs8s", // 中国
  "xn--fiqz9s", // 中囯
  "xn--j6w193g", // 香港
  "xn--55qx5d", // 公司
  "xn--io0a7i", // 网络
  // Add more legitimate domains as needed
]);

// Regex patterns
// biome-ignore lint/suspicious/noControlCharactersInRegex: <>
const NON_ASCII_REGEX = /[^\u0000-\u007F]/;
const TLD_REGEX = /\.(com|org|net|edu|gov)$/;
const SUSPICIOUS_PATTERNS = [
  /urgent/i,
  /verify.*account/i,
  /suspended/i,
  /click.*here/i,
  /limited.*time/i,
  /act.*now/i,
  /confirm.*identity/i,
];

// Popular brand domains for comparison
const POPULAR_BRANDS = [
  "google",
  "facebook",
  "amazon",
  "apple",
  "microsoft",
  "twitter",
  "instagram",
  "linkedin",
  "youtube",
  "netflix",
  "paypal",
  "ebay",
  "yahoo",
  "adobe",
  "salesforce",
  "oracle",
  "ibm",
  "cisco",
  "intel",
  "nvidia",
  "tesla",
  "citibank",
  "bankofamerica",
  "wellsfargo",
  "chase",
  "americanexpress",
];

// Type definitions
interface IDNDetectorOptions {
  strictMode?: boolean;
  enableWhitelist?: boolean;
  enableBrandProtection?: boolean;
  enableContextAnalysis?: boolean;
  maxSimilarityThreshold?: number;
  minDomainAge?: number;
}

interface IDNAnalysis {
  domain: string;
  isIDN: boolean;
  riskScore: number;
  riskFactors: string[];
  recommendations: string[];
  confidence: number;
}

interface IDNContext {
  emailContent?: string;
  displayText?: string;
  senderReputation?: number;
  emailHeaders?: Record<string, unknown>;
}

interface AnalysisResult {
  score: number;
  factors: string[];
}

class EnhancedIDNDetector {
  private options: IDNDetectorOptions;
  private cache: Map<string, IDNAnalysis>;

  constructor(options: IDNDetectorOptions = {}) {
    this.options = {
      strictMode: false,
      enableWhitelist: true,
      enableBrandProtection: true,
      enableContextAnalysis: true,
      maxSimilarityThreshold: 0.8,
      minDomainAge: 30, // Days
      ...options,
    };

    this.cache = new Map();
  }

  /**
   * Main detection method with comprehensive analysis
   */
  detectHomographAttack(domain: string, context: IDNContext = {}): IDNAnalysis {
    const cacheKey = this.getCacheKey(domain, context);
    if (this.cache.has(cacheKey)) {
      const cached = this.cache.get(cacheKey);
      if (cached) {
        return cached;
      }
    }

    const result = this.analyzeComprehensive(domain, context);
    this.cache.set(cacheKey, result);
    return result;
  }

  /**
   * Comprehensive analysis combining multiple detection methods
   */
  private analyzeComprehensive(domain: string, context: IDNContext): IDNAnalysis {
    const analysis: IDNAnalysis = {
      domain,
      isIDN: this.isIDNDomain(domain),
      riskScore: 0,
      riskFactors: [] as string[],
      recommendations: [] as string[],
      confidence: 0,
    };

    // Skip analysis for whitelisted domains
    if (this.options.enableWhitelist && this.isWhitelisted(domain)) {
      analysis.riskScore = 0;
      analysis.confidence = 1;
      analysis.recommendations = ["Domain is whitelisted as legitimate"];
      return analysis;
    }

    // Basic IDN detection
    if (analysis.isIDN) {
      analysis.riskScore += 0.3;
      analysis.riskFactors = [...analysis.riskFactors, "Contains non-ASCII characters"];
    }

    // Confusable character analysis
    const confusableAnalysis = this.analyzeConfusableCharacters(domain);
    analysis.riskScore += confusableAnalysis.score;
    analysis.riskFactors = [...analysis.riskFactors, ...confusableAnalysis.factors];

    // Brand similarity analysis
    if (this.options.enableBrandProtection) {
      const brandAnalysis = this.analyzeBrandSimilarity(domain);
      analysis.riskScore += brandAnalysis.score;
      analysis.riskFactors = [...analysis.riskFactors, ...brandAnalysis.factors];
    }

    // Script mixing analysis
    const scriptAnalysis = this.analyzeScriptMixing(domain);
    analysis.riskScore += scriptAnalysis.score;
    analysis.riskFactors = [...analysis.riskFactors, ...scriptAnalysis.factors];

    // Context analysis
    if (this.options.enableContextAnalysis && context) {
      const contextAnalysis = this.analyzeContext(domain, context);
      analysis.riskScore += contextAnalysis.score;
      analysis.riskFactors = [...analysis.riskFactors, ...contextAnalysis.factors];
    }

    // Punycode analysis
    if (domain.includes("xn--")) {
      const punycodeAnalysis = this.analyzePunycode(domain);
      analysis.riskScore += punycodeAnalysis.score;
      analysis.riskFactors = [...analysis.riskFactors, ...punycodeAnalysis.factors];
    }

    // Calculate final confidence and recommendations
    analysis.confidence = Math.min(analysis.riskScore, 1);
    analysis.recommendations = this.generateRecommendations(analysis);

    return analysis;
  }

  /**
   * Detect if domain contains IDN characters
   */
  private isIDNDomain(domain: string): boolean {
    return domain.includes("xn--") || NON_ASCII_REGEX.test(domain);
  }

  /**
   * Check if domain is in whitelist
   */
  private isWhitelisted(domain: string): boolean {
    const normalized = domain.toLowerCase();
    return LEGITIMATE_IDN_DOMAINS.has(normalized);
  }

  /**
   * Analyze confusable characters
   */
  private analyzeConfusableCharacters(domain: string): AnalysisResult {
    const analysis: AnalysisResult = { score: 0, factors: [] };
    let confusableCount = 0;
    let totalChars = 0;

    for (const char of domain) {
      totalChars++;
      if (CONFUSABLE_CHARS.has(char)) {
        confusableCount++;
        analysis.factors.push(`Confusable character: ${char} → ${CONFUSABLE_CHARS.get(char)}`);
      }
    }

    if (confusableCount > 0) {
      const ratio = confusableCount / totalChars;
      analysis.score = Math.min(ratio * 0.8, 0.6);
      analysis.factors.push(`${confusableCount}/${totalChars} characters are confusable`);
    }

    return analysis;
  }

  /**
   * Analyze similarity to popular brands
   */
  private analyzeBrandSimilarity(domain: string): AnalysisResult {
    const analysis: AnalysisResult = { score: 0, factors: [] };
    const cleanDomain = this.normalizeDomain(domain);

    for (const brand of POPULAR_BRANDS) {
      const similarity = this.calculateSimilarity(cleanDomain, brand);
      if (similarity > (this.options.maxSimilarityThreshold || 0.8)) {
        analysis.score = Math.max(analysis.score, similarity * 0.7);
        analysis.factors.push(`High similarity to ${brand}: ${(similarity * 100).toFixed(1)}%`);
      }
    }

    return analysis;
  }

  /**
   * Analyze script mixing patterns
   */
  private analyzeScriptMixing(domain: string): AnalysisResult {
    const analysis: AnalysisResult = { score: 0, factors: [] };
    const scripts = this.detectScripts(domain);

    if (scripts.size > 1) {
      // Mixed scripts can be suspicious
      const scriptList = [...scripts].join(", ");
      analysis.factors.push(`Mixed scripts detected: ${scriptList}`);

      // Higher risk for certain combinations
      if (scripts.has("Latin") && (scripts.has("Cyrillic") || scripts.has("Greek"))) {
        analysis.score += 0.4;
        analysis.factors.push("Suspicious Latin/Cyrillic or Latin/Greek mixing");
      } else {
        analysis.score += 0.2;
      }
    }

    return analysis;
  }

  /**
   * Analyze context (email headers, content, etc.)
   */
  private analyzeContext(domain: string, context: IDNContext): AnalysisResult {
    const analysis: AnalysisResult = { score: 0, factors: [] };

    // Check if display text differs from actual domain
    if (context.displayText && context.displayText !== domain) {
      analysis.score += 0.3;
      analysis.factors.push("Display text differs from actual domain");
    }

    // Check sender reputation
    if (context.senderReputation && context.senderReputation < 0.5) {
      analysis.score += 0.2;
      analysis.factors.push("Low sender reputation");
    }

    // Check for suspicious email patterns
    if (context.emailContent) {
      for (const pattern of SUSPICIOUS_PATTERNS) {
        if (pattern.test(context.emailContent)) {
          analysis.score += 0.1;
          analysis.factors.push(`Suspicious email pattern: ${pattern.source}`);
        }
      }
    }

    return analysis;
  }

  /**
   * Analyze punycode domains
   */
  private analyzePunycode(domain: string): AnalysisResult {
    const analysis: AnalysisResult = { score: 0, factors: [] };

    try {
      // Decode punycode to see actual characters
      const decoded = this.decodePunycode(domain);
      analysis.factors.push(`Punycode decoded: ${decoded}`);

      // Check if decoded version looks suspicious
      const decodedAnalysis = this.analyzeConfusableCharacters(decoded);
      analysis.score += decodedAnalysis.score * 0.8;
      analysis.factors.push(...decodedAnalysis.factors);
    } catch {
      analysis.score += 0.2;
      analysis.factors.push("Invalid punycode encoding");
    }

    return analysis;
  }

  /**
   * Normalize domain for comparison
   */
  private normalizeDomain(domain: string): string {
    let normalized = domain.toLowerCase();

    // Replace confusable characters with their Latin equivalents
    for (const [confusable, latin] of CONFUSABLE_CHARS) {
      normalized = normalized.replaceAll(confusable, latin);
    }

    // Remove common TLD for comparison
    normalized = normalized.replace(TLD_REGEX, "");

    return normalized;
  }

  /**
   * Calculate string similarity using Levenshtein distance
   */
  private calculateSimilarity(string1: string, string2: string): number {
    const length1 = string1.length;
    const length2 = string2.length;

    if (length1 === 0) return length2 === 0 ? 1 : 0;
    if (length2 === 0) return 0;

    const matrix: number[][] = new Array(length2 + 1)
      .fill(0)
      .map(() => new Array(length1 + 1).fill(0));

    for (let i = 0; i <= length2; i++) {
      const row = matrix[i];
      if (row) {
        row[0] = i;
      }
    }

    for (let j = 0; j <= length1; j++) {
      const firstRow = matrix[0];
      if (firstRow) {
        firstRow[j] = j;
      }
    }

    for (let i = 1; i <= length2; i++) {
      for (let j = 1; j <= length1; j++) {
        if (string2.charAt(i - 1) === string1.charAt(j - 1)) {
          const currentRow = matrix[i];
          const prevRow = matrix[i - 1];
          if (currentRow && prevRow) {
            currentRow[j] = prevRow[j - 1] ?? 0;
          }
        } else {
          const currentRow = matrix[i];
          const prevRow = matrix[i - 1];
          if (currentRow && prevRow) {
            currentRow[j] = Math.min(
              (prevRow[j - 1] ?? 0) + 1,
              (currentRow[j - 1] ?? 0) + 1,
              (prevRow[j] ?? 0) + 1,
            );
          }
        }
      }
    }

    const maxLength = Math.max(length1, length2);
    const finalRow = matrix[length2];
    const finalValue = finalRow?.[length1] ?? 0;
    return (maxLength - finalValue) / maxLength;
  }

  /**
   * Detect scripts used in domain
   */
  private detectScripts(domain: string): Set<string> {
    const scripts = new Set<string>();

    for (const char of domain) {
      const code = char.codePointAt(0);

      if (code !== undefined) {
        if ((code >= 0x00_41 && code <= 0x00_5a) || (code >= 0x00_61 && code <= 0x00_7a)) {
          scripts.add("Latin");
        } else if (code >= 0x04_00 && code <= 0x04_ff) {
          scripts.add("Cyrillic");
        } else if (code >= 0x03_70 && code <= 0x03_ff) {
          scripts.add("Greek");
        } else if (code >= 0x4e_00 && code <= 0x9f_ff) {
          scripts.add("CJK");
        } else if (code >= 0x05_90 && code <= 0x05_ff) {
          scripts.add("Hebrew");
        } else if (code >= 0x06_00 && code <= 0x06_ff) {
          scripts.add("Arabic");
        }
      }
    }

    return scripts;
  }

  /**
   * Simple punycode decoder (basic implementation)
   */
  private decodePunycode(domain: string): string {
    // This is a simplified implementation
    // In production, use a proper punycode library
    try {
      const url = new URL(`http://${domain}`);
      return url.hostname;
    } catch {
      return domain;
    }
  }

  /**
   * Generate recommendations based on analysis
   */
  private generateRecommendations(analysis: IDNAnalysis): string[] {
    const recommendations: string[] = [];

    if (analysis.riskScore > 0.8) {
      recommendations.push("HIGH RISK: Likely homograph attack - block or quarantine");
    } else if (analysis.riskScore > 0.6) {
      recommendations.push("MEDIUM RISK: Suspicious domain - flag for review");
    } else if (analysis.riskScore > 0.3) {
      recommendations.push("LOW RISK: Monitor domain activity");
    } else {
      recommendations.push("SAFE: Domain appears legitimate");
    }

    if (analysis.isIDN) {
      recommendations.push("Consider displaying punycode representation to users");
    }

    if (analysis.riskFactors.some((f) => f.includes("brand"))) {
      recommendations.push("Verify domain authenticity through official channels");
    }

    return recommendations;
  }

  /**
   * Generate cache key
   */
  private getCacheKey(domain: string, context: IDNContext): string {
    const contextHash = createHash("md5").update(JSON.stringify(context)).digest("hex").slice(0, 8);
    return `${domain}:${contextHash}`;
  }
}

export default EnhancedIDNDetector;
