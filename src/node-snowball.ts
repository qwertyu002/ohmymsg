import natural from "natural";

// Character encoding enum (from node-stemmer)
// biome-ignore lint/style/noEnum: <>
export enum CharacterEncoding {
  UTF_8 = "UTF_8",
  ISO_8859_1 = "ISO_8859_1",
  ISO_8859_2 = "ISO_8859_2",
  KOI8_R = "KOI8_R",
}

// Error class (from node-stemmer)
export class UnavailableAlgorithmError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnavailableAlgorithmError";
  }
}

// Type definitions
export type SupportedLanguage =
  | "en"
  | "english"
  | "es"
  | "spanish"
  | "fr"
  | "french"
  | "de"
  | "german"
  | "it"
  | "italian"
  | "pt"
  | "portuguese"
  | "nl"
  | "dutch"
  | "uk"
  | "ukrainian"
  | "no"
  | "norwegian"
  | "sv"
  | "swedish"
  | "fa"
  | "persian"
  | "ja"
  | "japanese"
  | "id"
  | "indonesian"
  | "ar"
  | "arabic"
  | "hy"
  | "armenian"
  | "eu"
  | "basque"
  | "ca"
  | "catalan"
  | "da"
  | "danish"
  | "fi"
  | "finnish"
  | "el"
  | "greek"
  | "hi"
  | "hindi"
  | "hu"
  | "hungarian"
  | "ga"
  | "irish"
  | "lt"
  | "lithuanian"
  | "ne"
  | "nepali"
  | "ro"
  | "romanian"
  | "sr"
  | "serbian"
  | "ta"
  | "tamil"
  | "tr"
  | "turkish"
  | "yi"
  | "yiddish"
  | "porter";

export type StemmerInput = string | string[];

// Stemmer configuration interface
export interface StemmerConfig {
  language: string;
  encoding?: CharacterEncoding;
  fallbackToOriginal?: boolean;
}

// Type for stemmer functions
interface StemmerFunction {
  stem(word: string): string;
}

// Language mapping to natural.js stemmers
const LANGUAGE_MAP: Record<string, StemmerFunction> = {
  // English
  en: (natural as any).PorterStemmer,
  english: (natural as any).PorterStemmer,

  // Spanish
  es: (natural as any).PorterStemmerEs,
  spanish: (natural as any).PorterStemmerEs,

  // French
  fr: (natural as any).PorterStemmerFr,
  french: (natural as any).PorterStemmerFr,

  // German
  de: (natural as any).PorterStemmerDe,
  german: (natural as any).PorterStemmerDe,

  // Italian
  it: (natural as any).PorterStemmerIt,
  italian: (natural as any).PorterStemmerIt,

  // Portuguese
  pt: (natural as any).PorterStemmerPt,
  portuguese: (natural as any).PorterStemmerPt,

  // Dutch
  nl: (natural as any).PorterStemmerNl,
  dutch: (natural as any).PorterStemmerNl,

  // Ukrainian
  uk: (natural as any).PorterStemmerUk,
  ukrainian: (natural as any).PorterStemmerUk,

  // Norwegian
  no: (natural as any).PorterStemmerNo,
  norwegian: (natural as any).PorterStemmerNo,

  // Swedish
  sv: (natural as any).PorterStemmerSv,
  swedish: (natural as any).PorterStemmerSv,

  // Persian
  fa: (natural as any).PorterStemmerFa,
  persian: (natural as any).PorterStemmerFa,

  // Japanese
  ja: (natural as any).StemmerJa,
  japanese: (natural as any).StemmerJa,

  // Indonesian
  id: (natural as any).StemmerId,
  indonesian: (natural as any).StemmerId,

  // Additional languages (fallback to English stemmer for unsupported languages)
  ar: (natural as any).PorterStemmer, // Arabic - fallback
  arabic: (natural as any).PorterStemmer,
  hy: (natural as any).PorterStemmer, // Armenian - fallback
  armenian: (natural as any).PorterStemmer,
  eu: (natural as any).PorterStemmer, // Basque - fallback
  basque: (natural as any).PorterStemmer,
  ca: (natural as any).PorterStemmer, // Catalan - fallback
  catalan: (natural as any).PorterStemmer,
  da: (natural as any).PorterStemmer, // Danish - fallback
  danish: (natural as any).PorterStemmer,
  fi: (natural as any).PorterStemmer, // Finnish - fallback
  finnish: (natural as any).PorterStemmer,
  el: (natural as any).PorterStemmer, // Greek - fallback
  greek: (natural as any).PorterStemmer,
  hi: (natural as any).PorterStemmer, // Hindi - fallback
  hindi: (natural as any).PorterStemmer,
  hu: (natural as any).PorterStemmer, // Hungarian - fallback
  hungarian: (natural as any).PorterStemmer,
  ga: (natural as any).PorterStemmer, // Irish - fallback
  irish: (natural as any).PorterStemmer,
  lt: (natural as any).PorterStemmer, // Lithuanian - fallback
  lithuanian: (natural as any).PorterStemmer,
  ne: (natural as any).PorterStemmer, // Nepali - fallback
  nepali: (natural as any).PorterStemmer,
  ro: (natural as any).PorterStemmer, // Romanian - fallback
  romanian: (natural as any).PorterStemmer,
  sr: (natural as any).PorterStemmer, // Serbian - fallback
  serbian: (natural as any).PorterStemmer,
  ta: (natural as any).PorterStemmer, // Tamil - fallback
  tamil: (natural as any).PorterStemmer,
  tr: (natural as any).PorterStemmer, // Turkish - fallback
  turkish: (natural as any).PorterStemmer,
  yi: (natural as any).PorterStemmer, // Yiddish - fallback
  yiddish: (natural as any).PorterStemmer,
  porter: (natural as any).PorterStemmer, // Porter algorithm
};

/**
 * Get the appropriate stemmer for the given language
 * @param language - The language code or name
 * @returns The stemmer instance or null if not supported
 */
function getStemmer(language: string): StemmerFunction | null {
  const normalizedLang = language.toLowerCase();
  return LANGUAGE_MAP[normalizedLang] || null;
}

/**
 * Get list of supported algorithms/languages
 * @returns Array of supported language codes
 */
export function getSupportedAlgorithms(): string[] {
  return Object.keys(LANGUAGE_MAP).filter(
    (key) => (!key.includes("fallback") && key.length <= 2) || key === "porter",
  );
}

/**
 * Check if a language is supported
 * @param language - The language code or name
 * @returns True if the language is supported
 */
export function isLanguageSupported(language: string): boolean {
  const normalizedLang = language.toLowerCase();
  return normalizedLang in LANGUAGE_MAP;
}

/**
 * Stem a single word using the specified language
 * @param word - The word to stem
 * @param language - The language code (default: 'english')
 * @param encoding - Character encoding (ignored for natural.js compatibility)
 * @param fallbackToOriginal - Whether to return original word if stemming fails
 * @returns The stemmed word
 */
function stemWord(
  word: string,
  language = "english",
  _encoding?: CharacterEncoding,
  fallbackToOriginal = true,
): string {
  if (!word || typeof word !== "string") {
    return word;
  }

  const stemmer = getStemmer(language);
  if (!stemmer) {
    if (fallbackToOriginal) {
      return word;
    }
    throw new UnavailableAlgorithmError(`Language '${language}' is not supported`);
  }

  try {
    return stemmer.stem(word);
  } catch (error) {
    if (fallbackToOriginal) {
      return word;
    }
    throw error;
  }
}

/**
 * Enhanced Stemmer class (inspired by node-stemmer)
 */
export class Stemmer {
  private language: string;
  private encoding: CharacterEncoding;
  private fallbackToOriginal: boolean;

  constructor(
    algorithm: string,
    charenc: CharacterEncoding = CharacterEncoding.UTF_8,
    fallbackToOriginal = true,
  ) {
    this.language = algorithm;
    this.encoding = charenc;
    this.fallbackToOriginal = fallbackToOriginal;

    if (!isLanguageSupported(algorithm)) {
      throw new UnavailableAlgorithmError(`Algorithm '${algorithm}' is not available`);
    }
  }

  /**
   * Get list of supported algorithms
   * @returns Array of supported algorithm names
   */
  static algorithms(): string[] {
    return getSupportedAlgorithms();
  }

  /**
   * Stem a single word
   * @param word - The word to stem
   * @returns The stemmed word
   */
  stemWord(word: string): string {
    return stemWord(word, this.language, this.encoding, this.fallbackToOriginal);
  }

  /**
   * Stem multiple words
   * @param words - Array of words to stem
   * @returns Array of stemmed words
   */
  stemWords(words: string[]): string[] {
    return words.map((word) => this.stemWord(word));
  }
}

/**
 * Main stemword function that matches the original node-snowball API
 * @param input - Single word or array of words to stem
 * @param language - The language code (default: 'english')
 * @param encoding - Encoding parameter (ignored, kept for compatibility)
 * @returns Stemmed word(s)
 */
export function stemword(
  input: StemmerInput,
  language = "english",
  encoding?: string,
): string | string[] {
  // Handle array input
  if (Array.isArray(input)) {
    return input.map((word) => stemWord(word, language, encoding as CharacterEncoding));
  }

  // Handle single string input
  return stemWord(input, language, encoding as CharacterEncoding);
}

/**
 * Enhanced stemword function with more options
 * @param input - Single word or array of words to stem
 * @param config - Stemmer configuration
 * @returns Stemmed word(s)
 */
export function stemwordAdvanced(input: StemmerInput, config: StemmerConfig): string | string[] {
  const { language, encoding, fallbackToOriginal = true } = config;

  // Handle array input
  if (Array.isArray(input)) {
    return input.map((word) => stemWord(word, language, encoding, fallbackToOriginal));
  }

  // Handle single string input
  return stemWord(input, language, encoding, fallbackToOriginal);
}

// Default export for compatibility with the original API
export default {
  stemword,
  stemwordAdvanced,
  Stemmer,
  CharacterEncoding,
  UnavailableAlgorithmError,
  getSupportedAlgorithms,
  isLanguageSupported,
};

// Some parts of this file are based on and significantly adapt:
// - https://github.com/hthetiot/node-snowball/commit/29f5ad0 – MIT © 2014 Harold Thetiot
// - https://github.com/amaccis/node-stemmer/tree/12927a5 – MIT © 2022 Andrea Maccis
