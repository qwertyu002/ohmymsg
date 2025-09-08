/** biome-ignore-all lint/style/useExportType: <stemword> */

// Type declarations for external modules without type definitions

declare module "@ladjs/naivebayes" {
  interface NaiveBayesOptions {
    tokenizer?: (text: string | string[]) => string[];
    vocabulary?: Record<string, number>;
    vocabularySize?: number;
    minimumFrequency?: number;
    maximumVocabularySize?: number;
    minimumLength?: number;
    maximumLength?: number;
    caseSensitive?: boolean;
    stripHtml?: boolean;
    stripPunctuation?: boolean;
    stripNumbers?: boolean;
    stripStopWords?: boolean;
    stripAccents?: boolean;
    stripDiacritics?: boolean;
    stripEmojis?: boolean;
    stripUrls?: boolean;
    stripEmails?: boolean;
    stripPhoneNumbers?: boolean;
    stripCreditCards?: boolean;
    stripIps?: boolean;
    stripMacs?: boolean;
    stripBitcoins?: boolean;
    stripHexColors?: boolean;
    stripFloatingPoints?: boolean;
    stripDates?: boolean;
    stripFilePaths?: boolean;
    stripArbitrary?: boolean;
    stripMacros?: boolean;
    stripExecutables?: boolean;
    stripViruses?: boolean;
    stripPhishing?: boolean;
    stripIdnHomograph?: boolean;
    stripPatterns?: boolean;
    stripMixedLanguage?: boolean;
    stripAdvancedPatterns?: boolean;
    stripPerformanceMetrics?: boolean;
    stripCaching?: boolean;
    stripTimeout?: boolean;
    stripSupportedLanguages?: boolean;
    stripDebug?: boolean;
    stripLogger?: boolean;
    stripClamscan?: boolean;
    stripClassifier?: boolean;
    stripReplacements?: boolean;
    stripHashTokens?: boolean;
    stripStrictIdnDetection?: boolean;
    stripEnableMacroDetection?: boolean;
    stripEnableMalwareUrlCheck?: boolean;
    stripEnablePerformanceMetrics?: boolean;
    stripEnableCaching?: boolean;
    stripEnableMixedLanguageDetection?: boolean;
    stripEnableAdvancedPatternRecognition?: boolean;
  }

  class NaiveBayes {
    constructor(options?: NaiveBayesOptions | Record<string, unknown>);
    tokenizer: (text: string | string[]) => string[];
    categorize(text: string): string;
    toJsonObject(): Record<string, unknown>;
  }

  export = NaiveBayes;
}

declare module "array-join-conjunction" {
  function arrayJoinConjunction(array: string[]): string;
  export = arrayJoinConjunction;
}

declare module "ascii-fullwidth-halfwidth-convert" {
  class AFHConvert {
    constructor();
    toHalfWidth(text: string): string;
    toFullWidth(text: string): string;
  }
  export = AFHConvert;
}

declare module "bitcoin-regex" {
  interface BitcoinRegexOptions {
    exact?: boolean;
  }
  function bitcoinRegex(options?: BitcoinRegexOptions): RegExp;
  export = bitcoinRegex;
}

declare module "credit-card-regex" {
  interface CreditCardRegexOptions {
    exact?: boolean;
  }
  function creditCardRegex(options?: CreditCardRegexOptions): RegExp;
  export = creditCardRegex;
}

declare module "file-extension" {
  function fileExtension(filename: string): string;
  export = fileExtension;
}

declare module "floating-point-regex" {
  const floatingPointRegex: RegExp;
  export = floatingPointRegex;
}

declare module "hexa-color-regex" {
  interface HexaColorRegexOptions {
    exact?: boolean;
  }
  function hexaColorRegex(options?: HexaColorRegexOptions): RegExp;
  export = hexaColorRegex;
}

declare module "is-string-and-not-blank" {
  function isSANB(value: unknown): value is string;
  export = isSANB;
}

declare module "mac-regex" {
  interface MacRegexOptions {
    exact?: boolean;
  }
  function macRegex(options?: MacRegexOptions): RegExp;
  export = macRegex;
}

declare module "phone-regex" {
  interface PhoneRegexOptions {
    exact?: boolean;
  }
  function phoneRegex(options?: PhoneRegexOptions): RegExp;
  export = phoneRegex;
}

declare module "clamscan" {
  interface ClamScanOptions {
    removeInfected?: boolean;
    quarantineInfected?: boolean;
    scanLog?: string | null;
    debugMode?: boolean;
    fileList?: string | null;
    scanRecursively?: boolean;
    clamscanPath?: string;
    clamdscanPath?: string;
    preference?: string;
  }

  interface ScanResult {
    isInfected: boolean;
    viruses?: string[];
  }

  class ClamScan {
    constructor();
    init(options: ClamScanOptions): Promise<NodeClam>;
  }

  interface NodeClam {
    scanBuffer(buffer: Buffer): Promise<ScanResult>;
  }

  export = ClamScan;
}

declare module "stopword" {
  interface Stopword {
    [key: string]: string[];
  }
  const stopword: Stopword;
  export = stopword;
}

declare module "natural" {
  interface Natural {
    stopwords: string[];
  }
  const natural: Natural;
  export = natural;
}

declare module "lande" {
  function lande(text: string): [string, number][];
  export = lande;
}

declare module "franc" {
  function franc(text: string): string;
  export = franc;
}
