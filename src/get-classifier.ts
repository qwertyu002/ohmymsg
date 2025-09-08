import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { debuglog } from "node:util";
import NaiveBayes from "@ladjs/naivebayes";

const debug = debuglog("spamscanner");

// ES module compatibility
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

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

// Create a fallback classifier
const createFallbackClassifier = (): ClassifierData => {
  const fallback = new NaiveBayes();
  // Train with minimal data to avoid empty classifier issues
  (fallback as any).learn("spam", "buy now free money click here");
  (fallback as any).learn("spam", "urgent action required verify account");
  (fallback as any).learn("ham", "hello how are you doing today");
  (fallback as any).learn("ham", "thank you for your email");
  return fallback.toJsonObject() as unknown as ClassifierData;
};

let classifier: ClassifierData = createFallbackClassifier();

// Try to load classifier from multiple possible locations
const possiblePaths = [
  // 1. In the package directory (for development)
  join(__dirname, "classifier.json"),
  // 2. In the current working directory (for user-provided classifier)
  "./classifier.json",
  // 3. In a classifiers subdirectory
  join(__dirname, "classifiers", "classifier.json"),
  // 4. In the user's home directory
  join(process.env.HOME || process.env.USERPROFILE || "", ".ohmymsg", "classifier.json"),
];

for (const path of possiblePaths) {
  try {
    if (existsSync(path)) {
      debug(`Loading classifier from: ${path}`);
      classifier = JSON.parse(readFileSync(path, "utf8"));
      break;
    }
  } catch (error) {
    debug(`Failed to load classifier from ${path}:`, error);
  }
}

// If no classifier was loaded, warn the user
if (classifier === createFallbackClassifier()) {
  debug(
    "No classifier.json found. Using fallback classifier. For better spam detection, please provide a trained classifier.",
  );
  debug(
    "You can download a pre-trained classifier from: https://github.com/reliverse/ohmymsg/blob/main/classifier.json",
  );
  debug("Place it in one of these locations:");
  for (const path of possiblePaths) {
    debug(`  - ${path}`);
  }
}

export default classifier;
