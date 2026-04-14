const maskedField = document.getElementById("masked");
const actualField = document.getElementById("actual");
const meterFill = document.getElementById("meterFill");
const meterValue = document.getElementById("meterValue");
const meterHint = document.getElementById("meterHint");
const meterTrack = document.querySelector(".meter__track");
const entropyScoreEl = document.getElementById("entropyScore");
const entropyBitsEl = document.getElementById("entropyBits");
const dictScoreEl = document.getElementById("dictScore");
const dictStatusEl = document.getElementById("dictStatus");
const patternScoreEl = document.getElementById("patternScore");
const patternStatusEl = document.getElementById("patternStatus");
const compositionScoreEl = document.getElementById("compositionScore");
const compositionStatusEl = document.getElementById("compositionStatus");

// very strong password example: j7&kQ!9mXp#!e

const categories = [
  { label: "Very Weak", min: 0, max: 20, hint: "Add length and variety to make it stronger." },
  { label: "Weak", min: 21, max: 40, hint: "Try adding numbers or symbols." },
  { label: "Fair", min: 41, max: 60, hint: "Mix upper and lower case letters." },
  { label: "Strong", min: 61, max: 80, hint: "Great progress. Add a few extra characters." },
  { label: "Very Strong", min: 81, max: 100, hint: "Excellent! This is tough to guess." }
];

const BREACH_CSV = "10millionPasswords.csv";
const MAX_BREACH = 200000;
const MAX_DICT = 80000;

const breachSet = new Set();
const dictionarySet = new Set();
let dataReady = false;

const keyboardRows = ["1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"];
const keyboardPositions = new Map();

keyboardRows.forEach((row, rowIndex) => {
  row.split("").forEach((char, colIndex) => {
    keyboardPositions.set(char, { row: rowIndex, col: colIndex });
  });
});

const knownWalks = [
  "qwerty",
  "asdfgh",
  "zxcvbn",
  "poiuyt",
  "lkjhg",
  "mnbvc",
  "123456",
  "654321",
  "1qaz",
  "2wsx",
  "3edc"
];

function analyzePassword(value) {
  if (value.length === 0) {
    return { score: 0, bits: 0, poolSize: 0 };
  }

  const hasLower = /[a-z]/.test(value);
  const hasUpper = /[A-Z]/.test(value);
  const hasNumber = /\d/.test(value);
  const hasSymbol = /[^A-Za-z0-9]/.test(value);

  let poolSize = 0;
  poolSize += hasLower ? 26 : 0;
  poolSize += hasUpper ? 26 : 0;
  poolSize += hasNumber ? 10 : 0;
  poolSize += hasSymbol ? 32 : 0;

  if (poolSize === 0) {
    return { score: 0, bits: 0, poolSize: 0 };
  }

  const entropyBits = value.length * Math.log2(poolSize);
  const scaled = ((entropyBits - 28) / (80 - 28)) * 30;
  const entropyScore = Math.max(0, Math.min(30, scaled));
  const roundedScore = Math.round(entropyScore);

  return { score: roundedScore, bits: entropyBits, poolSize };
}

let realValue = "";

function normalizeLeet(value) {
  const map = {
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "9": "g",
    "@": "a",
    "$": "s",
    "!": "i",
    "+": "t"
  };

  return value
    .toLowerCase()
    .split("")
    .map((char) => map[char] ?? char)
    .join("");
}

function stripCommonSuffix(value) {
  let result = value;
  let changed = true;

  while (changed) {
    const before = result;
    result = result.replace(/(\d{2,4}|[!?.]+)$/g, "");
    result = result.replace(/(1234|123|111|000)$/g, "");
    changed = result !== before;
  }

  return result;
}

function isKeyboardNeighbor(prevChar, nextChar) {
  const prev = keyboardPositions.get(prevChar);
  const next = keyboardPositions.get(nextChar);

  if (!prev || !next) {
    return false;
  }

  return Math.abs(prev.row - next.row) <= 1 && Math.abs(prev.col - next.col) <= 1;
}

function hasKeyboardWalk(value) {
  const lower = value.toLowerCase();

  if (knownWalks.some((walk) => lower.includes(walk))) {
    return true;
  }

  let run = 1;
  for (let i = 1; i < lower.length; i += 1) {
    if (isKeyboardNeighbor(lower[i - 1], lower[i])) {
      run += 1;
      if (run >= 4) {
        return true;
      }
    } else {
      run = 1;
    }
  }

  return false;
}

function hasSequence(value) {
  if (value.length < 3) {
    return false;
  }

  let run = 1;
  for (let i = 1; i < value.length; i += 1) {
    const diff = value.charCodeAt(i) - value.charCodeAt(i - 1);
    if (diff === 1 || diff === -1) {
      run += 1;
      if (run >= 3) {
        return true;
      }
    } else {
      run = 1;
    }
  }

  return false;
}

function hasRepeatedChars(value) {
  let run = 1;
  for (let i = 1; i < value.length; i += 1) {
    if (value[i] === value[i - 1]) {
      run += 1;
      if (run >= 3) {
        return true;
      }
    } else {
      run = 1;
    }
  }
  return false;
}

function hasRepeatedPattern(value) {
  const length = value.length;
  for (let size = 1; size <= Math.floor(length / 2); size += 1) {
    if (length % size !== 0) continue;
    const pattern = value.slice(0, size);
    if (pattern.repeat(length / size) === value) {
      return true;
    }
  }
  return false;
}

function hasDatePattern(value) {
  const patterns = [
    /\b(19|20)\d{2}\b/,
    /\b\d{4}[-/.]\d{1,2}[-/.]\d{1,2}\b/,
    /\b\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}\b/,
    /\b\d{8}\b/,
    /\b\d{6}\b/
  ];

  return patterns.some((regex) => regex.test(value));
}

function hasTrailingAppendage(value) {
  return (
    /^[a-zA-Z]{3,}[\d!@#$%^&*?]{1,4}$/.test(value) ||
    /^[\d!@#$%^&*?]{1,4}[a-zA-Z]{3,}$/.test(value)
  );
}

function isPalindrome(value) {
  const lower = value.toLowerCase();
  if (lower.length < 4) {
    return false;
  }
  return lower === lower.split("").reverse().join("");
}

function containsDictionarySubstring(value) {
  const lower = value.toLowerCase();
  const maxLen = Math.min(12, lower.length);

  for (let len = 4; len <= maxLen; len += 1) {
    for (let i = 0; i + len <= lower.length; i += 1) {
      const chunk = lower.slice(i, i + len);
      if (dictionarySet.has(chunk)) {
        return chunk;
      }
    }
  }

  return null;
}

function scoreDictionaryResistance(value) {
  if (!dataReady) {
    return { score: 25, status: "Breach list not loaded yet." };
  }

  if (value.length === 0) {
    return { score: 25, status: "Start typing to check for leaks." };
  }

  const lower = value.toLowerCase();

  if (breachSet.has(lower)) {
    return { score: 0, status: "Exact match in breach list." };
  }

  let score = 25;
  const flags = [];

  if (dictionarySet.has(lower)) {
    score -= 15;
    flags.push("Exact dictionary match");
  }

  const leet = normalizeLeet(lower);
  if (leet !== lower && dictionarySet.has(leet)) {
    score -= 10;
    flags.push("Leet substitutions detected");
  }

  const stripped = stripCommonSuffix(lower);
  if (stripped !== lower && dictionarySet.has(stripped)) {
    score -= 8;
    flags.push("Common suffix stripped");
  }

  const substring = containsDictionarySubstring(lower);
  if (substring) {
    score -= 6;
    flags.push(`Contains "${substring}"`);
  }

  return {
    score: Math.max(0, score),
    status: flags.length > 0 ? flags.join(" · ") : "No matches found."
  };
}

function scorePatternPredictability(value) {
  if (value.length === 0) {
    return { score: 20, status: "Start typing to analyze patterns." };
  }

  let score = 20;
  const flags = [];
  const lower = value.toLowerCase();

  if (hasKeyboardWalk(lower)) {
    score -= 6;
    flags.push("Keyboard walk");
  }

  if (hasSequence(value)) {
    score -= 5;
    flags.push("Sequential characters");
  }

  if (hasRepeatedChars(value)) {
    score -= 4;
    flags.push("Repeated characters");
  }

  if (hasRepeatedPattern(lower)) {
    score -= 4;
    flags.push("Repeating pattern");
  }

  if (dataReady) {
    const normalized = normalizeLeet(lower);
    if (normalized !== lower && dictionarySet.has(normalized)) {
      score -= 4;
      flags.push("Leet-only complexity");
    }
  }

  if (hasDatePattern(value)) {
    score -= 4;
    flags.push("Date pattern");
  }

  if (hasTrailingAppendage(value)) {
    score -= 3;
    flags.push("Predictable suffix/prefix");
  }

  if (isPalindrome(lower)) {
    score -= 3;
    flags.push("Palindrome");
  }

  return {
    score: Math.max(0, score),
    status: flags.length > 0 ? flags.join(" · ") : "No patterns detected."
  };
}

function getCharClass(char) {
  if (/[a-z]/.test(char)) return "lower";
  if (/[A-Z]/.test(char)) return "upper";
  if (/\d/.test(char)) return "digit";
  if (/[^A-Za-z0-9]/.test(char)) return "symbol";
  return "other";
}

function scoreCompositionDiversity(value) {
  if (value.length === 0) {
    return { score: 15, status: "Start typing to analyze composition." };
  }

  const length = value.length;
  const uniqueRatio = new Set(value).size / length;
  const uniqueScore = Math.max(0, Math.min(3, Math.round(uniqueRatio * 3)));

  const classes = { lower: 0, upper: 0, digit: 0, symbol: 0 };
  const classSeq = [];

  for (const char of value) {
    const cls = getCharClass(char);
    if (classes[cls] !== undefined) {
      classes[cls] += 1;
    }
    classSeq.push(cls);
  }

  const classPresence = ["lower", "upper", "digit", "symbol"].reduce(
    (count, cls) => count + (classes[cls] > 0 ? 1 : 0),
    0
  );

  let transitions = 0;
  for (let i = 1; i < classSeq.length; i += 1) {
    if (classSeq[i] !== classSeq[i - 1]) {
      transitions += 1;
    }
  }

  const maxTransitions = Math.max(1, length - 1);
  const interleaveScore = Math.max(0, Math.min(5, Math.round((transitions / maxTransitions) * 5)));

  const maxClassRatio = Math.max(...Object.values(classes)) / length;
  let dominancePenalty = 0;
  if (maxClassRatio > 0.85) {
    dominancePenalty = -3;
  } else if (maxClassRatio > 0.7) {
    dominancePenalty = -2;
  }

  let uncommonBonus = 0;
  if (/[^\x00-\x7F]/.test(value)) {
    uncommonBonus = 3;
  } else {
    const hasSpace = /\s/.test(value);
    const hasUnusualSymbol = /[~`^{}|<>]/.test(value);
    if (hasSpace || hasUnusualSymbol) {
      uncommonBonus = 2;
    }
  }

  const rawScore = uniqueScore + classPresence + interleaveScore + dominancePenalty + uncommonBonus;
  const normalized = Math.max(0, Math.min(15, Math.round((rawScore / 12) * 15)));

  const flags = [];
  if (uniqueRatio < 0.4) flags.push("Low variety");
  if (classPresence <= 2) flags.push("Limited classes");
  if (interleaveScore <= 2) flags.push("Clustered classes");
  if (dominancePenalty < 0) flags.push("One class dominates");
  if (uncommonBonus > 0) flags.push("Uncommon chars");

  return {
    score: normalized,
    status: flags.length > 0 ? flags.join(" · ") : "Balanced character mix."
  };
}

function applyMask() {
  maskedField.value = "*".repeat(realValue.length);
  actualField.value = realValue;

  const entropy = analyzePassword(realValue);
  const dictionary = scoreDictionaryResistance(realValue);
  const pattern = scorePatternPredictability(realValue);
  const composition = scoreCompositionDiversity(realValue);
  
  let totalScore =
    realValue.length === 0
      ? 0
      : Math.round(((entropy.score + dictionary.score + pattern.score + composition.score) / 90) * 100);

  // Critical Capping: Ensure a single failure point limits the final score
  if (realValue.length > 0) {
    // 1. Breach Cap: Known leaked passwords are fundamentally unsafe.
    if (dictionary.status === "Exact match in breach list.") {
      totalScore = Math.min(totalScore, 10);
    } 
    // 2. Dictionary Cap: Significant reliance on dictionary words or patterns.
    else if (dictionary.score <= 15) {
      totalScore = Math.min(totalScore, 30);
    }

    // 3. Entropy Caps: Low mathematical complexity.
    if (entropy.score < 8) {
      totalScore = Math.min(totalScore, 10);
    } else if (entropy.score < 15) {
      totalScore = Math.min(totalScore, 25);
    }
  }

  meterFill.style.width = `${totalScore}%`;
  meterTrack.setAttribute("aria-valuenow", `${totalScore}`);

  const bucket = categories.find((item) => totalScore >= item.min && totalScore <= item.max) ?? categories[0];
  meterValue.textContent = bucket.label;
  if (realValue.length === 0) {
    meterHint.textContent = "Start typing to see feedback.";
  } else if (dictionary.status === "Exact match in breach list.") {
    meterHint.textContent = "This password appears in a breach list. Choose a different one.";
  } else {
    meterHint.textContent = bucket.hint;
  }

  entropyScoreEl.textContent = `${entropy.score} / 30`;
  entropyBitsEl.textContent = entropy.bits.toFixed(1);
  dictScoreEl.textContent = `${dictionary.score} / 25`;
  dictStatusEl.textContent = dictionary.status;
  patternScoreEl.textContent = `${pattern.score} / 20`;
  patternStatusEl.textContent = pattern.status;
  compositionScoreEl.textContent = `${composition.score} / 15`;
  compositionStatusEl.textContent = composition.status;
}

maskedField.addEventListener("beforeinput", (event) => {
  const inputType = event.inputType;
  const data = event.data ?? "";
  const start = maskedField.selectionStart ?? realValue.length;
  const end = maskedField.selectionEnd ?? realValue.length;

  let nextValue = realValue;
  let caretShift = 0;

  if (inputType === "insertText" || inputType === "insertCompositionText") {
    nextValue = realValue.slice(0, start) + data + realValue.slice(end);
    caretShift = data.length;
  } else if (inputType === "insertFromPaste" || inputType === "insertReplacementText") {
    const pasteData = event.dataTransfer ? event.dataTransfer.getData("text") : data;
    nextValue = realValue.slice(0, start) + pasteData + realValue.slice(end);
    caretShift = pasteData.length;
  } else if (inputType === "deleteContentBackward") {
    if (start === end && start > 0) {
      nextValue = realValue.slice(0, start - 1) + realValue.slice(end);
      caretShift = -1;
    } else {
      nextValue = realValue.slice(0, start) + realValue.slice(end);
    }
  } else if (inputType === "deleteContentForward") {
    if (start === end && end < realValue.length) {
      nextValue = realValue.slice(0, start) + realValue.slice(end + 1);
    } else {
      nextValue = realValue.slice(0, start) + realValue.slice(end);
    }
  } else if (inputType === "deleteByCut") {
    nextValue = realValue.slice(0, start) + realValue.slice(end);
  } else {
    return;
  }

  event.preventDefault();
  realValue = nextValue;
  applyMask();

  const caretPos = Math.max(0, Math.min(realValue.length, start + caretShift));
  requestAnimationFrame(() => {
    maskedField.setSelectionRange(caretPos, caretPos);
  });
});

maskedField.addEventListener("focus", applyMask);

async function loadBreachData() {
  try {
    const response = await fetch(BREACH_CSV, { cache: "force-cache" });
    if (!response.ok) {
      throw new Error(`Failed to load breach data (${response.status}).`);
    }
    const text = await response.text();
    const lines = text.split(/\r?\n/);

    for (let i = 1; i < lines.length && breachSet.size < MAX_BREACH; i += 1) {
      const line = lines[i];
      if (!line) continue;

      const commaIndex = line.indexOf(",");
      if (commaIndex === -1) continue;

      const password = line.slice(commaIndex + 1).trim();
      if (!password) continue;

      const lower = password.toLowerCase();
      breachSet.add(lower);

      if (dictionarySet.size < MAX_DICT && /^[a-z]+$/i.test(password) && password.length >= 3) {
        dictionarySet.add(lower);
      }
    }

    if (breachSet.size === 0) {
      dictStatusEl.textContent = "Breach list empty. Serve the page with a local server.";
      dataReady = false;
    } else {
      dataReady = true;
    }
  } catch (error) {
    dictStatusEl.textContent = "Breach list unavailable. Serve the page with a local server.";
  }

  applyMask();
}

loadBreachData();
applyMask();
