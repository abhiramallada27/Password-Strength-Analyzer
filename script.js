/* ==========================================================================
   SentinelPass - Core Application Logic
   ========================================================================== */

document.addEventListener('DOMContentLoaded', () => {
  // Global States
  let activeTab = 'analyzer';
  let activeSubTab = 'sandbox';
  let historyList = loadHistory();
  let revealedHistoryIds = {};
  
  // Generator Settings
  const generatorSettings = {
    length: 16,
    uppercase: true,
    lowercase: true,
    numbers: true,
    symbols: true,
    excludeSimilar: false
  };

  // Common Passwords Dictionary
  const COMMON_PASSWORDS = new Set([
    '123456', 'password', '123456789', '12345678', '12345', 'qwerty', 
    'password123', 'letmein', 'admin', 'welcome', 'charlie', 'shadow', 
    'monkey', 'lincoln', 'letmein123', 'iloveyou', 'football', 'princess', 
    'solomon', 'trusted', 'security', '1234567', 'password12', 'abc123',
    '111111', '123321', 'secret', 'login', 'dragon', 'computer'
  ]);

  // Characters Pools
  const UPPERCASE_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const LOWERCASE_CHARS = 'abcdefghijklmnopqrstuvwxyz';
  const NUMBER_CHARS = '0123456789';
  const SYMBOL_CHARS = '!@#$%^&*()_+-=[]{}|;:\',./<>?';

  /* ==========================================================================
     Theme Management
     ========================================================================== */
  const themeToggleBtn = document.getElementById('theme-toggle-btn');
  
  // Load saved theme
  const savedTheme = localStorage.getItem('sentinel_theme') || 'theme-dark';
  document.body.className = savedTheme;

  themeToggleBtn.addEventListener('click', () => {
    if (document.body.classList.contains('theme-dark')) {
      document.body.className = 'theme-light';
      localStorage.setItem('sentinel_theme', 'theme-light');
    } else {
      document.body.className = 'theme-dark';
      localStorage.setItem('sentinel_theme', 'theme-dark');
    }
  });

  /* ==========================================================================
     UTC Clock
     ========================================================================== */
  const utcClockText = document.getElementById('utc-time-string');
  
  function updateUTCClock() {
    const now = new Date();
    // format as YYYY-MM-DD HH:MM:SS UTC
    const year = now.getUTCFullYear();
    const month = String(now.getUTCMonth() + 1).padStart(2, '0');
    const day = String(now.getUTCDate()).padStart(2, '0');
    const hours = String(now.getUTCHours()).padStart(2, '0');
    const minutes = String(now.getUTCMinutes()).padStart(2, '0');
    const seconds = String(now.getUTCSeconds()).padStart(2, '0');
    
    if (utcClockText) {
      utcClockText.textContent = `System Operating: ${year}-${month}-${day} ${hours}:${minutes}:${seconds} UTC`;
    }
  }
  
  updateUTCClock();
  setInterval(updateUTCClock, 1000);

  /* ==========================================================================
     Navigation Tab Switcher
     ========================================================================== */
  const tabButtons = document.querySelectorAll('.tab-btn');
  const tabPanels = document.querySelectorAll('.tab-panel');

  tabButtons.forEach(button => {
    button.addEventListener('click', () => {
      const targetTab = button.getAttribute('data-tab');
      switchTab(targetTab);
    });
  });

  function switchTab(tabId) {
    activeTab = tabId;

    // Update active button state
    tabButtons.forEach(btn => {
      if (btn.getAttribute('data-tab') === tabId) {
        btn.classList.add('active');
      } else {
        btn.classList.remove('active');
      }
    });

    // Update active panel display
    tabPanels.forEach(panel => {
      if (panel.id === `panel-${tabId}`) {
        panel.classList.add('active');
      } else {
        panel.classList.remove('active');
      }
    });

    // Trigger specific updates if moving to Generator
    if (tabId === 'generator') {
      triggerGenerator();
    }
  }

  // Education Sub-Tabs
  const eduSubTabBtns = document.querySelectorAll('.edu-sub-tab-btn');
  const eduSubContents = document.querySelectorAll('.edu-sub-content');

  eduSubTabBtns.forEach(button => {
    button.addEventListener('click', () => {
      const targetSubTab = button.getAttribute('data-subtab');
      switchSubTab(targetSubTab);
    });
  });

  function switchSubTab(subTabId) {
    activeSubTab = subTabId;

    eduSubTabBtns.forEach(btn => {
      if (btn.getAttribute('data-subtab') === subTabId) {
        btn.classList.add('active');
      } else {
        btn.classList.remove('active');
      }
    });

    eduSubContents.forEach(content => {
      if (content.id === `edu-content-${subTabId}`) {
        content.classList.add('active');
      } else {
        content.classList.remove('active');
      }
    });
  }

  /* ==========================================================================
     Core Security Logic (SHA-256, Bcrypt, Random Utilities)
     ========================================================================== */

  // Pure Javascript SHA-256 fallback in case Web Crypto is blocked
  function sha256Fallback(ascii) {
    function rightRotate(value, amount) {
      return (value >>> amount) | (value << (32 - amount));
    }
    
    const mathPow = Math.pow;
    const maxWord = mathPow(2, 32);
    const result = [];
    const words = [];
    const asciiLength = ascii.length;
    
    const hash = [
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ];
    const k = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    let i, j;
    const charCodes = [];
    for (i = 0; i < asciiLength; i++) {
      charCodes.push(ascii.charCodeAt(i));
    }
    
    charCodes.push(0x80);
    while (charCodes.length % 64 !== 56) {
      charCodes.push(0);
    }
    
    const lengthBits = asciiLength * 8;
    for (i = 7; i >= 0; i--) {
      charCodes.push((lengthBits >>> (i * 8)) & 0xff);
    }
    
    for (i = 0; i < charCodes.length; i += 64) {
      const w = [];
      for (j = 0; j < 16; j++) {
        w.push(
          (charCodes[i + j * 4] << 24) | 
          (charCodes[i + j * 4 + 1] << 16) | 
          (charCodes[i + j * 4 + 2] << 8) | 
          charCodes[i + j * 4 + 3]
        );
      }
      for (; j < 64; j++) {
        const s0 = rightRotate(w[j - 15], 7) ^ rightRotate(w[j - 15], 18) ^ (w[j - 15] >>> 3);
        const s1 = rightRotate(w[j - 2], 17) ^ rightRotate(w[j - 2], 19) ^ (w[j - 2] >>> 10);
        w.push((w[j - 16] + s0 + w[j - 7] + s1) | 0);
      }
      
      let a = hash[0], b = hash[1], c = hash[2], d = hash[3], 
          e = hash[4], f = hash[5], g = hash[6], h = hash[7];
          
      for (j = 0; j < 64; j++) {
        const s1_e = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
        const ch = (e & f) ^ (~e & g);
        const temp1 = (h + s1_e + ch + k[j] + w[j]) | 0;
        const s0_a = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (s0_a + maj) | 0;
        
        h = g;
        g = f;
        f = e;
        e = (d + temp1) | 0;
        d = c;
        c = b;
        b = a;
        a = (temp1 + temp2) | 0;
      }
      
      hash[0] = (hash[0] + a) | 0;
      hash[1] = (hash[1] + b) | 0;
      hash[2] = (hash[2] + c) | 0;
      hash[3] = (hash[3] + d) | 0;
      hash[4] = (hash[4] + e) | 0;
      hash[5] = (hash[5] + f) | 0;
      hash[6] = (hash[6] + g) | 0;
      hash[7] = (hash[7] + h) | 0;
    }
    
    for (i = 0; i < 8; i++) {
      const hex = (hash[i] >>> 0).toString(16).padStart(2, '0');
      result.push(hex.substring(hex.length - 8));
    }
    return result.join('');
  }

  // SHA-256 Async Wrapper
  async function sha256(message) {
    try {
      if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        return hashHex;
      }
    } catch (e) {
      console.warn('Web Crypto API fallback engaged due to sandbox constraints.', e);
    }
    return sha256Fallback(message);
  }

  // Simulated Bcrypt hash representation
  async function simulateBcrypt(password, customSalt, rounds = 12) {
    const combinedText = `bcrypt_seed::${password}::salt::${customSalt}::rounds::${rounds}`;
    const sha = await sha256(combinedText);
    const bcryptCharset = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    
    let saltPart = '';
    let hashPart = '';
    
    for (let i = 0; i < 22; i++) {
      const charCode = sha.charCodeAt(i % sha.length);
      saltPart += bcryptCharset.charAt(charCode % bcryptCharset.length);
    }
    for (let j = 0; j < 31; j++) {
      const charCode = sha.charCodeAt((j + 13) % sha.length);
      hashPart += bcryptCharset.charAt(charCode % bcryptCharset.length);
    }
    
    const paddedCost = String(rounds).padStart(2, '0');
    return `$2b$${paddedCost}$${saltPart}${hashPart}`;
  }

  // Generate Salt
  function generateRandomSalt(length = 16) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+';
    let result = '';
    const randomBytes = new Uint8Array(length);
    if (typeof window !== 'undefined' && window.crypto) {
      window.crypto.getRandomValues(randomBytes);
      for (let i = 0; i < length; i++) {
        result += chars.charAt(randomBytes[i] % chars.length);
      }
    } else {
      for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
      }
    }
    return result;
  }

  // Password Generator
  function generatePassword(settings) {
    const { length, uppercase, lowercase, numbers, symbols, excludeSimilar } = settings;

    let upperPool = UPPERCASE_CHARS;
    let lowerPool = LOWERCASE_CHARS;
    let numberPool = NUMBER_CHARS;
    let symbolPool = SYMBOL_CHARS;

    if (excludeSimilar) {
      upperPool = upperPool.replace(/[O]/g, '');
      lowerPool = lowerPool.replace(/[il]/g, '');
      numberPool = numberPool.replace(/[01]/g, '');
      symbolPool = symbolPool.replace(/[.,:;'"_`~|]/g, '');
    }

    const activePools = [];
    let combinedPool = '';

    const getRandChar = (pool) => {
      if (pool.length === 0) return '';
      const array = new Uint32Array(1);
      if (typeof window !== 'undefined' && window.crypto) {
        window.crypto.getRandomValues(array);
        const index = array[0] % pool.length;
        return pool.charAt(index);
      } else {
        const index = Math.floor(Math.random() * pool.length);
        return pool.charAt(index);
      }
    };

    if (uppercase && upperPool.length > 0) {
      activePools.push({ charPool: upperPool, mandatoryChar: getRandChar(upperPool) });
      combinedPool += upperPool;
    }
    if (lowercase && lowerPool.length > 0) {
      activePools.push({ charPool: lowerPool, mandatoryChar: getRandChar(lowerPool) });
      combinedPool += lowerPool;
    }
    if (numbers && numberPool.length > 0) {
      activePools.push({ charPool: numberPool, mandatoryChar: getRandChar(numberPool) });
      combinedPool += numberPool;
    }
    if (symbols && symbolPool.length > 0) {
      activePools.push({ charPool: symbolPool, mandatoryChar: getRandChar(symbolPool) });
      combinedPool += symbolPool;
    }

    if (combinedPool.length === 0) {
      combinedPool = lowerPool.length > 0 ? lowerPool : LOWERCASE_CHARS;
      activePools.push({ charPool: combinedPool, mandatoryChar: getRandChar(combinedPool) });
    }

    const resultChars = [];
    activePools.forEach(p => {
      if (p.mandatoryChar) {
        resultChars.push(p.mandatoryChar);
      }
    });

    const remainingLength = Math.max(0, length - resultChars.length);
    for (let i = 0; i < remainingLength; i++) {
      resultChars.push(getRandChar(combinedPool));
    }

    for (let i = resultChars.length - 1; i > 0; i--) {
      let j = 0;
      if (typeof window !== 'undefined' && window.crypto) {
        const array = new Uint32Array(1);
        window.crypto.getRandomValues(array);
        j = array[0] % (i + 1);
      } else {
        j = Math.floor(Math.random() * (i + 1));
      }
      const temp = resultChars[i];
      resultChars[i] = resultChars[j];
      resultChars[j] = temp;
    }

    return resultChars.join('');
  }

  // Repetitive Pattern Checks
  function hasRepetitivePattern(pwd) {
    if (pwd.length < 3) return false;
    const allSame = /^([\w\d\s\S])\1+$/;
    if (allSame.test(pwd)) return true;

    for (let len = 2; len <= Math.floor(pwd.length / 2); len++) {
      const chunk = pwd.slice(0, len);
      let replicated = '';
      while (replicated.length < pwd.length) {
        replicated += chunk;
      }
      if (replicated === pwd) return true;
    }
    return false;
  }

  // Sequences Check
  function hasSimpleSequence(pwd) {
    if (pwd.length < 4) return false;
    const lower = pwd.toLowerCase();
    for (let i = 0; i < lower.length - 3; i++) {
      const c1 = lower.charCodeAt(i);
      const c2 = lower.charCodeAt(i + 1);
      const c3 = lower.charCodeAt(i + 2);
      const c4 = lower.charCodeAt(i + 3);
      if (c2 === c1 + 1 && c3 === c2 + 1 && c4 === c3 + 1) return true;
      if (c2 === c1 - 1 && c3 === c2 - 1 && c4 === c3 - 1) return true;
    }
    return false;
  }

  // Brute Force Estimates
  function getCrackTime(entropy) {
    if (entropy === 0) return 'Instant';
    const combos = Math.pow(2, entropy);
    const guessesPerSecond = 1e10; // 10 Billion guesses/sec
    const seconds = combos / guessesPerSecond;

    if (seconds < 1e-3) return 'Instant (nanoseconds)';
    if (seconds < 1) return `${(seconds * 1000).toFixed(0)} milliseconds`;
    if (seconds < 60) return `${seconds.toFixed(1)} seconds`;
    
    const minutes = seconds / 60;
    if (minutes < 60) return `${minutes.toFixed(0)} minutes`;
    
    const hours = minutes / 60;
    if (hours < 24) return `${hours.toFixed(0)} hours`;
    
    const days = hours / 24;
    if (days < 30) return `${days.toFixed(0)} days`;
    
    const months = days / 30.44;
    if (months < 12) return `${months.toFixed(0)} months`;
    
    const years = months / 12;
    if (years < 100) return `${years.toFixed(0)} years`;
    if (years < 1e6) return `${(years / 100).toFixed(0)} centuries`;
    if (years < 1e9) return `${(years / 1e6).toFixed(1)} million years`;
    if (years < 1e12) return `${(years / 1e9).toFixed(1)} billion years`;
    
    return 'Trillions of years (Beyond the age of the Universe)';
  }

  // Core Password Analyzer Logic
  function analyzePassword(password) {
    if (!password) {
      return {
        score: 0,
        label: 'Very Weak',
        color: 'rose',
        entropy: 0,
        crackTime: 'Instant',
        checks: {
          length: false,
          lowercase: false,
          uppercase: false,
          numbers: false,
          symbols: false
        },
        suggestions: ['Begin typing a password in the input field above to see real-time secure analysis.'],
        isCommon: false
      };
    }

    const checks = {
      length: password.length >= 8,
      lowercase: /[a-z]/.test(password),
      uppercase: /[A-Z]/.test(password),
      numbers: /[0-9]/.test(password),
      symbols: /[^A-Za-z0-9]/.test(password)
    };

    const isCommon = COMMON_PASSWORDS.has(password.trim().toLowerCase());
    const hasSequence = hasSimpleSequence(password);
    const hasRepetitions = hasRepetitivePattern(password);

    // Pool size
    let poolSize = 0;
    if (checks.lowercase) poolSize += 26;
    if (checks.uppercase) poolSize += 26;
    if (checks.numbers) poolSize += 10;
    if (checks.symbols) poolSize += 33;
    if (poolSize === 0) poolSize = 1;

    // Shannon Entropy
    const entropy = Math.max(0, password.length * Math.log2(poolSize));

    // Calculate score
    let rawScore = 0;
    if (password.length >= 16) rawScore += 40;
    else if (password.length >= 12) rawScore += 32;
    else if (password.length >= 8) rawScore += 20;
    else rawScore += password.length * 2;

    const activeClasses = Object.values(checks).slice(1).filter(Boolean).length;
    rawScore += activeClasses * 10;

    if (password.length >= 12 && activeClasses >= 3) rawScore += 10;
    if (password.length >= 16 && activeClasses === 4) rawScore += 10;

    if (isCommon) {
      rawScore = Math.min(10, rawScore - 50);
    } else if (hasSequence) {
      rawScore = Math.max(15, rawScore - 25);
    } else if (hasRepetitions) {
      rawScore = Math.max(15, rawScore - 20);
    }

    const score = Math.max(0, Math.min(100, Math.round(rawScore)));

    let label = 'Very Weak';
    let color = 'rose';

    if (score >= 90) {
      label = 'Excellent';
      color = 'emerald';
    } else if (score >= 70) {
      label = 'Strong';
      color = 'teal';
    } else if (score >= 45) {
      label = 'Medium';
      color = 'amber';
    } else if (score >= 20) {
      label = 'Weak';
      color = 'orange';
    }

    const suggestions = [];
    if (isCommon) {
      suggestions.push('⚠️ CRITICAL: This password is in the top list of commonly cracked passwords. Hackers will guess it instantly via dictionary attacks. Do not use it.');
    }
    if (password.length < 8) {
      suggestions.push('Make the password longer: Target at least 12–16 characters for elite production security.');
    } else if (password.length >= 8 && password.length < 12) {
      suggestions.push('Increase length to 12 or more characters. Length is the single most powerful factor to increase cracking time.');
    }
    if (!checks.lowercase) suggestions.push('Add at least one lowercase letter to widen the key search pool.');
    if (!checks.uppercase) suggestions.push('Add at least one uppercase letter (e.g. A, B, C) to create structural variations.');
    if (!checks.numbers) suggestions.push('Mix in some digits (0-9) so the password is not pure text.');
    if (!checks.symbols) suggestions.push('Insert a special symbol (like @, #, $, %, !, *) to force hackers into a much larger keyspace search.');
    if (hasSequence) {
      suggestions.push('Avoid natural sequences like "1234", "abcd", or keyboard walkthroughs which automated lookup script dictionaries hit first.');
    }
    if (hasRepetitions) {
      suggestions.push('Avoid repetitive character sequences or duplicate blocks (like "aaaa" or "xyzxyz").');
    }

    if (score >= 70 && suggestions.length === 0) {
      suggestions.push('Excellent! Your password has superb character diversity and length.');
    } else if (score >= 90) {
      suggestions.splice(0, suggestions.length, '⭐ Bulletproof! Securely memorize this or save it in an offline password manager. This password is highly resilient against brute forcing.');
    }

    const crackTime = getCrackTime(entropy);

    return {
      score,
      label,
      color,
      entropy: Math.round(entropy * 100) / 100,
      crackTime,
      checks,
      suggestions,
      isCommon
    };
  }

  /* ==========================================================================
     Assessment UI (Tab A) Interactions
     ========================================================================== */
  const masterPasswordInput = document.getElementById('master-password-input');
  const toggleVisibilityBtn = document.getElementById('toggle-visibility-btn');
  const eyeIcon = toggleVisibilityBtn.querySelector('.eye-icon');
  const eyeOffIcon = toggleVisibilityBtn.querySelector('.eye-off-icon');
  const commitHistoryBtn = document.getElementById('commit-history-btn');
  const reuseWarningBanner = document.getElementById('reuse-warning-banner');
  const reuseWarningText = document.getElementById('reuse-warning-text');
  
  const strengthDisplayCard = document.getElementById('strength-display-card');
  const postureIcon = document.getElementById('posture-icon');
  const strengthLabel = document.getElementById('strength-label');
  const strengthScore = document.getElementById('strength-score');
  const strengthProgress = document.getElementById('strength-progress');
  
  const entropyBadge = document.getElementById('entropy-badge');
  const entropyValue = document.getElementById('entropy-value');
  const crackTimeValue = document.getElementById('crack-time-value');
  
  const ruleLength = document.getElementById('rule-length');
  const ruleLowercase = document.getElementById('rule-lowercase');
  const ruleUppercase = document.getElementById('rule-uppercase');
  const ruleNumbers = document.getElementById('rule-numbers');
  const ruleSymbols = document.getElementById('rule-symbols');
  
  const suggestionsList = document.getElementById('suggestions-list');
  const suggestionsTip = document.getElementById('suggestions-tip');

  // Input events
  masterPasswordInput.addEventListener('input', () => {
    updateAnalyzerUI(masterPasswordInput.value);
  });

  // Toggle input mask visibility
  toggleVisibilityBtn.addEventListener('click', () => {
    if (masterPasswordInput.type === 'password') {
      masterPasswordInput.type = 'text';
      eyeIcon.classList.add('hidden');
      eyeOffIcon.classList.remove('hidden');
      toggleVisibilityBtn.title = "Hide password";
    } else {
      masterPasswordInput.type = 'password';
      eyeIcon.classList.remove('hidden');
      eyeOffIcon.classList.add('hidden');
      toggleVisibilityBtn.title = "Show password";
    }
  });

  // Main UI update routine
  function updateAnalyzerUI(val) {
    const res = analyzePassword(val);
    
    // Check if reused
    const isReused = historyList.some(item => item.val === val) && val.length > 0;
    if (isReused) {
      const match = historyList.find(item => item.val === val);
      reuseWarningText.innerHTML = `This credentials candidate is already saved in your history ledger (logged on <strong>${match.date}</strong> with an integrity score of <strong>${match.score}/100</strong>). Pattern reuse elevates risk from credential stuffing.`;
      reuseWarningBanner.classList.remove('hidden');
    } else {
      reuseWarningBanner.classList.add('hidden');
    }

    // Set buttons disabled state
    if (val && !historyList.some(item => item.val === val)) {
      commitHistoryBtn.classList.remove('disabled');
      commitHistoryBtn.removeAttribute('disabled');
    } else {
      commitHistoryBtn.classList.add('disabled');
      commitHistoryBtn.setAttribute('disabled', 'true');
      if (val && historyList.some(item => item.val === val)) {
        commitHistoryBtn.title = 'Already committed to history log';
      }
    }

    // Update Strength Display Card theme class
    strengthDisplayCard.className = `strength-card color-${res.color}`;
    
    // Icon configuration
    if (res.score >= 70) {
      postureIcon.setAttribute('data-lucide', 'shield-check');
    } else {
      postureIcon.setAttribute('data-lucide', 'shield-alert');
    }
    
    strengthLabel.textContent = res.label;
    strengthScore.textContent = res.score;
    strengthProgress.style.width = `${res.score}%`;

    // Entropy Badge configuration
    entropyValue.textContent = res.entropy;
    if (res.entropy < 30) {
      entropyBadge.textContent = 'Trivial';
      entropyBadge.className = 'badge badge-danger';
    } else if (res.entropy < 60) {
      entropyBadge.textContent = 'Moderate';
      entropyBadge.className = 'badge badge-warning';
    } else if (res.entropy < 80) {
      entropyBadge.textContent = 'High Defense';
      entropyBadge.className = 'badge badge-info';
    } else {
      entropyBadge.textContent = 'Military-Grade';
      entropyBadge.className = 'badge badge-success';
    }

    crackTimeValue.textContent = res.crackTime;

    // Rules checklist styling updates
    updateRuleItem(ruleLength, res.checks.length);
    updateRuleItem(ruleLowercase, res.checks.lowercase);
    updateRuleItem(ruleUppercase, res.checks.uppercase);
    updateRuleItem(ruleNumbers, res.checks.numbers);
    updateRuleItem(ruleSymbols, res.checks.symbols);

    // Render suggestions
    suggestionsList.innerHTML = '';
    res.suggestions.forEach(tip => {
      const li = document.createElement('li');
      li.textContent = tip;
      suggestionsList.appendChild(li);
    });

    if (res.score < 70) {
      suggestionsTip.classList.remove('hidden');
    } else {
      suggestionsTip.classList.add('hidden');
    }

    // Dynamic icons reload
    lucide.createIcons();
  }

  function updateRuleItem(element, met) {
    const badge = element.querySelector('.rule-badge');
    if (met) {
      element.classList.add('met');
      badge.textContent = 'Pass';
    } else {
      element.classList.remove('met');
      badge.textContent = 'Required';
    }
  }

  /* ==========================================================================
     Password History Management
     ========================================================================== */
  const clearHistoryBtn = document.getElementById('clear-history-btn');
  const historyEmptyState = document.getElementById('history-empty-state');
  const historyGrid = document.getElementById('history-grid');

  commitHistoryBtn.addEventListener('click', () => {
    const val = masterPasswordInput.value;
    if (!val) return;
    if (historyList.some(item => item.val === val)) return;

    const res = analyzePassword(val);
    const dateStr = new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }) + ' ' + new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric' });

    const newItem = {
      id: Math.random().toString(36).substring(2, 9),
      val: val,
      score: res.score,
      label: res.label,
      color: res.color,
      date: dateStr
    };

    historyList.unshift(newItem);
    historyList = historyList.slice(0, 8); // Max 8 elements
    saveHistory(historyList);
    renderHistoryUI();
    updateAnalyzerUI(val);
  });

  clearHistoryBtn.addEventListener('click', () => {
    historyList = [];
    saveHistory([]);
    renderHistoryUI();
    updateAnalyzerUI(masterPasswordInput.value);
  });

  function renderHistoryUI() {
    historyGrid.innerHTML = '';

    if (historyList.length === 0) {
      historyEmptyState.classList.remove('hidden');
      clearHistoryBtn.classList.add('hidden');
      return;
    }

    historyEmptyState.classList.add('hidden');
    clearHistoryBtn.classList.remove('hidden');

    historyList.forEach(item => {
      const card = document.createElement('div');
      card.className = 'history-card animate-fade-in';
      card.setAttribute('data-id', item.id);

      const isRevealed = !!revealedHistoryIds[item.id];
      const displayVal = isRevealed ? item.val : '••••••••••••';

      card.innerHTML = `
        <div class="history-card-top">
          <div>
            <div class="history-date">Valid: ${item.date}</div>
            <div class="history-value-container">
              <span class="history-value font-mono">${displayVal}</span>
              <button class="history-card-btn reveal-btn" title="${isRevealed ? 'Mask value' : 'Expose value'}">
                <i data-lucide="${isRevealed ? 'eye-off' : 'eye'}"></i>
              </button>
            </div>
          </div>
          <div class="history-card-actions">
            <button class="history-card-btn delete-btn" title="Delete entry">
              <i data-lucide="trash-2"></i>
            </button>
          </div>
        </div>
        <div class="history-card-bottom">
          <span class="history-score-label">Audit Score</span>
          <div class="history-score-badge">
            <span class="history-score-dot dot-${item.color}"></span>
            <span class="score">${item.score}</span>
            <span class="label lbl-${item.color}">${item.label}</span>
          </div>
        </div>
      `;

      // Load to input click
      card.addEventListener('click', (e) => {
        // Prevent click events when triggering individual button action elements
        if (e.target.closest('.history-card-btn')) return;
        masterPasswordInput.value = item.val;
        updateAnalyzerUI(item.val);
      });

      // Delete entry action
      const deleteBtn = card.querySelector('.delete-btn');
      deleteBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        historyList = historyList.filter(h => h.id !== item.id);
        saveHistory(historyList);
        renderHistoryUI();
        updateAnalyzerUI(masterPasswordInput.value);
      });

      // Reveal / Mask action
      const revealBtn = card.querySelector('.reveal-btn');
      revealBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        revealedHistoryIds[item.id] = !revealedHistoryIds[item.id];
        renderHistoryUI();
      });

      historyGrid.appendChild(card);
    });

    lucide.createIcons();
  }

  function loadHistory() {
    try {
      const raw = localStorage.getItem('sentinel_password_history');
      return raw ? JSON.parse(raw) : [];
    } catch {
      return [];
    }
  }

  function saveHistory(list) {
    try {
      localStorage.setItem('sentinel_password_history', JSON.stringify(list));
    } catch (e) {
      console.error(e);
    }
  }

  /* ==========================================================================
     Entropy Generator (Tab B) Interactions
     ========================================================================== */
  const lengthSlider = document.getElementById('length-slider');
  const lengthBadge = document.getElementById('length-badge');
  const poolUppercase = document.getElementById('pool-uppercase');
  const poolLowercase = document.getElementById('pool-lowercase');
  const poolNumbers = document.getElementById('pool-numbers');
  const poolSymbols = document.getElementById('pool-symbols');
  const excludeSimilar = document.getElementById('exclude-similar');
  
  const generatedPasswordOutput = document.getElementById('generated-password-output');
  const genStrengthBadge = document.getElementById('gen-strength-badge');
  const genEntropyValue = document.getElementById('gen-entropy-value');
  
  const regenerateBtn = document.getElementById('regenerate-btn');
  const copyPasswordBtn = document.getElementById('copy-password-btn');
  const copyIcon = copyPasswordBtn.querySelector('.copy-icon');
  const checkIcon = copyPasswordBtn.querySelector('.check-icon');
  const copyBtnText = document.getElementById('copy-btn-text');
  const applyToAnalyzerBtn = document.getElementById('apply-to-analyzer-btn');

  // Slide element events
  lengthSlider.addEventListener('input', () => {
    generatorSettings.length = parseInt(lengthSlider.value);
    lengthBadge.textContent = generatorSettings.length;
    triggerGenerator();
  });

  [poolUppercase, poolLowercase, poolNumbers, poolSymbols, excludeSimilar].forEach(item => {
    item.addEventListener('change', () => {
      generatorSettings.uppercase = poolUppercase.checked;
      generatorSettings.lowercase = poolLowercase.checked;
      generatorSettings.numbers = poolNumbers.checked;
      generatorSettings.symbols = poolSymbols.checked;
      generatorSettings.excludeSimilar = excludeSimilar.checked;
      triggerGenerator();
    });
  });

  regenerateBtn.addEventListener('click', triggerGenerator);

  // Copy password
  copyPasswordBtn.addEventListener('click', () => {
    const text = generatedPasswordOutput.textContent;
    if (!text || text === 'Select parameters...') return;

    navigator.clipboard.writeText(text).then(() => {
      copyIcon.classList.add('hidden');
      checkIcon.classList.remove('hidden');
      copyBtnText.textContent = 'Copied!';
      
      setTimeout(() => {
        copyIcon.classList.remove('hidden');
        checkIcon.classList.add('hidden');
        copyBtnText.textContent = 'Copy';
      }, 2000);
    });
  });

  // Apply password directly to assessment
  applyToAnalyzerBtn.addEventListener('click', () => {
    const text = generatedPasswordOutput.textContent;
    if (!text || text === 'Select parameters...') return;

    masterPasswordInput.value = text;
    updateAnalyzerUI(text);
    switchTab('analyzer');
    masterPasswordInput.focus();
  });

  function triggerGenerator() {
    const pwd = generatePassword(generatorSettings);
    generatedPasswordOutput.textContent = pwd;
    
    // Analyze generated strength
    const res = analyzePassword(pwd);
    genStrengthBadge.textContent = `${res.label} (${res.score}/100)`;
    genStrengthBadge.className = `badge badge-${res.color === 'rose' ? 'danger' : res.color === 'orange' ? 'warning' : res.color === 'amber' ? 'warning' : res.color === 'teal' ? 'info' : 'success'}`;
    genEntropyValue.textContent = `${res.entropy} bits`;
  }

  /* ==========================================================================
     Cybersecurity Specialist Lab Sandbox (Tab C) Interactions
     ========================================================================== */
  const sandboxInputText = document.getElementById('sandbox-input-text');
  const sandboxAutoSalt = document.getElementById('sandbox-auto-salt');
  const sandboxSaltInput = document.getElementById('sandbox-salt-input');
  const sandboxRefreshSaltBtn = document.getElementById('sandbox-refresh-salt-btn');
  const sandboxCostSlider = document.getElementById('sandbox-cost-slider');
  const sandboxCostBadge = document.getElementById('sandbox-cost-badge');
  const consoleStatus = document.getElementById('console-status');

  const step1Val = document.getElementById('console-step1-value');
  const step2Val = document.getElementById('console-step2-value');
  const step3Val = document.getElementById('console-step3-value');
  const step3SaltBadge = document.getElementById('console-step3-salt-badge');
  const step4Val = document.getElementById('console-step4-value');
  const step4MetaBadge = document.getElementById('console-step4-meta-badge');

  // Input states and change events
  let sandboxSalt = generateRandomSalt(12);

  sandboxInputText.addEventListener('input', runSandboxCalculations);

  sandboxAutoSalt.addEventListener('change', () => {
    const auto = sandboxAutoSalt.checked;
    sandboxSaltInput.disabled = auto;
    
    if (auto) {
      sandboxSalt = generateRandomSalt(12);
      sandboxSaltInput.value = '';
    } else {
      sandboxSalt = sandboxSaltInput.value || 'StaticSaltDemo';
    }
    runSandboxCalculations();
  });

  sandboxSaltInput.addEventListener('input', () => {
    sandboxSalt = sandboxSaltInput.value || '';
    runSandboxCalculations();
  });

  sandboxRefreshSaltBtn.addEventListener('click', () => {
    if (sandboxAutoSalt.checked) {
      sandboxSalt = generateRandomSalt(12);
      runSandboxCalculations();
    }
  });

  sandboxCostSlider.addEventListener('input', () => {
    const rounds = parseInt(sandboxCostSlider.value);
    sandboxCostBadge.textContent = `${rounds} rounds`;
    runSandboxCalculations();
  });

  async function runSandboxCalculations() {
    consoleStatus.textContent = 'executing...';
    consoleStatus.style.backgroundColor = 'rgba(245, 158, 11, 0.1)';
    consoleStatus.style.color = 'var(--warning)';

    const text = sandboxInputText.value;
    const rounds = parseInt(sandboxCostSlider.value);
    const activeSalt = sandboxAutoSalt.checked ? sandboxSalt : (sandboxSalt || 'StaticSaltDemo');

    // Step 1
    step1Val.textContent = `"${text}"`;

    // Step 2
    const sha = await sha256(text);
    step2Val.textContent = sha;

    // Step 3
    step3SaltBadge.textContent = `Salt: "${activeSalt}"`;
    const saltedSha = await sha256(text + activeSalt);
    step3Val.textContent = saltedSha;

    // Step 4
    step4MetaBadge.textContent = `[ID: $2b$, Cost: ${rounds}]`;
    const bcryptRep = await simulateBcrypt(text, activeSalt, rounds);
    step4Val.textContent = bcryptRep;

    // Set online status back
    consoleStatus.textContent = 'online';
    consoleStatus.style.backgroundColor = 'rgba(16, 185, 129, 0.1)';
    consoleStatus.style.color = 'var(--success)';
  }

  // Specialist Lab Code Copy triggers
  setupCopyBtn('copy-sql-btn', 'sql-code-display');
  setupCopyBtn('copy-node-btn', 'node-code-display');

  function setupCopyBtn(btnId, codeId) {
    const btn = document.getElementById(btnId);
    if (!btn) return;
    const copyIcon = btn.querySelector('.copy-icon');
    const checkIcon = btn.querySelector('.check-icon');
    const textSpan = btn.querySelector('.copy-text');

    btn.addEventListener('click', () => {
      const code = document.getElementById(codeId).textContent;
      navigator.clipboard.writeText(code).then(() => {
        copyIcon.classList.add('hidden');
        checkIcon.classList.remove('hidden');
        if (textSpan) textSpan.textContent = 'Copied';

        setTimeout(() => {
          copyIcon.classList.remove('hidden');
          checkIcon.classList.add('hidden');
          if (textSpan) textSpan.textContent = 'Copy';
        }, 2000);
      });
    });
  }

  /* ==========================================================================
     Initializations
     ========================================================================== */
  
  // Set initial text inputs if values present
  masterPasswordInput.value = '';
  updateAnalyzerUI('');
  
  // Render initially loaded history
  renderHistoryUI();

  // Run initial sandbox calculations
  sandboxSaltInput.placeholder = "Auto-generated: " + sandboxSalt;
  runSandboxCalculations();

  // Load Lucide Icons
  lucide.createIcons();
});
