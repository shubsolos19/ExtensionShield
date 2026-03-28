import React, { useState, useEffect, useRef, useCallback } from "react";
import { useNavigate, Link } from "react-router-dom";
import { motion } from "framer-motion";
import { ArrowRight, Download } from "lucide-react";
import { useScan } from "../context/ScanContext";
import { useAuth } from "../context/AuthContext";
import { requiresAuthForScan } from "../utils/authUtils";
import databaseService from "../services/databaseService";
import SEOHead from "../components/SEOHead";
import { HeroOrbitalCarousel } from "../components/hero";
import DemoModal from "../components/DemoModal";
import UploadModal from "../components/UploadModal";
import DevOpenCoreSection from "../components/home/DevOpenCoreSection";
import HowWeProtectYouSection from "../components/home/HowWeProtectYouSection";
import { CHROME_EXTENSION_STORE_URL, EXTENSION_ICON_PLACEHOLDER, getExtensionIconUrl } from "../utils/constants";
import { getScanResultsRoute } from "../utils/slug";
import "./HomePage.scss";

const HomePage = () => {
  const navigate = useNavigate();
  const { startScan, setUrl, error: scanError } = useScan();
  const { isAuthenticated, openSignInModal } = useAuth();
  const [isVisible, setIsVisible] = useState(false);
  const [scanInput, setScanInput] = useState("");
  // Hero stat: real cumulative usage is 100+ (DB was reset, so live count would show lower). Animation runs immediately on load.
  const EXTENSIONS_DISPLAY_TARGET = 100;
  const [extensionsScannedCount] = useState(EXTENSIONS_DISPLAY_TARGET);
  const [displayCount, setDisplayCount] = useState(0);
  const displayCountRef = useRef(0);
  const rafRef = useRef(null);
  const [demoModalOpen, setDemoModalOpen] = useState(false);
  const [uploadModalOpen, setUploadModalOpen] = useState(false);
  const demoTriggerRef = useRef(null);
  const [reducedMotion, setReducedMotion] = useState(false);
  const [heroAudience, setHeroAudience] = useState("users"); // "users" | "developers"

  // Autocomplete — same as /scan: logo + name only, no scoring
  const [autocompleteSuggestions, setAutocompleteSuggestions] = useState([]);
  const [autocompleteIndex, setAutocompleteIndex] = useState(0);
  const [autocompleteLoading, setAutocompleteLoading] = useState(false);
  const autocompleteTimerRef = useRef(null);

  const handleAutocomplete = useCallback((query) => {
    const q = (query || "").trim();
    if (!q || q.length < 2 || /^https?:\/\//.test(q) || /^[a-z]{32}$/i.test(q)) {
      setAutocompleteSuggestions([]);
      setAutocompleteLoading(false);
      return;
    }
    setAutocompleteLoading(true);
    setAutocompleteSuggestions([]);
    clearTimeout(autocompleteTimerRef.current);
    autocompleteTimerRef.current = setTimeout(async () => {
      try {
        const results = await databaseService.getRecentScans(6, q);
        setAutocompleteSuggestions(results || []);
        setAutocompleteIndex(0);
      } catch {
        setAutocompleteSuggestions([]);
      } finally {
        setAutocompleteLoading(false);
      }
    }, 80);
  }, []);

  const handleSelectSuggestion = useCallback((scan) => {
    setAutocompleteSuggestions([]);
    const route = getScanResultsRoute(scan.extension_id, scan.extension_name);
    navigate(route);
  }, [navigate]);

  // Animate display count from current to target (incremental counter effect)
  useEffect(() => {
    const target = Math.max(0, extensionsScannedCount);
    const start = displayCountRef.current;
    const diff = target - start;
    if (diff === 0) return;

    const durationMs = 1400;
    const easeOutQuart = (t) => 1 - (1 - t) ** 4;
    const startTime = performance.now();

    const tick = (now) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / durationMs, 1);
      const eased = easeOutQuart(progress);
      const current = Math.round(start + diff * eased);
      displayCountRef.current = current;
      setDisplayCount(current);
      if (progress < 1) {
        rafRef.current = requestAnimationFrame(tick);
      } else {
        displayCountRef.current = target;
        setDisplayCount(target);
      }
    };

    rafRef.current = requestAnimationFrame(tick);
    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
  }, [extensionsScannedCount]);

  const scrollToProof = useCallback(() => {
    document.getElementById("proof")?.scrollIntoView({ behavior: "smooth" });
  }, []);

  useEffect(() => {
    setIsVisible(true);
  }, []);

  useEffect(() => {
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    setReducedMotion(mq.matches);
    const handler = () => setReducedMotion(mq.matches);
    mq.addEventListener("change", handler);
    return () => mq.removeEventListener("change", handler);
  }, []);

  const handleScan = useCallback(() => {
    const input = scanInput.trim();
    if (input) {
      setScanInput("");
      setUrl("");
      startScan(input);
    } else {
      navigate("/scan");
    }
  }, [scanInput, setUrl, startScan, navigate]);

  const organizationSchema = {
    "@context": "https://schema.org",
    "@type": "Organization",
    "name": "ExtensionShield",
    "url": "https://extensionshield.com",
    "logo": "https://extensionshield.com/logo.png",
    "description": "Chrome extension scanner — safety reports in seconds.",
    "sameAs": [
      "https://github.com/Stanzin7/ExtensionShield"
    ]
  };

  const softwareAppSchema = {
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    "name": "ExtensionShield",
    "applicationCategory": "SecurityApplication",
    "operatingSystem": "Web",
    "offers": [
      { "@type": "Offer", "price": "0", "priceCurrency": "USD", "description": "Free public extension scan by Chrome Web Store URL" },
      { "@type": "Offer", "description": "Pro: private CRX/ZIP security audit and vulnerability scan" }
    ],
    "description": "Chrome extension security scanner. Scan by Chrome Web Store URL for free. Upload private CRX/ZIP for pre-release security audit, vulnerability scanning, and fix suggestions.",
    "url": "https://extensionshield.com/scan"
  };

  const faqSchema = {
    "@context": "https://schema.org",
    "@type": "FAQPage",
    "mainEntity": [
      {
        "@type": "Question",
        "name": "Can I scan a private CRX/ZIP?",
        "acceptedAnswer": { "@type": "Answer", "text": "Yes. Pro users can upload a private CRX or ZIP build for a pre-release security audit. Sign in and go to Upload CRX/ZIP from the Scan menu." }
      },
      {
        "@type": "Question",
        "name": "What does the audit check?",
        "acceptedAnswer": { "@type": "Answer", "text": "The audit checks security (SAST, malware/VirusTotal, obfuscation), privacy (permissions, data exfil, network calls), and governance (policy alignment, disclosure). You get evidence-linked findings and fix suggestions." }
      },
      {
        "@type": "Question",
        "name": "Do you store uploads?",
        "acceptedAnswer": { "@type": "Answer", "text": "Uploads are processed to generate the report. We do not retain your private build for longer than needed to complete the scan. Reports are private by default; you choose whether to share." }
      },
      {
        "@type": "Question",
        "name": "Does this help with Chrome Web Store policy risks?",
        "acceptedAnswer": { "@type": "Answer", "text": "Yes. The governance layer covers policy alignment, disclosure accuracy, and consistency—so you can address store policy risks before submission." }
      },
      {
        "@type": "Question",
        "name": "Is the Chrome extension scanner free?",
        "acceptedAnswer": { "@type": "Answer", "text": "Yes. Our free extension scanner lets you scan any Chrome extension by Web Store URL or extension ID. Private CRX/ZIP upload and audit are available on Pro for developers." }
      }
    ]
  };

  return (
    <>
      <SEOHead
        title="Free Chrome Extension Scanner & Security Audit | ExtensionShield"
        description="Free Chrome extension scanner and security audit for developers. Scan any extension by URL—get risk score, permissions & malware check. Audit CRX/ZIP builds before release."
        pathname="/"
        ogType="website"
        schema={[organizationSchema, softwareAppSchema, faqSchema]}
        keywords="free extension scanner, free extension audit, Chrome extension scanner, Chrome extension security, extension security audit, developer extension audit, scan Chrome extension"
      />
      
      <div className="home-page">
        {/* Hero Section - Two-column layout with frosted glass scan preview */}
        <section
          className="hero-section"
          aria-label="Chrome Extension Security Gate"
        >
          {/* Mobile/tablet: scanner not supported — show idea + Step-by-step guide + Check on desktop */}
          <div className="hero-mobile-message">
            <p className="hero-tagline">CHROME EXTENSION SECURITY GATE</p>
            <h1 className="hero-title">Ship safer Chrome extensions.</h1>
            <button
              type="button"
              className="hero-mobile-demo-btn"
              onClick={() => setDemoModalOpen(true)}
              title="Step-by-step guide"
            >
              <span className="hero-demo-icon" aria-hidden>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="10" />
                  <polygon points="10 8 16 12 10 16 10 8" fill="currentColor" stroke="none" />
                </svg>
              </span>
              <span>Step-by-step guide</span>
            </button>
            <p className="hero-mobile-cta">Check on desktop.</p>
          </div>

          <div className="hero-desktop-content">
          <div className="hero-grid">
            {/* Left Panel - Headline, Input, CTA */}
            <motion.div
              className="hero-left"
              initial={{ opacity: 0, y: 24 }}
              animate={isVisible ? { opacity: 1, y: 0 } : {}}
              transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
            >
              <div className="hero-audience-toggle" role="group" aria-label="Audience">
                <button
                  type="button"
                  className={`hero-toggle-option ${heroAudience === "users" ? "active" : ""}`}
                  onClick={() => setHeroAudience("users")}
                  aria-pressed={heroAudience === "users"}
                >
                  Users
                </button>
                <button
                  type="button"
                  className={`hero-toggle-option ${heroAudience === "developers" ? "active" : ""}`}
                  onClick={() => setHeroAudience("developers")}
                  aria-pressed={heroAudience === "developers"}
                >
                  Developers
                </button>
              </div>

              {heroAudience === "users" ? (
              <>
                <p className="hero-tagline">Extension Risk Check</p>
                <h1 className="hero-title">
                  Know what your Chrome extensions can access.
                </h1>
                <button
                  type="button"
                  ref={demoTriggerRef}
                  className="scanner-demo-link scanner-demo-link--above"
                  title="Step-by-step guide to scanning an extension"
                  onClick={() => setDemoModalOpen(true)}
                >
                  <span className="scanner-demo-icon" aria-hidden>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <circle cx="12" cy="12" r="10" />
                      <polygon points="10 8 16 12 10 16 10 8" fill="currentColor" stroke="none" />
                    </svg>
                  </span>
                  <span>Step-by-step guide</span>
                </button>
                <div className="hero-search">
                  <div className="search-container hero-search-container">
                    <span className="search-icon search-icon-chrome" aria-hidden="true">
                      <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" className="chrome-logo">
                        <path d="M12 12L22 12A10 10 0 0 1 7 3.34L12 12Z" fill="#4285F4" />
                        <path d="M12 12L7 3.34A10 10 0 0 1 7 20.66L12 12Z" fill="#EA4335" />
                        <path d="M12 12L7 20.66A10 10 0 0 1 22 12L12 12Z" fill="#FBBC05" />
                        <circle cx="12" cy="12" r="4" fill="#34A853" />
                        <circle cx="12" cy="12" r="2.5" fill="white" />
                      </svg>
                    </span>
                    <input
                      type="text"
                      id="hero-scan-input"
                      placeholder="Search extension name or paste Store URL"
                      value={scanInput}
                      onChange={(e) => {
                        setScanInput(e.target.value);
                        handleAutocomplete(e.target.value);
                      }}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") {
                          if (autocompleteSuggestions.length > 0 && autocompleteIndex >= 0 && autocompleteSuggestions[autocompleteIndex]) {
                            handleSelectSuggestion(autocompleteSuggestions[autocompleteIndex]);
                            return;
                          }
                          handleScan();
                          return;
                        }
                        if (e.key === "Escape") setAutocompleteSuggestions([]);
                        if (e.key === "ArrowDown" && autocompleteSuggestions.length > 0) {
                          e.preventDefault();
                          setAutocompleteIndex((i) => Math.min(i + 1, autocompleteSuggestions.length - 1));
                        }
                        if (e.key === "ArrowUp" && autocompleteSuggestions.length > 0) {
                          e.preventDefault();
                          setAutocompleteIndex((i) => Math.max(i - 1, 0));
                        }
                      }}
                      onFocus={() => { if (scanInput.trim().length >= 2) handleAutocomplete(scanInput); }}
                      onBlur={() => { setTimeout(() => { setAutocompleteSuggestions([]); setAutocompleteLoading(false); }, 150); }}
                      aria-label="Search extension name or paste Store URL"
                      autoComplete="off"
                      role="combobox"
                      aria-expanded={autocompleteSuggestions.length > 0 || autocompleteLoading}
                      aria-autocomplete="list"
                      aria-controls="hero-autocomplete-list"
                    />
                    {(autocompleteSuggestions.length > 0 || autocompleteLoading) && (
                      <ul className="hero-autocomplete" id="hero-autocomplete-list" role="listbox">
                        {autocompleteLoading && autocompleteSuggestions.length === 0 ? (
                          <li className="hero-autocomplete-item hero-autocomplete-loading" role="status">
                            <span className="hero-autocomplete-name">Searching...</span>
                          </li>
                        ) : (
                          autocompleteSuggestions.map((s, i) => (
                          <li
                            key={s.extension_id}
                            role="option"
                            aria-selected={i === autocompleteIndex}
                            className={`hero-autocomplete-item${i === autocompleteIndex ? " active" : ""}`}
                            onMouseDown={(e) => {
                              e.preventDefault();
                              handleSelectSuggestion(s);
                            }}
                          >
                            <img
                              src={getExtensionIconUrl(s.extension_id)}
                              alt=""
                              className="hero-autocomplete-icon"
                              width="20"
                              height="20"
                              onError={(e) => { e.target.onerror = null; e.target.src = EXTENSION_ICON_PLACEHOLDER; }}
                            />
                            <span className="hero-autocomplete-name">{s.extension_name || s.extension_id}</span>
                          </li>
                        ))
                        )}
                      </ul>
                    )}
                    <motion.button
                      type="button"
                      className="search-btn search-btn-icon"
                      onClick={handleScan}
                      aria-label="Scan extension"
                      whileHover={{ scale: 1.02 }}
                      whileTap={{ scale: 0.98 }}
                    >
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                        <circle cx="11" cy="11" r="8" />
                        <path d="M21 21l-4.35-4.35" />
                      </svg>
                    </motion.button>
                  </div>
                  <p className="hero-scan-info">
                    <svg className="hero-scan-check" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                      <path d="M20 6L9 17l-5-5" />
                    </svg>
                    Checks permissions, network access, version history, and known threats.
                  </p>
                  <div className="hero-cta-block">
                    <a
                      href={CHROME_EXTENSION_STORE_URL}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="get-extension-btn"
                    >
                      <Download size={18} strokeWidth={2} aria-hidden />
                      Add to Chrome
                    </a>
                  </div>
                  {scanError && <p className="scan-error-hint">{scanError}</p>}
                </div>
              </>
              ) : (
              <>
                <p className="hero-tagline">Pro • Private Build Audit</p>
                <h1 className="hero-title">
                  Chrome extension security audit before you ship
                </h1>
                <p className="hero-dev-body">
                  Vulnerabilities, permissions, policy checks — with evidence and fix guidance.
                </p>
                <p className="hero-dev-helper">Private by default — share only if you choose.</p>
                <div className="hero-developers-cta">
                  {isAuthenticated ? (
                    <button
                      type="button"
                      className="hero-pro-upload-btn"
                      onClick={() => navigate("/scan/upload")}
                    >
                      <span className="hero-pro-upload-btn-icon" aria-hidden>
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                          <polyline points="17 8 12 3 7 8" />
                          <line x1="12" y1="3" x2="12" y2="15" />
                        </svg>
                      </span>
                      <span>Upload CRX/ZIP</span>
                    </button>
                  ) : (
                    <button
                      type="button"
                      className="hero-pro-upload-btn"
                      onClick={() => openSignInModal()}
                    >
                      <span>Start a Pro audit</span>
                    </button>
                  )}
                </div>
              </>
              )}
            </motion.div>

            {/* Right Panel - 3D orbital carousel with focus report card */}
            <motion.div
              className="hero-right"
              initial={{ opacity: 0, x: 24 }}
              animate={isVisible ? { opacity: 1, x: 0 } : {}}
              transition={{ duration: 0.6, delay: 0.15, ease: [0.22, 1, 0.36, 1] }}
            >
              <HeroOrbitalCarousel />
            </motion.div>
          </div>

          {/* Stats bar — above scroll cue */}
          <motion.div
            className="stats-bar"
            initial={{ opacity: 0, y: 20 }}
            animate={isVisible ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.5, delay: 0.5, ease: [0.22, 1, 0.36, 1] }}
          >
            <div className="stat-item">
              <span className="stat-value live">
                <span className="live-dot" aria-hidden="true" />
                FREE
              </span>
              <span className="stat-label">PUBLIC SCANS</span>
            </div>
            <div className="stat-divider" />
            <div className="stat-item">
              <span className="stat-value">
                <span className="stat-value-number">100+</span>
              </span>
              <span className="stat-label">Security rules</span>
            </div>
            <div className="stat-divider" />
            <div className="stat-item">
              <span className="stat-value">&lt;&nbsp;60s</span>
              <span className="stat-label">Scan time</span>
            </div>
            <div className="stat-divider" />
            <div className="stat-item">
              <span className="stat-value live" data-stat="extensions-scanned">
                <span className="live-dot" aria-hidden="true" />
                <span className="stat-value-number">{displayCount.toLocaleString()}+</span>
              </span>
              <span className="stat-label">Extensions scanned</span>
            </div>
          </motion.div>

          {/* Scroll Cue */}
          <motion.button
            type="button"
            className="scroll-cue"
            onClick={scrollToProof}
            initial={{ opacity: 0 }}
            animate={isVisible ? { opacity: 1 } : {}}
            transition={{ delay: 0.8, duration: 0.4 }}
            aria-label="Scroll to see how extensions can turn risky"
          >
            <span>See how extensions can turn risky</span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
              <path d="M12 5v14M5 12l7 7 7-7" />
            </svg>
          </motion.button>
          </div>

          <DemoModal
            isOpen={demoModalOpen}
            onClose={() => setDemoModalOpen(false)}
            triggerRef={demoTriggerRef}
          />
          <UploadModal
            isOpen={uploadModalOpen}
            onClose={() => setUploadModalOpen(false)}
          />
        </section>

        {/* Combined dev + open-core section: left copy, right pipeline */}
        <DevOpenCoreSection reducedMotion={reducedMotion} />

      {/* How we protect you – animated timeline (scroll-triggered, reduced-motion aware) */}
      <HowWeProtectYouSection />

      {/* Honey Case Study Section – scroll-reveal for landing consistency */}
      <section className="honey-case-study">
        <motion.div
          className="case-study-container"
          initial={reducedMotion ? false : { opacity: 0, y: 20 }}
          whileInView={reducedMotion ? {} : { opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.12 }}
          transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
        >
          {/* Header */}
          <div className="case-study-header">
            <span className="case-study-badge">CASE STUDY</span>
            <h2 className="case-study-title">
              Honey Extension Case Study
              <span className="subtitle">17M+ users reported. $4B acquisition.</span>
            </h2>
          </div>

          {/* Main Content Grid: content left, honey icon section right (match site layout) */}
          <div className="case-study-content">
            {/* Left: Case study content */}
            <div className="scam-details">
              <div className="scam-intro">
                <p>
                  Promised savings. Investigators reported <strong>commission diversion</strong> and <strong>alleged worse deals</strong>.
                </p>
              </div>

              <div className="scam-points">
                <div className="scam-point">
                  <div className="point-icon theft">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <circle cx="12" cy="12" r="10" />
                      <path d="M12 8v4M12 16h.01" />
                    </svg>
                  </div>
                  <div className="point-content">
                    <h4>Affiliate Link Hijacking</h4>
                    <p>Investigators found silent overwriting of creator affiliate codes. Creators reported lost commissions.</p>
                  </div>
                </div>

                <div className="scam-point">
                  <div className="point-icon data">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                      <circle cx="12" cy="12" r="3" />
                    </svg>
                  </div>
                  <div className="point-content">
                    <h4>Shopping Surveillance</h4>
                    <p>Investigators reported tracking of views, carts, and purchases. Data reportedly shared with retailers.</p>
                  </div>
                </div>

                <div className="scam-point">
                  <div className="point-icon fake">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M18 6L6 18M6 6l12 12" />
                    </svg>
                  </div>
                  <div className="point-content">
                    <h4>Disputed "Best" Coupons</h4>
                    <p>Users reported finding better deals publicly. The coupon animation was questioned by investigators.</p>
                  </div>
                </div>

                <div className="scam-point">
                  <div className="point-icon money">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <line x1="12" y1="1" x2="12" y2="23" />
                      <path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6" />
                    </svg>
                  </div>
                  <div className="point-content">
                    <h4>Retailer Kickbacks</h4>
                    <p>Investigators reported payments to prioritize certain deals. Users disputed whether they received the best available price.</p>
                  </div>
                </div>
              </div>

              <Link to="/research/case-studies" className="scam-footer scam-footer-link">
                <div className="exposed-by">
                  <span>Exposed by</span>
                  <strong>MegaLag</strong>
                  <span className="date">• December 2024</span>
                </div>
                <span className="scam-footer-read-more">
                  <span>Read case study</span>
                  <ArrowRight size={16} strokeWidth={2} aria-hidden />
                </span>
              </Link>
            </div>

            {/* Right: Honey Icon section */}
            <div className="honey-icon-section">
              <div className="honey-icon-wrapper">
                {/* Honey Logo - Hexagon with honeycomb pattern */}
                <div className="honey-logo">
                  <svg viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
                    {/* Hexagon background */}
                    <path 
                      d="M50 5L93.3 27.5V72.5L50 95L6.7 72.5V27.5L50 5Z" 
                      fill="url(#honeyGradient)" 
                      stroke="url(#honeyStroke)"
                      strokeWidth="2"
                    />
                    {/* Honeycomb cells */}
                    <path d="M50 30L62 38V54L50 62L38 54V38L50 30Z" fill="rgba(255,255,255,0.15)" />
                    <path d="M35 45L47 53V69L35 77L23 69V53L35 45Z" fill="rgba(255,255,255,0.1)" />
                    <path d="M65 45L77 53V69L65 77L53 69V53L65 45Z" fill="rgba(255,255,255,0.1)" />
                    {/* Letter H */}
                    <text x="50" y="58" textAnchor="middle" fill="white" fontSize="28" fontWeight="bold" fontFamily="Arial">h</text>
                    <defs>
                      <linearGradient id="honeyGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" stopColor="#FF9500" />
                        <stop offset="50%" stopColor="#FF6B00" />
                        <stop offset="100%" stopColor="#E85D04" />
                      </linearGradient>
                      <linearGradient id="honeyStroke" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" stopColor="#FFB347" />
                        <stop offset="100%" stopColor="#FF8C00" />
                      </linearGradient>
                    </defs>
                  </svg>
                </div>
                
                {/* Warning badge */}
                <div className="warning-badge">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                    <line x1="12" y1="9" x2="12" y2="13" />
                    <line x1="12" y1="17" x2="12.01" y2="17" />
                  </svg>
                </div>
              </div>
              
              <div className="honey-stats">
                <div className="honey-stat">
                  <span className="stat-number">17M+</span>
                  <span className="stat-desc">Reported Users</span>
                </div>
                <div className="honey-stat">
                  <span className="stat-number">$4B</span>
                  <span className="stat-desc">Acquisition</span>
                </div>
                <div className="honey-stat">
                  <span className="stat-number danger">—</span>
                  <span className="stat-desc">Savings Not Guaranteed</span>
                </div>
              </div>
            </div>
          </div>
        </motion.div>
      </section>
      </div>
    </>
  );
};

export default HomePage;
