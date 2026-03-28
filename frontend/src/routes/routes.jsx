import React from "react";
import { Navigate, useParams } from "react-router-dom";
import GlossaryPage from "../pages/GlossaryPage";

// Lazy load pages for better code splitting
const HomePage = React.lazy(() => import("../pages/HomePage"));
const ScannerPage = React.lazy(() => import("../pages/scanner/ScannerPage"));
const ScanUploadPage = React.lazy(() => import("../pages/scanner/ScanUploadPage"));
const ScanProgressPage = React.lazy(() => import("../pages/scanner/ScanProgressPage"));
const ScanResultsPageV2 = React.lazy(() => import("../pages/scanner/ScanResultsPageV2"));
const ScanHistoryPage = React.lazy(() => import("../pages/ScanHistoryPage"));
const EnterprisePage = React.lazy(() => import("../pages/EnterprisePage"));
const SettingsPage = React.lazy(() => import("../pages/SettingsPage"));
const PrivacyPolicyPage = React.lazy(() => import("../pages/PrivacyPolicyPage"));
const AuthCallbackPage = React.lazy(() => import("../pages/auth/AuthCallbackPage"));
const AuthDiagnosticsPage = React.lazy(() => import("../pages/auth/AuthDiagnosticsPage"));

// Research Pages
const ResearchPage = React.lazy(() => import("../pages/research/ResearchPage"));
const MethodologyPage = React.lazy(() => import("../pages/research/MethodologyPage"));
const CaseStudiesPage = React.lazy(() => import("../pages/research/CaseStudiesPage"));
const HoneyCaseStudyPage = React.lazy(() => import("../pages/research/HoneyCaseStudyPage"));
const PdfConvertersCaseStudyPage = React.lazy(() => import("../pages/research/PdfConvertersCaseStudyPage"));
const FakeAdBlockersCaseStudyPage = React.lazy(() => import("../pages/research/FakeAdBlockersCaseStudyPage"));
const BenchmarksPage = React.lazy(() => import("../pages/research/BenchmarksPage"));

// GSoC / Open Source Pages
const GSoCIdeasPage = React.lazy(() => import("../pages/gsoc/GSoCIdeasPage"));
const ContributePage = React.lazy(() => import("../pages/gsoc/ContributePage"));
const CommunityLandingPage = React.lazy(() => import("../pages/community/CommunityLandingPage"));
const OpenSourcePage = React.lazy(() => import("../pages/open-source/OpenSourcePage"));
const OpenSourceProgramsPage = React.lazy(() => import("../pages/open-source/OpenSourceProgramsPage"));
const AboutUsPage = React.lazy(() => import("../pages/AboutUsPage"));

// Compare pages (SEO: best scanner, CRXcavator alternatives)
const CompareIndexPage = React.lazy(() => import("../pages/compare/CompareIndexPage"));
const CompareCrxcavatorPage = React.lazy(() => import("../pages/compare/CompareCrxcavatorPage"));
const CompareCrxplorerPage = React.lazy(() => import("../pages/compare/CompareCrxplorerPage"));
const CompareExtensionAuditorPage = React.lazy(() => import("../pages/compare/CompareExtensionAuditorPage"));

// SEO keyword landing pages (high-intent) + educational hub
const IsThisChromeExtensionSafePage = React.lazy(() => import("../pages/landing/IsThisChromeExtensionSafePage"));
const ChromeExtensionPermissionsPage = React.lazy(() => import("../pages/landing/ChromeExtensionPermissionsPage"));
const ChromeExtensionSecurityScannerPage = React.lazy(() => import("../pages/landing/ChromeExtensionSecurityScannerPage"));
const BrowserExtensionRiskAssessmentPage = React.lazy(() => import("../pages/landing/BrowserExtensionRiskAssessmentPage"));
const CrxcavatorAlternativePage = React.lazy(() => import("../pages/landing/CrxcavatorAlternativePage"));

// Blog (SEO long-tail)
const BlogIndexPage = React.lazy(() => import("../pages/blog/BlogIndexPage"));
const BlogPostPage = React.lazy(() => import("../pages/blog/BlogPostPage"));

// Careers
const CareersPage = React.lazy(() => import("../pages/careers/CareersPage"));
const CareersApplyPage = React.lazy(() => import("../pages/careers/CareersApplyPage"));

// Redirect /extension/:id to /scan/results/:id (extension route removed)
const RedirectExtensionToScanResults = () => {
  const { extensionId } = useParams();
  return <Navigate to={`/scan/results/${encodeURIComponent(extensionId || "")}`} replace />;
};

// Report detail (individual report view)
const ReportDetailPage = React.lazy(() => import("../pages/reports/ReportDetailPage"));

// Dev / Debug (not in nav)
const ThemeDebugPage = React.lazy(() => import("../pages/debug/ThemeDebugPage"));

/**
 * Route Configuration
 * 
 * Each route object can have:
 * - path: string (required)
 * - element: React component (required)
 * - seo: { title, description, canonical } (optional, for sitemap generation)
 * - priority: number 0-1 (optional, for sitemap)
 * - changefreq: string (optional, for sitemap)
 */
export const routes = [
  // ============ CORE ROUTES ============
  {
    path: "/",
    element: <HomePage />,
    seo: {
      title: "Free Chrome Extension Scanner & Security Audit | ExtensionShield",
      description: "Free Chrome extension scanner and security audit for developers. Scan any extension by URL—get risk score, permissions & malware check. Audit CRX/ZIP builds before release.",
      canonical: "/"
    },
    priority: 1.0,
    changefreq: "weekly"
  },

  // ============ SCAN ROUTES ============
  {
    path: "/scan",
    element: <ScannerPage />,
    seo: {
      title: "Is This Chrome Extension Safe? Free Extension Risk Check | ExtensionShield",
      description: "Free extension risk check by Chrome Web Store URL. Get risk score, permissions, privacy and governance signals. See if a Chrome extension is safe before you install.",
      canonical: "/scan"
    },
    priority: 0.9,
    changefreq: "weekly"
  },
  {
    path: "/scan/upload",
    element: <ScanUploadPage />,
    seo: {
      title: "Chrome Extension Security Audit (CRX/ZIP) — Pre-release Build Scan (Pro) | ExtensionShield",
      description: "Private CRX/ZIP upload for pre-release Chrome extension security audit. Vulnerabilities, evidence per finding, fix guidance. SAST, permissions, policy checks. Private by default.",
      canonical: "/scan/upload"
    },
    priority: 0.8,
    changefreq: "weekly"
  },
  {
    path: "/scan/history",
    element: <ScanHistoryPage />,
    seo: {
      title: "Chrome Extension Scan History | ExtensionShield",
      description: "View your Chrome extension scan history and past security reports. Track extension risk assessments and security audits.",
      canonical: "/scan/history"
    },
    priority: 0.7,
    changefreq: "weekly"
  },
  {
    path: "/scan/progress/:scanId",
    element: <ScanProgressPage />
  },
  {
    path: "/scan/results/:scanId",
    element: <ScanResultsPageV2 />
  },

  // /extension/:id → scan results (backward compatibility)
  {
    path: "/extension/:extensionId",
    element: <RedirectExtensionToScanResults />
  },
  {
    path: "/extension/:extensionId/version/:buildHash",
    element: <RedirectExtensionToScanResults />
  },

  // ============ RESEARCH ROUTES ============
  {
    path: "/research",
    element: <ResearchPage />,
    seo: {
      title: "Extension Threat Research & Case Studies | ExtensionShield",
      description: "In-depth security research on Chrome extension threats, malware analysis, and case studies.",
      canonical: "/research"
    },
    priority: 0.8,
    changefreq: "weekly"
  },
  {
    path: "/research/case-studies",
    element: <CaseStudiesPage />,
    seo: {
      title: "Extension Security Case Studies | ExtensionShield",
      description: "Real-world case studies of malicious Chrome extensions.",
      canonical: "/research/case-studies"
    },
    priority: 0.8,
    changefreq: "weekly"
  },
  {
    path: "/research/case-studies/honey",
    element: <HoneyCaseStudyPage />,
    seo: {
      title: "Honey Extension Case Study | ExtensionShield",
      description: "Reported analysis of PayPal's Honey extension: alleged affiliate link hijacking, shopping tracking, and disputed savings claims.",
      canonical: "/research/case-studies/honey"
    },
    priority: 0.7,
    changefreq: "monthly"
  },
  {
    path: "/research/case-studies/pdf-converters",
    element: <PdfConvertersCaseStudyPage />,
    seo: {
      title: "PDF Converter Extensions Data Harvesting Case Study | ExtensionShield",
      description: "Chrome extension security case study: malicious PDF converter extensions that harvest document contents and user data. Enterprise extension risk.",
      canonical: "/research/case-studies/pdf-converters"
    },
    priority: 0.7,
    changefreq: "monthly"
  },
  {
    path: "/research/case-studies/fake-ad-blockers",
    element: <FakeAdBlockersCaseStudyPage />,
    seo: {
      title: "Fake Ad Blocker Extensions Case Study | ExtensionShield",
      description: "Chrome extension malware case study: fake ad blockers that inject ads. 20M–80M+ users affected. Extension security research for enterprises.",
      canonical: "/research/case-studies/fake-ad-blockers"
    },
    priority: 0.7,
    changefreq: "monthly"
  },
  {
    path: "/research/methodology",
    element: <MethodologyPage />,
    seo: {
      title: "Chrome Extension Risk Score & Security Analysis Methodology | ExtensionShield",
      description: "How we calculate chrome extension risk score: static analysis, threat intelligence, and extension security analysis. Transparent methodology for auditing chrome extension security.",
      canonical: "/research/methodology"
    },
    priority: 0.7,
    changefreq: "monthly"
  },
  {
    path: "/research/benchmarks",
    element: <BenchmarksPage />,
    seo: {
      title: "Benchmarks & Industry Trends | ExtensionShield",
      description: "Transparent metrics: coverage, disagreement, speed, and governance/privacy signals. Open, reproducible comparisons across scanners.",
      canonical: "/research/benchmarks"
    },
    priority: 0.7,
    changefreq: "monthly"
  },

  // ============ SEO KEYWORD LANDING PAGES + EDUCATIONAL HUB ============
  {
    path: "/is-this-chrome-extension-safe",
    element: <IsThisChromeExtensionSafePage />,
    seo: {
      title: "Is This Chrome Extension Safe? | ExtensionShield",
      description: "How to tell if a Chrome extension is safe: check permissions, network access, and updates. A simple guide and free scanner to see risk before you install.",
      canonical: "/is-this-chrome-extension-safe"
    },
    priority: 0.9,
    changefreq: "monthly"
  },
  {
    path: "/chrome-extension-permissions",
    element: <ChromeExtensionPermissionsPage />,
    seo: {
      title: "Chrome Extension Permissions Explained | What to Allow | ExtensionShield",
      description: "Understand Chrome extension permissions: which are risky, red flags to watch, and how to review before you install. Plus a free scanner to check any extension.",
      canonical: "/chrome-extension-permissions"
    },
    priority: 0.85,
    changefreq: "monthly"
  },
  {
    path: "/chrome-extension-security-scanner",
    element: <ChromeExtensionSecurityScannerPage />,
    seo: {
      title: "Chrome Extension Security Scanner | Free Scan & Risk Score | ExtensionShield",
      description: "Free Chrome extension scanner and security audit. Scan any extension for malware, risk score, permissions & threats in under 60 seconds. For developers: audit extensions before release.",
      canonical: "/chrome-extension-security-scanner"
    },
    priority: 0.85,
    changefreq: "monthly"
  },
  {
    path: "/browser-extension-risk-assessment",
    element: <BrowserExtensionRiskAssessmentPage />,
    seo: {
      title: "Browser Extension Risk Assessment | Enterprise Extension Security | ExtensionShield",
      description: "Browser extension risk assessment for enterprises: govern extensions, enforce allowlists, and get audit-ready reports. Extension security and compliance monitoring at scale.",
      canonical: "/browser-extension-risk-assessment"
    },
    priority: 0.8,
    changefreq: "monthly"
  },
  {
    path: "/crxcavator-alternative",
    element: <CrxcavatorAlternativePage />,
    seo: {
      title: "CRXcavator Alternative | Chrome Extension Risk Score & Security | ExtensionShield",
      description: "Looking for a CRXcavator alternative? ExtensionShield offers transparent chrome extension risk scoring, SAST, VirusTotal, and governance. Compare features and try free scans.",
      canonical: "/crxcavator-alternative"
    },
    priority: 0.8,
    changefreq: "monthly"
  },

  // ============ COMPARE ROUTES (SEO: best scanner, alternatives) ============
  {
    path: "/compare",
    element: <CompareIndexPage />,
    seo: {
      title: "Best Chrome Extension Security Scanner | CRXcavator Alternatives",
      description: "Compare the best chrome extension security scanner tools. ExtensionShield vs CRXcavator, CRXplorer, ExtensionAuditor. Chrome extension risk score tool with security, privacy, and governance.",
      canonical: "/compare"
    },
    priority: 0.8,
    changefreq: "monthly"
  },
  {
    path: "/compare/crxcavator",
    element: <CompareCrxcavatorPage />,
    seo: {
      title: "ExtensionShield vs CRXcavator | Best CRXcavator Alternative",
      description: "Compare ExtensionShield vs CRXcavator: chrome extension risk score, security audit, and governance. CRXcavator alternatives with transparent scoring and enterprise extension security.",
      canonical: "/compare/crxcavator"
    },
    priority: 0.7,
    changefreq: "monthly"
  },
  {
    path: "/compare/crxplorer",
    element: <CompareCrxplorerPage />,
    seo: {
      title: "ExtensionShield vs CRXplorer | Chrome Extension Security Scanner Comparison",
      description: "ExtensionShield vs CRXplorer: compare chrome extension security scanners. Transparent risk score, SAST, VirusTotal, and extension governance vs AI-only scoring.",
      canonical: "/compare/crxplorer"
    },
    priority: 0.7,
    changefreq: "monthly"
  },
  {
    path: "/compare/extension-auditor",
    element: <CompareExtensionAuditorPage />,
    seo: {
      title: "ExtensionShield vs ExtensionAuditor | Chrome Extension Security Comparison",
      description: "ExtensionShield vs ExtensionAuditor: compare chrome extension security scanners. Risk score, permissions checker, governance, and audit chrome extension security for enterprise.",
      canonical: "/compare/extension-auditor"
    },
    priority: 0.7,
    changefreq: "monthly"
  },

  // ============ CAREERS ROUTES ============
  {
    path: "/careers",
    element: <CareersPage />,
    seo: {
      title: "Careers | ExtensionShield",
      description: "Join ExtensionShield. We're building the security, privacy, and governance layer for browser extensions. View open roles and apply.",
      canonical: "/careers"
    },
    priority: 0.75,
    changefreq: "monthly"
  },
  {
    path: "/careers/apply",
    element: <CareersApplyPage />,
    seo: {
      title: "Apply | Careers | ExtensionShield",
      description: "Apply to join ExtensionShield. Submit your application for open engineering and security roles.",
      canonical: "/careers/apply"
    },
    priority: 0.6,
    changefreq: "monthly"
  },
  // ============ BLOG ROUTES (SEO long-tail) ============
  {
    path: "/blog",
    element: <BlogIndexPage />,
    seo: {
      title: "Chrome Extension Security Blog | How to Audit & Check Extension Safety",
      description: "How to check chrome extension permissions safely, detect malicious chrome extensions, and audit a chrome extension before installing. Extension security research and guides.",
      canonical: "/blog"
    },
    priority: 0.75,
    changefreq: "weekly"
  },
  {
    path: "/blog/how-to-check-chrome-extension-permissions",
    element: <Navigate to="/chrome-extension-permissions" replace />,
  },
  {
    path: "/blog/how-to-audit-chrome-extension-before-installing",
    element: <BlogPostPage />,
    seo: {
      title: "How to Audit a Chrome Extension Before Installing | ExtensionShield",
      description: "Step-by-step guide to audit a chrome extension before installing: permissions, risk score, and how to check if a Chrome extension is safe using a browser extension security scanner.",
      canonical: "/blog/how-to-audit-chrome-extension-before-installing"
    },
    priority: 0.6,
    changefreq: "monthly"
  },
  {
    path: "/blog/enterprise-browser-extension-risk-management",
    element: <BlogPostPage />,
    seo: {
      title: "Enterprise Browser Extension Risk Management | ExtensionShield",
      description: "How to run a browser extension risk management program: allowlist policy, compliance monitoring, shadow IT browser extensions, and chrome enterprise extension security.",
      canonical: "/blog/enterprise-browser-extension-risk-management"
    },
    priority: 0.6,
    changefreq: "monthly"
  },
  {
    path: "/blog/how-to-detect-malicious-chrome-extensions",
    element: <BlogPostPage />,
    seo: {
      title: "How to Detect Malicious Chrome Extensions | ExtensionShield",
      description: "Signs of malicious chrome extensions, browser extension spyware, and how to detect data exfiltration and extension hijacking. Use a chrome extension security scanner to check if an extension is safe.",
      canonical: "/blog/how-to-detect-malicious-chrome-extensions"
    },
    priority: 0.6,
    changefreq: "monthly"
  },

  // ============ ENTERPRISE ROUTES ============
  {
    path: "/enterprise",
    element: <EnterprisePage />,
    seo: {
      title: "Browser Extension Risk Assessment & Governance (Allowlist, Monitoring) | ExtensionShield",
      description: "Extension governance: allowlist policies, monitoring, audit exports. Browser extension risk assessment for enterprise. Manage Chrome extensions at scale.",
      canonical: "/enterprise"
    },
    priority: 0.8,
    changefreq: "monthly"
  },

  // ============ OPEN SOURCE / GSOC ROUTES ============
  {
    path: "/about",
    element: <AboutUsPage />,
    seo: {
      title: "About Us | ExtensionShield",
      description: "Learn about ExtensionShield's founder, Stanzin, and why this project was created to help users understand browser extension security.",
      canonical: "/about"
    },
    priority: 0.7,
    changefreq: "monthly"
  },
  {
    path: "/open-source/programs",
    element: <OpenSourceProgramsPage />,
    seo: {
      title: "Open Source Programs | ExtensionShield",
      description: "Open source programs ExtensionShield has applied to: Google Summer of Code and more. Explore project ideas and contribution opportunities.",
      canonical: "/open-source/programs"
    },
    priority: 0.7,
    changefreq: "monthly"
  },
  {
    path: "/open-source",
    element: <OpenSourcePage />,
    seo: {
      title: "Open Source | ExtensionShield",
      description: "ExtensionShield is open source. Explore our GitHub, contribute code, or join our GSoC program.",
      canonical: "/open-source"
    },
    priority: 0.7,
    changefreq: "monthly"
  },
  {
    path: "/community",
    element: <CommunityLandingPage />,
    seo: {
      title: "Community | ExtensionShield",
      description: "Join the ExtensionShield community: connect with contributors, run scans, earn karma, and help make the web safer for everyone.",
      canonical: "/community"
    },
    priority: 0.7,
    changefreq: "monthly"
  },
  {
    path: "/open-source/gsoc",
    element: <Navigate to="/gsoc/ideas" replace />
  },
  {
    path: "/gsoc/ideas",
    element: <GSoCIdeasPage />,
    seo: {
      title: "Google Summer of Code Ideas | ExtensionShield",
      description: "GSoC project ideas: Help build open-source tools that scan Chrome extensions for risky behavior and empower community-driven security.",
      canonical: "/gsoc/ideas"
    },
    priority: 0.7,
    changefreq: "monthly"
  },
  {
    path: "/contribute",
    element: <ContributePage />,
    seo: {
      title: "Everyone Can Contribute | ExtensionShield",
      description: "Help build a safer web. Scan extensions, report threats, help others—every contribution matters, no coding required.",
      canonical: "/contribute"
    },
    priority: 0.6,
    changefreq: "monthly"
  },
  {
    path: "/gsoc/community",
    element: <Navigate to="/community" replace />
  },
  // ============ REPORTS ============
  {
    path: "/reports",
    element: <Navigate to="/scan/history" replace />
  },
  {
    path: "/reports/:reportId",
    element: <ReportDetailPage />
  },

  // ============ AUTHENTICATION ============
  {
    path: "/auth/callback",
    element: <AuthCallbackPage />
  },
  {
    path: "/auth/diagnostics",
    element: <AuthDiagnosticsPage />
  },

  // ============ SETTINGS ============
  {
    path: "/settings",
    element: <SettingsPage />
  },
  {
    path: "/privacy-policy",
    element: <PrivacyPolicyPage />,
    seo: {
      title: "Privacy Policy | ExtensionShield",
      description: "ExtensionShield Privacy Policy - Learn how we collect, use, and protect your data.",
      canonical: "/privacy-policy"
    },
    priority: 0.5,
    changefreq: "monthly"
  },
  {
    path: "/glossary",
    element: <GlossaryPage />,
    seo: {
      title: "Chrome Extension Permissions & Security Glossary | ExtensionShield",
      description: "Chrome extension permissions checker guide: what permissions are dangerous, MV3, content security policy, web accessible resources, and extension risk assessment terms.",
      canonical: "/glossary"
    },
    priority: 0.7,
    changefreq: "monthly"
  },

  // Old URL redirects
  {
    path: "/scanner",
    element: <Navigate to="/scan" replace />
  },
  {
    path: "/scanner/progress/:scanId",
    element: <Navigate to="/scan/progress/:scanId" replace />
  },
  {
    path: "/scanner/results/:scanId",
    element: <Navigate to="/scan/results/:scanId" replace />
  },
  {
    path: "/history",
    element: <Navigate to="/scan/history" replace />
  },
  {
    path: "/dashboard",
    element: <Navigate to="/scan" replace />
  },
  {
    path: "/scan-history",
    element: <Navigate to="/scan/history" replace />
  },
  {
    path: "/sample-report",
    element: <Navigate to="/research/case-studies/honey" replace />
  },
  {
    path: "/analysis",
    element: <Navigate to="/scan" replace />
  },

  // ============ DEBUG (dev only) ============
  {
    path: "/debug/theme",
    element: <ThemeDebugPage />
  },

  // ============ CATCH-ALL ============
  {
    path: "*",
    element: <Navigate to="/" replace />
  }
];

/**
 * Get all routes that should be in the sitemap
 * Excludes dynamic routes, redirects, and non-SEO routes
 */
export const getSitemapRoutes = () => {
  return routes.filter(route => 
    route.seo && 
    !route.path.includes(":") && 
    !route.path.includes("*")
  );
};

export default routes;

