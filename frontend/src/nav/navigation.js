/**
 * Navigation: top nav, mega menu, footer.
 * Logo links to "/", so a separate Home item is omitted.
 * Categories: Product, Research (includes Resources section), Enterprise.
 */
export const NAV_CATEGORIES = {
  PRODUCT: "Product",
  RESEARCH: "Research",
  ENTERPRISE: "Enterprise",
  RESOURCES: "Resources",
};

export const topNavItems = [
  {
    category: NAV_CATEGORIES.PRODUCT,
    label: "Scan",
    path: "/scan",
    matchPaths: ["/scan"],
    dropdownItems: [
      {
        icon: "🔍",
        label: "Risk Check (Free)",
        description: "Chrome Web Store URL",
        path: "/scan"
      },
      {
        icon: "📦",
        label: "Private Build Audit (Pro)",
        description: "Upload CRX/ZIP for pre-release audit",
        path: "/scan/upload",
        badge: "PRO"
      },
      {
        icon: "🕐",
        label: "Scan History",
        description: "Your past scans",
        path: "/scan/history"
      }
    ]
  },
  {
    category: NAV_CATEGORIES.RESEARCH,
    label: "Research",
    path: "/research",
    matchPaths: ["/research", "/compare", "/open-source", "/community", "/about", "/careers"],
    dropdownSections: [
      {
        heading: "Research",
        items: [
          { icon: "📋", label: "Case Studies", description: "Real-world analysis", path: "/research/case-studies" },
          { icon: "⚙️", label: "How We Score", description: "How we score risk", path: "/research/methodology" },
          { icon: "benchmarks", label: "Benchmarks", description: "Industry trends & scoring", path: "/research/benchmarks" },
          { icon: "compare", label: "Compare Scanners", description: "ExtensionShield vs alternatives", path: "/compare" }
        ]
      },
      {
        heading: "Resources",
        items: [
          { icon: "🌱", label: "Open Source", description: "Contribute & explore", path: "/open-source" },
          { icon: "💬", label: "Community", description: "Safety notes & alternatives", path: "/community" },
          { icon: "💼", label: "Careers", description: "Join the team", path: "/careers" },
          { icon: "👤", label: "About", description: "Founder's story", path: "/about" }
        ]
      }
    ]
  },
  {
    category: NAV_CATEGORIES.ENTERPRISE,
    label: "Enterprise",
    path: "/enterprise",
    matchPaths: ["/enterprise"],
    dropdownItems: [
      {
        icon: "🏢",
        label: "Governance",
        description: "Org reports & policies",
        path: "/enterprise"
      },
      {
        icon: "📡",
        label: "Monitoring & Alerts",
        description: "Real-time updates",
        path: "/enterprise#monitoring"
      }
    ]
  }
];

/**
 * Build sections for mobile menu: each section has a category label and links.
 * Research includes both Research and Resources links (from dropdownSections).
 */
export function getMobileNavSections() {
  const sections = [];
  topNavItems.forEach((item) => {
    let links;
    if (item.dropdownSections) {
      links = item.dropdownSections.flatMap((s) =>
        s.items.map((i) => ({ label: i.label, path: i.path, external: i.external, href: i.href }))
      );
    } else if (item.dropdownItems) {
      links = item.dropdownItems.map((d) => ({
        label: d.label,
        path: d.path,
        external: d.external,
        href: d.href,
      }));
    } else {
      links = [{ label: item.label, path: item.path }];
    }
    sections.push({ category: item.category, links });
  });
  return sections;
}

/**
 * User Menu Items (authenticated users)
 */
export const userMenuItems = [
  {
    icon: "scan",
    label: "Risk Check",
    path: "/scan"
  },
  {
    icon: "history",
    label: "Scan History",
    path: "/scan/history"
  },
  {
    icon: "settings",
    label: "Settings",
    path: "/settings"
  }
];

/**
 * Footer Configuration
 * Two-column layout: left = brand + disclaimer, right = link groups.
 */
export const footerConfig = {
  disclaimer: "Comprehensive extension governance through security, privacy, and compliance analysis. We aggregate multiple dimensions into a single actionable score. So you can trust the results you find.",
  tagline: "Extension security you can trust.",
  linkGroups: [
    {
      heading: "Product",
      links: [
        { label: "Risk Check (Free)", path: "/scan" },
        { label: "Private Build Audit (Pro)", path: "/scan/upload" },
        { label: "Is extension safe?", path: "/is-this-chrome-extension-safe" },
        { label: "Scan History", path: "/scan/history" }
      ]
    },
    {
      heading: "Research",
      links: [
        { label: "How We Score", path: "/research/methodology" },
        { label: "Case Studies", path: "/research/case-studies" },
        { label: "Compare Scanners", path: "/compare" },
        { label: "Benchmarks", path: "/research/benchmarks" }
      ]
    },
    {
      heading: "Company",
      links: [
        { label: "Enterprise", path: "/enterprise" },
        { label: "Careers", path: "/careers" },
        { label: "Contribute", path: "/contribute" }
      ]
    },
    {
      heading: "Legal & Community",
      links: [
        { label: "Privacy Policy", path: "/privacy-policy" },
        { label: "Community", path: "/community" },
        { label: "Discord", href: "https://discord.gg/mgR4skWB", external: true },
        { label: "GitHub", href: "https://github.com/Stanzin7/ExtensionShield", external: true }
      ]
    }
  ]
};

export default {
  topNavItems,
  userMenuItems,
  footerConfig,
  getMobileNavSections,
  NAV_CATEGORIES,
};

