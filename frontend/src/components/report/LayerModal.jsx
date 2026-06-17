import React from 'react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '../ui/dialog';
import { AlertTriangle, Check, HelpCircle, Info } from 'lucide-react';
import './LayerModal.scss';

const FACTOR_HUMAN = {
  SAST:                 { label: 'Code Safety',           category: 'code',   desc: 'Scans source code for known vulnerability patterns' },
  VirusTotal:           { label: 'Malware Scan',          category: 'threat', desc: 'Checks against 70+ antivirus engines for malicious code' },
  Obfuscation:          { label: 'Hidden Code',           category: 'code',   desc: 'Detects deliberately obscured or unreadable code' },
  Manifest:             { label: 'Extension Config',      category: 'code',   desc: 'Validates security settings in the extension manifest' },
  ChromeStats:          { label: 'Threat Intel',          category: 'threat', desc: 'Cross-references known threat databases' },
  Webstore:             { label: 'Store Reputation',      category: 'trust',  desc: 'Chrome Web Store ratings and user reviews' },
  Maintenance:          { label: 'Update Freshness',      category: 'trust',  desc: 'How recently the extension was updated by its developer' },
  PermissionsBaseline:  { label: 'Permission Risk',       category: 'access', desc: 'Evaluates the sensitivity of requested browser permissions' },
  PermissionCombos:     { label: 'Dangerous Combos',      category: 'access', desc: 'Flags risky combinations of permissions that enable data theft' },
  NetworkExfil:         { label: 'Data Sharing',          category: 'data',   desc: 'Detects if data is sent to external servers' },
  CaptureSignals:       { label: 'Screen Capture',        category: 'data',   desc: 'Checks for screen or tab recording capabilities' },
  ToSViolations:        { label: 'Policy Violations',     category: 'policy', desc: 'Checks compliance with Chrome Web Store policies' },
  Consistency:          { label: 'Behavior Match',        category: 'policy', desc: 'Compares stated purpose vs actual behavior' },
  DisclosureAlignment:  { label: 'Disclosure Accuracy',   category: 'policy', desc: 'Validates privacy policy against actual data collection' },
};

// Short, sentence-case tags used as a secondary caption on flagged/uncovered rows.
const CATEGORY_TAG = {
  code:   'Code',
  threat: 'Threat',
  trust:  'Trust',
  access: 'Permissions',
  data:   'Data',
  policy: 'Policy',
};

const LAYER_CONFIG = {
  security:   { title: 'Security',   icon: '🛡️' },
  privacy:    { title: 'Privacy',    icon: '🔒' },
  governance: { title: 'Governance', icon: '📋' },
};

/**
 * A check whose underlying analysis did not run has no coverage and must not be
 * shown as "Clear" (that overstates certainty). The network/exfil analyzer
 * reports this via details.network_analysis_enabled === false.
 */
export function isNotAnalyzed(factor) {
  const details = factor?.details;
  if (!details || typeof details !== 'object') return false;
  if (details.network_analysis_enabled === false) return true;
  return false;
}

/**
 * Map a factor to a truthful presentation status:
 *  - issues:  the check ran and found something material (severity >= 0.4).
 *             tone splits high (>= 0.7 -> bad/red) vs moderate (warn/amber).
 *  - unknown: the check could not run -> "Not analyzed" (never "Clear").
 *  - clear:   the check ran and found nothing material.
 */
export function humanizeFactor(factor) {
  const info = FACTOR_HUMAN[factor.name] || {
    label: factor.name,
    category: 'other',
    desc: '',
  };
  const severity = factor.severity ?? 0;
  let status, statusType, tone;
  if (severity >= 0.4) {
    statusType = 'issues';
    tone = severity >= 0.7 ? 'bad' : 'warn';
    status = severity >= 0.7 ? 'High risk' : 'Issue';
  } else if (isNotAnalyzed(factor)) {
    statusType = 'unknown';
    tone = 'neutral';
    status = 'Not analyzed';
  } else {
    statusType = 'clear';
    tone = 'good';
    status = 'Clear';
  }
  return { ...info, status, statusType, tone, severity, raw: factor };
}

/**
 * Triage a layer's factors into severity tiers for display:
 * issues (most severe first) -> not analyzed -> cleared (alphabetical).
 * Keeping this pure makes the "issues first / not-analyzed distinct" ordering testable.
 */
export function triageFactors(factors = []) {
  const humanised = (factors || []).map(humanizeFactor);
  return {
    all: humanised,
    issues: humanised
      .filter((i) => i.statusType === 'issues')
      .sort((a, b) => b.severity - a.severity),
    notAnalyzed: humanised.filter((i) => i.statusType === 'unknown'),
    cleared: humanised
      .filter((i) => i.statusType === 'clear')
      .sort((a, b) => a.label.localeCompare(b.label)),
  };
}

function bandLabel(band) {
  switch (band) {
    case 'GOOD': return 'Safe';
    case 'WARN': return 'Needs review';
    case 'BAD':  return 'Not safe';
    default:     return 'Not rated';
  }
}

function bandToneClass(band) {
  switch (band) {
    case 'GOOD': return 'lm-verdict-good';
    case 'WARN': return 'lm-verdict-warn';
    case 'BAD':  return 'lm-verdict-bad';
    default:     return 'lm-verdict-na';
  }
}

const InfoTooltip = ({ text }) => {
  return (
    <span
      className="lm-info-trigger"
      role="button"
      aria-label="More info"
      tabIndex={0}
    >
      <Info size={13} strokeWidth={2} />
      <span className="lm-info-tooltip" role="tooltip">{text}</span>
    </span>
  );
};

/** Prominent row for a flagged or uncovered check (issues + not-analyzed tiers). */
const PrimaryCheckRow = ({ item, index }) => (
  <div
    className={`lm-check lm-check--${item.statusType} lm-tone-${item.tone}`}
    style={{ animationDelay: `${index * 30}ms` }}
    role="listitem"
  >
    <span className="lm-check-rail" aria-hidden />
    <span className="lm-check-glyph" aria-hidden>
      {item.statusType === 'issues'
        ? <AlertTriangle size={15} strokeWidth={2.25} />
        : <HelpCircle size={15} strokeWidth={2.25} />}
    </span>
    <span className="lm-check-main">
      <span className="lm-check-name">
        {item.label}
        {item.desc && <InfoTooltip text={item.desc} />}
      </span>
      {CATEGORY_TAG[item.category] && (
        <span className="lm-check-tag">{CATEGORY_TAG[item.category]}</span>
      )}
    </span>
    <span className={`lm-check-status lm-status-${item.statusType}`}>{item.status}</span>
  </div>
);

const LayerModal = ({
  open,
  onClose,
  layer,
  // eslint-disable-next-line no-unused-vars
  score = null,
  band = 'NA',
  factors = [],
  // eslint-disable-next-line no-unused-vars
  keyFindings = [],
  // eslint-disable-next-line no-unused-vars
  gateResults = [],
  // eslint-disable-next-line no-unused-vars
  layerReasons = [],
  // eslint-disable-next-line no-unused-vars
  layerDetails = null,
  // eslint-disable-next-line no-unused-vars
  onViewEvidence = null,
}) => {
  const config = LAYER_CONFIG[layer] || LAYER_CONFIG.security;

  // Severity-first triage: what's wrong, then what couldn't be checked, then what's fine.
  const { all, issues, notAnalyzed, cleared } = triageFactors(factors);
  const hasChecks = all.length > 0;

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="lm-content lm-dialog-smooth" aria-describedby="lm-checks" aria-label={`${config.title} details`} data-layer={layer} data-band={band}>
        <DialogHeader className="lm-header-wrap">
          <DialogTitle className="lm-header">
            <div className="lm-header-inner">
              <div className="lm-header-left">
                <span className="lm-icon" aria-hidden>{config.icon}</span>
                <span className="lm-title">{config.title}</span>
              </div>
              <span className={`lm-verdict-pill ${bandToneClass(band)}`}>{bandLabel(band)}</span>
            </div>
          </DialogTitle>
        </DialogHeader>

        <div className="lm-body" id="lm-checks">
          {!hasChecks && (
            <p className="lm-empty">No checks are available for this layer.</p>
          )}

          {issues.length > 0 && (
            <section className="lm-tier lm-tier--issues" aria-label="Issues found">
              <header className="lm-tier-head">
                <span className="lm-tier-title">Issues found</span>
                <span className="lm-tier-count lm-tier-count--issues">{issues.length}</span>
              </header>
              <div className="lm-rows" role="list">
                {issues.map((item, idx) => (
                  <PrimaryCheckRow key={`i-${idx}`} item={item} index={idx} />
                ))}
              </div>
            </section>
          )}

          {notAnalyzed.length > 0 && (
            <section className="lm-tier lm-tier--unknown" aria-label="Not analyzed">
              <header className="lm-tier-head">
                <span className="lm-tier-title">Not analyzed</span>
                <span className="lm-tier-count">{notAnalyzed.length}</span>
              </header>
              <div className="lm-rows" role="list">
                {notAnalyzed.map((item, idx) => (
                  <PrimaryCheckRow key={`u-${idx}`} item={item} index={idx} />
                ))}
              </div>
              <p className="lm-tier-note">Coverage unavailable — treat as unknown, not safe.</p>
            </section>
          )}

          {cleared.length > 0 && (
            <section className="lm-tier lm-tier--clear" aria-label="Checks that passed">
              <header className="lm-tier-head">
                <span className="lm-tier-title">Cleared</span>
                <span className="lm-tier-count">{cleared.length}</span>
              </header>
              <div className="lm-clear-grid" role="list">
                {cleared.map((item, idx) => (
                  <div className="lm-clear-row" key={`c-${idx}`} role="listitem">
                    <Check className="lm-clear-tick" size={13} strokeWidth={2.5} aria-hidden />
                    <span className="lm-clear-name">{item.label}</span>
                    {item.desc && <InfoTooltip text={item.desc} />}
                  </div>
                ))}
              </div>
            </section>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default LayerModal;
