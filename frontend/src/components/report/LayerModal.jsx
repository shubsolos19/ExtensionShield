import React from 'react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '../ui/dialog';
import { CheckCircle, AlertCircle, Info } from 'lucide-react';
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

const CATEGORY_LABELS = {
  code:   'Code Checks',
  threat: 'Threat Detection',
  trust:  'Trust Signals',
  access: 'Permissions',
  data:   'Data Handling',
  policy: 'Policies',
};

const LAYER_CONFIG = {
  security: {
    title: 'Security',
    icon: '🛡️',
  },
  privacy: {
    title: 'Privacy',
    icon: '🔒',
  },
  governance: {
    title: 'Governance',
    icon: '📋',
  },
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

export function humanizeFactor(factor) {
  const info = FACTOR_HUMAN[factor.name] || {
    label: factor.name,
    category: 'other',
    desc: '',
  };
  const severity = factor.severity ?? 0;
  let status, statusType;
  if (severity >= 0.4) {
    status = 'Issue';
    statusType = 'issues';
  } else if (isNotAnalyzed(factor)) {
    status = 'Not analyzed';
    statusType = 'unknown';
  } else {
    status = 'Clear';
    statusType = 'clear';
  }
  return { ...info, status, statusType, severity, raw: factor };
}

function groupByCategory(items) {
  const groups = {};
  items.forEach(item => {
    const cat = item.category || 'other';
    if (!groups[cat]) groups[cat] = [];
    groups[cat].push(item);
  });
  Object.values(groups).forEach(g => g.sort((a, b) => b.severity - a.severity));
  return Object.entries(groups)
    .sort(([, a], [, b]) => Math.max(...b.map(x => x.severity)) - Math.max(...a.map(x => x.severity)));
}

function bandLabel(band) {
  switch (band) {
    case 'GOOD': return 'Safe';
    case 'WARN': return 'Needs Review';
    case 'BAD':  return 'Not Safe';
    default:     return '';
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

const LayerModal = ({
  open,
  onClose,
  layer,
  score = null,
  band = 'NA',
  factors = [],
  // eslint-disable-next-line no-unused-vars
  keyFindings = [],
  // eslint-disable-next-line no-unused-vars
  gateResults = [],
  // eslint-disable-next-line no-unused-vars
  layerReasons = [],
  layerDetails = null,
  // eslint-disable-next-line no-unused-vars
  onViewEvidence = null,
}) => {
  const config = LAYER_CONFIG[layer] || LAYER_CONFIG.security;

  const humanised = factors.map(humanizeFactor);
  const grouped = groupByCategory(humanised);

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="lm-content lm-dialog-smooth" aria-describedby="lm-checks" aria-label={`${config.title} details`} data-layer={layer}>
        <DialogHeader className="lm-header-wrap">
          <DialogTitle className="lm-header">
            <div className="lm-header-inner">
              <div className="lm-header-left">
                <span className="lm-icon" aria-hidden>{config.icon}</span>
                <span className="lm-title">{config.title}</span>
              </div>
            </div>
          </DialogTitle>
        </DialogHeader>

        <div className="lm-body" id="lm-checks">
          {grouped.length > 0 && (
            <div className="lm-checks" role="list" aria-label={`${config.title} checks`}>
              {grouped.map(([cat, items], catIdx) => (
                <div key={cat} className="lm-group" style={{ animationDelay: `${catIdx * 40}ms` }} role="group" aria-label={CATEGORY_LABELS[cat] || cat}>
                  <span className="lm-group-label">{CATEGORY_LABELS[cat] || cat}</span>
                  <div className="lm-group-items">
                    {items.map((item, idx) => (
                      <div
                        key={idx}
                        className={`lm-check-card lm-check-${item.statusType}`}
                        style={{ animationDelay: `${(catIdx * 40 + (idx + 1) * 25)}ms` }}
                        role="listitem"
                      >
                        <div className="lm-check-left">
                          <span className="lm-check-name">{item.label}</span>
                          {item.desc && <InfoTooltip text={item.desc} />}
                        </div>
                        <span className="lm-status-wrap">
                          {item.statusType === 'clear' ? (
                            <CheckCircle className="lm-status-icon" size={14} strokeWidth={2} aria-hidden />
                          ) : item.statusType === 'unknown' ? (
                            <Info className="lm-status-icon" size={14} strokeWidth={2} aria-hidden />
                          ) : (
                            <AlertCircle className="lm-status-icon" size={14} strokeWidth={2} aria-hidden />
                          )}
                          <span className={`lm-status lm-status-${item.statusType}`}>
                            {item.status}
                          </span>
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default LayerModal;
