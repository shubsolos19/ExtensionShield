/**
 * LayerModal status-mapping tests (Phase 1 follow-up).
 *
 * A check whose underlying analysis did not run has no coverage and must read as
 * "Not analyzed", never "Clear" (which overstates certainty). The network/exfil
 * analyzer reports this via details.network_analysis_enabled === false.
 *
 * These exercise the pure status mapping only — no rendering required.
 */
import { describe, it, expect } from 'vitest';
import { humanizeFactor, isNotAnalyzed } from './LayerModal';

describe('LayerModal status mapping', () => {
  it('Data Sharing with no network coverage is "Not analyzed", not "Clear"', () => {
    const factor = {
      name: 'NetworkExfil',
      severity: 0,
      confidence: 0.5,
      details: { network_analysis_enabled: false },
    };
    const result = humanizeFactor(factor);
    expect(result.status).toBe('Not analyzed');
    expect(result.statusType).toBe('unknown');
    expect(result.label).toBe('Data Sharing');
  });

  it('Data Sharing WITH coverage and no findings reads "Clear"', () => {
    const factor = {
      name: 'NetworkExfil',
      severity: 0,
      confidence: 0.7,
      details: { network_analysis_enabled: true, domains_analyzed: 3 },
    };
    const result = humanizeFactor(factor);
    expect(result.status).toBe('Clear');
    expect(result.statusType).toBe('clear');
  });

  it('an actual ISSUE-level finding wins over the not-analyzed flag', () => {
    const factor = {
      name: 'NetworkExfil',
      severity: 0.6,
      details: { network_analysis_enabled: false },
    };
    const result = humanizeFactor(factor);
    expect(result.status).toBe('Issue');
    expect(result.statusType).toBe('issues');
  });

  it('a normal sub-threshold factor without coverage flags is "Clear"', () => {
    const factor = { name: 'CaptureSignals', severity: 0.1, details: {} };
    expect(humanizeFactor(factor).status).toBe('Clear');
  });

  it('isNotAnalyzed only fires on the explicit coverage flag', () => {
    expect(isNotAnalyzed({ details: { network_analysis_enabled: false } })).toBe(true);
    expect(isNotAnalyzed({ details: { network_analysis_enabled: true } })).toBe(false);
    expect(isNotAnalyzed({ details: {} })).toBe(false);
    expect(isNotAnalyzed({})).toBe(false);
  });
});
