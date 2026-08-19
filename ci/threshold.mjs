/**
 * Decide whether a report should fail the build.
 *
 * Kept pure and separate from anything GitHub-shaped so the policy that gates people's
 * deploys is testable without a runner. This is the part a user is most likely to be
 * surprised by, so it has to be predictable and explainable.
 */

/** Ordered worst-first. A threshold includes everything above it. */
export const SEVERITIES = ['critical', 'high', 'medium', 'low'];

/** `never` disables build-failing entirely; the report is still produced. */
export const THRESHOLDS = [...SEVERITIES, 'never'];

export function parseThreshold(value) {
  const v = String(value ?? 'high').trim().toLowerCase();
  if (!THRESHOLDS.includes(v)) {
    throw new Error(`fail-on must be one of ${THRESHOLDS.join(', ')} (got "${value}")`);
  }
  return v;
}

/** True when `severity` is at least as serious as `threshold`. */
export function meetsThreshold(severity, threshold) {
  if (threshold === 'never') return false;
  const s = SEVERITIES.indexOf(String(severity).toLowerCase());
  const t = SEVERITIES.indexOf(threshold);
  if (s === -1) return false; // 'info' and anything unrecognised never gates a build
  return s <= t;
}

/**
 * @param {{results: CheckResult[], score: number}} report
 * @param {{failOn?: string, warningsAsErrors?: boolean}} opts
 */
export function evaluate(report, opts = {}) {
  const failOn = parseThreshold(opts.failOn);
  const warningsAsErrors = Boolean(opts.warningsAsErrors);

  const failing = report.results.filter(
    (r) => r.status === 'fail' && meetsThreshold(r.severity, failOn)
  );
  const warnings = report.results.filter((r) => r.status === 'warn');
  const blockingWarnings = warningsAsErrors
    ? warnings.filter((r) => meetsThreshold(r.severity, failOn))
    : [];

  const blocking = [...failing, ...blockingWarnings];

  // A check that errored is a broken scan, not a clean site. Never let it read as a pass.
  const errored = report.results.filter((r) => r.status === 'error');

  return {
    failOn,
    blocking,
    errored,
    shouldFail: blocking.length > 0 || errored.length > 0,
    exitCode: blocking.length > 0 || errored.length > 0 ? 1 : 0,
    reason: explain(blocking, errored, failOn, report),
  };
}

function explain(blocking, errored, failOn, report) {
  if (errored.length) {
    return `${errored.length} check(s) failed to run, so the scan is incomplete: ${errored.map((r) => r.id).join(', ')}`;
  }
  if (!blocking.length) {
    return failOn === 'never'
      ? `Score ${report.score}/100. Build-failing is disabled (fail-on: never).`
      : `Score ${report.score}/100. No findings at or above "${failOn}".`;
  }
  const ids = blocking.map((r) => `${r.id} (${r.severity})`).join(', ');
  return `Score ${report.score}/100. ${blocking.length} finding(s) at or above "${failOn}": ${ids}`;
}
