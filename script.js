'use strict';

const STORAGE_KEY = 'brandshield-ai-cases-v1';
const MIGRATION_KEY = 'brandshield-ai-sqlite-migrated-v1';
const CASE_STATUSES = ['New', 'Under Review', 'Confirmed', 'False Positive'];
const safeBrowsingConfigured = document.body.dataset.safeBrowsingConfigured === 'true';
const elements = {
  dashboardView: document.getElementById('dashboardView'),
  casesView: document.getElementById('casesView'),
  graphView: document.getElementById('graphView'),
  reportsView: document.getElementById('reportsView'),
  settingsView: document.getElementById('settingsView'),
  recentCasesBody: document.getElementById('recentCasesBody'),
  casesTableBody: document.getElementById('casesTableBody'),
  graph: document.getElementById('threatGraph'),
  dashboardGraph: document.getElementById('dashboardGraph'),
  evidenceAnalysis: document.getElementById('evidenceAnalysis'),
  riskDistributionChart: document.getElementById('riskDistributionChart'),
  riskChartLegend: document.getElementById('riskChartLegend'),
  platformDistributionChart: document.getElementById('platformDistributionChart'),
  caseDialog: document.getElementById('caseDialog'),
  detailDialog: document.getElementById('detailDialog'),
  tourDialog: document.getElementById('tourDialog'),
  caseForm: document.getElementById('caseForm'),
  search: document.getElementById('caseSearch'),
  globalSearch: document.getElementById('globalSearch'),
  riskFilter: document.getElementById('riskFilter'),
  statusFilter: document.getElementById('statusFilter'),
  reportSelect: document.getElementById('reportCaseSelect'),
  reportHistoryList: document.getElementById('reportHistoryList'),
  reportOutput: document.getElementById('reportOutput'),
  toast: document.getElementById('toast')
};

let cases = [];
let reports = [];
let dashboardData = null;
let backendReady = false;
let toastTimer;
let generatedReport = '';
let selectedCaseId = '';
let tourStepIndex = 0;
let dashboardCaseScope = '';
const websiteCheckResults = new Map();
const safeBrowsingResults = new Map();

const tourSteps = [
  {
    title: 'Start with sample cases',
    description: 'Review fictional social-profile and mobile-app cases, dashboard totals, risk bands, and platform counts. This workspace does not receive live platform feeds.',
    highlights: ['Cases are seeded examples, not live detections.', 'Risk totals use local explainable rules, not a trained AI model.'],
    view: 'dashboard'
  },
  {
    title: 'Triage social and app cases',
    description: 'Add a suspected social profile, Google Play listing, or Apple App Store listing. Review the rule-based score and reasons, then search, filter, and update its analyst status.',
    highlights: ['Scam and impersonation cues contribute to the score.', 'A low score is not a safety guarantee or proof of legitimacy.'],
    view: 'cases'
  },
  {
    title: 'Connect only what the evidence supports',
    description: 'The relationship graph links cases only when an analyst explicitly entered the same indicator. Similar-looking domains do not create a link.',
    highlights: ['Exact, case-insensitive indicator matching.', 'Select a graph node to inspect its evidence.'],
    view: 'graph'
  },
  {
    title: 'Leave an auditable handoff',
    description: 'Generate a case summary with its evidence, contributing rules, recommendation, and related cases. Reports stay in the local SQLite history.',
    highlights: ['Download a plain-text report.', 'The report repeats the prototype’s limitations.'],
    view: 'reports'
  }
];

async function apiRequest(path, options = {}) {
  let response;
  try {
    response = await fetch(path, {
      ...options,
      headers: { 'Content-Type': 'application/json', ...options.headers }
    });
  } catch (error) {
    throw new Error('Cannot reach the local Flask server. Start it in VS Code and reload this page.');
  }
  let result;
  try {
    result = await response.json();
  } catch {
    throw new Error('The local server returned an unreadable response.');
  }
  if (!response.ok) throw new Error(result.error || `Server request failed (${response.status}).`);
  return result;
}

function isValidCase(item) {
  return item && typeof item === 'object'
    && typeof item.id === 'string'
    && typeof item.brand === 'string'
    && typeof item.url === 'string'
    && typeof item.platform === 'string'
    && typeof item.observations === 'string'
    && Array.isArray(item.indicators)
    && item.indicators.every((indicator) => typeof indicator === 'string')
    && CASE_STATUSES.includes(item.status)
    && typeof item.createdAt === 'string';
}

async function refreshData() {
  const [caseResult, reportResult, dashboardResult] = await Promise.all([
    apiRequest('/api/cases'),
    apiRequest('/api/reports'),
    apiRequest('/api/dashboard')
  ]);
  cases = caseResult.cases;
  reports = reportResult.reports;
  dashboardData = dashboardResult;
  backendReady = true;
  renderAll();
}

async function refreshDashboardData() {
  try {
    dashboardData = await apiRequest('/api/dashboard');
    return '';
  } catch (error) {
    dashboardData = null;
    return error.message;
  }
}

async function initializeApp() {
  try {
    await apiRequest('/api/health');
    if (localStorage.getItem(MIGRATION_KEY) !== 'done') {
      let migrationWarning = '';
      try {
        const saved = localStorage.getItem(STORAGE_KEY);
        if (saved) {
          const legacyCases = JSON.parse(saved);
          if (Array.isArray(legacyCases)) {
            const importable = legacyCases.filter((item) => isValidCase(item));
            if (importable.length) {
              await apiRequest('/api/migrate', {
                method: 'POST',
                body: JSON.stringify({ cases: importable })
              });
            }
          }
        }
      } catch (error) {
        migrationWarning = error.message;
      }
      localStorage.setItem(MIGRATION_KEY, 'done');
      if (migrationWarning) {
        showToast(`Saved browser data was not migrated: ${migrationWarning}. Import a JSON backup from Settings if needed.`);
      }
    }
    await refreshData();
  } catch (error) {
    backendReady = false;
    showToast(error.message);
  }
}

function makeElement(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function appendCell(row, child, className) {
  const cell = document.createElement('td');
  if (className) cell.className = className;
  if (child instanceof Node) cell.append(child);
  else if (child !== undefined) cell.textContent = String(child);
  row.append(cell);
  return cell;
}

function getRisk(caseItem) {
  return caseItem.risk || {
    value: 0,
    level: 'low',
    reasons: [],
    recommendation: 'The backend has not supplied a risk analysis.'
  };
}

function getHostname(value) {
  try {
    return new URL(value).hostname;
  } catch {
    return '';
  }
}

function getRiskLabel(level) {
  return level.charAt(0).toUpperCase() + level.slice(1);
}

function getStatusClass(status) {
  if (status === 'Under Review') return 'status-review';
  if (status === 'Confirmed') return 'status-confirmed';
  if (status === 'False Positive') return 'status-false';
  return 'status-new';
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'Date unavailable';
  return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', year: 'numeric' }).format(date);
}

function compareCases(left, right) {
  return new Date(right.createdAt).getTime() - new Date(left.createdAt).getTime();
}

function createRiskIndicator(caseItem, compact) {
  const risk = getRisk(caseItem);
  const wrapper = makeElement('span', compact ? `risk-badge risk-${risk.level}` : `risk-cell risk-${risk.level}`);
  if (compact) {
    wrapper.append(makeElement('span', '', getRiskLabel(risk.level)));
    wrapper.title = `${risk.value}/100 · ${risk.recommendation}`;
    return wrapper;
  }
  wrapper.append(makeElement('span', 'risk-number', String(risk.value)));
  const track = makeElement('span', 'risk-track');
  const fill = makeElement('span', 'risk-fill');
  fill.style.width = `${risk.value}%`;
  track.append(fill);
  wrapper.append(track);
  wrapper.title = `${getRiskLabel(risk.level)} · ${risk.value}/100`;
  return wrapper;
}

function createStatusBadge(status) {
  return makeElement('span', `status-badge ${getStatusClass(status)}`, status);
}

function createStatusSelect(caseItem) {
  const select = document.createElement('select');
  select.className = `select-control status-select ${getStatusClass(caseItem.status)}`;
  select.setAttribute('aria-label', `Update status for ${caseItem.brand}, ${caseItem.id}`);
  select.dataset.caseId = caseItem.id;
  CASE_STATUSES.forEach((status) => {
    const option = makeElement('option', '', status);
    option.value = status;
    option.selected = status === caseItem.status;
    select.append(option);
  });
  return select;
}

function createCaseRow(caseItem, compact) {
  const row = document.createElement('tr');
  row.dataset.selectCaseId = caseItem.id;
  row.tabIndex = 0;
  row.classList.toggle('is-selected', caseItem.id === selectedCaseId);
  row.setAttribute('aria-label', `Select ${caseItem.brand}, ${caseItem.id}, for evidence analysis`);
  const assetCell = document.createElement('td');
  const asset = makeElement('div', 'asset-cell');
  const avatar = makeElement('span', 'asset-avatar', caseItem.brand.trim().charAt(0).toUpperCase() || '?');
  const assetCopy = document.createElement('span');
  assetCopy.append(
    makeElement('span', 'asset-primary', getHostname(caseItem.url) || caseItem.url),
    makeElement('span', 'asset-secondary', `${caseItem.brand} · ${caseItem.id}`)
  );
  asset.append(avatar, assetCopy);
  assetCell.append(asset);
  row.append(assetCell);
  if (compact) {
    appendCell(row, caseItem.platform, 'platform-cell');
  } else {
    appendCell(row, caseItem.brand, 'brand-cell');
    appendCell(row, caseItem.platform, 'platform-cell');
  }
  appendCell(row, createRiskIndicator(caseItem, false));
  const statusCell = document.createElement('td');
  statusCell.append(createStatusSelect(caseItem));
  row.append(statusCell);
  if (!compact) appendCell(row, formatDate(caseItem.createdAt));
  const actionCell = document.createElement('td');
  const action = makeElement('button', 'row-action', '⋯');
  action.type = 'button';
  action.dataset.detailsId = caseItem.id;
  action.setAttribute('aria-label', `View details for ${caseItem.brand}, ${caseItem.id}`);
  action.title = 'View case details';
  actionCell.append(action);
  row.append(actionCell);
  return row;
}

function renderDashboard() {
  const sorted = [...cases].sort(compareCases);
  const summary = dashboardData?.summary;
  document.getElementById('openCases').textContent = String(summary?.openCases ?? '—');
  document.getElementById('highRiskCases').textContent = String(summary?.highRiskCases ?? '—');
  document.getElementById('relatedClusters').textContent = String(summary?.relatedClusters ?? '—');
  document.getElementById('reportsReady').textContent = String(summary?.reportsReady ?? '—');
  document.getElementById('navCaseCount').textContent = String(cases.length);
  elements.recentCasesBody.replaceChildren(...sorted.slice(0, 5).map((item) => createCaseRow(item, true)));
  document.getElementById('recentEmpty').classList.toggle('hidden', sorted.length > 0);
  document.getElementById('settingsCaseCount').textContent = String(cases.length);
  document.getElementById('settingsDemoCount').textContent = String(cases.filter((item) => item.demo).length);
  if (!cases.some((item) => item.id === selectedCaseId)) selectedCaseId = sorted[0]?.id || '';
  renderEvidenceAnalysis(selectedCaseId);
  renderDashboardCharts();
  renderThreatGraph(elements.dashboardGraph, sorted.slice(0, 6), true);
}

function renderCases() {
  const searchTerm = elements.search.value.trim().toLocaleLowerCase();
  const riskValue = elements.riskFilter.value;
  const statusValue = elements.statusFilter.value;
  const relatedIds = new Set((dashboardData?.relationships || [])
    .flatMap((relationship) => [relationship.source, relationship.target]));
  const filtered = [...cases].sort(compareCases).filter((item) => {
    const searchMatches = !searchTerm || [item.id, item.brand, item.url, item.platform, item.observations, ...item.indicators]
      .some((value) => value.toLocaleLowerCase().includes(searchTerm));
    const levelMatches = riskValue === 'all' || getRisk(item).level === riskValue;
    const statusMatches = statusValue === 'all' || item.status === statusValue;
    const scopeMatches = dashboardCaseScope === 'open'
      ? ['New', 'Under Review'].includes(item.status)
      : dashboardCaseScope === 'high'
        ? getRisk(item).value >= 70
        : dashboardCaseScope === 'related'
          ? relatedIds.has(item.id)
          : true;
    return searchMatches && levelMatches && statusMatches && scopeMatches;
  });
  elements.casesTableBody.replaceChildren(...filtered.map((item) => createCaseRow(item, false)));
  const scopeLabel = {
    open: 'open',
    high: 'high-risk',
    related: 'related'
  }[dashboardCaseScope];
  document.getElementById('resultsCount').textContent = `${filtered.length} ${scopeLabel ? `${scopeLabel} ` : ''}${filtered.length === 1 ? 'case' : 'cases'}`;
  const empty = document.getElementById('casesEmpty');
  empty.classList.toggle('hidden', filtered.length > 0);
  const noCases = cases.length === 0;
  document.getElementById('casesEmptyTitle').textContent = noCases ? 'No cases in this workspace' : 'No cases found';
  document.getElementById('casesEmptyText').textContent = noCases
    ? 'Add a case to begin tracking an investigation.'
    : 'Try a different search or risk filter.';
  document.getElementById('clearFilters').classList.toggle('hidden', noCases || (!searchTerm && riskValue === 'all' && statusValue === 'all' && !dashboardCaseScope));
}

function openDashboardMetric(metric) {
  if (metric === 'reports') {
    setView('reports');
    document.querySelector('.report-history-panel').scrollIntoView({ behavior: 'smooth', block: 'start' });
    return;
  }
  dashboardCaseScope = ['open', 'high', 'related'].includes(metric) ? metric : '';
  elements.search.value = '';
  elements.globalSearch.value = '';
  elements.riskFilter.value = 'all';
  elements.statusFilter.value = 'all';
  setView('cases');
  renderCases();
}

function renderReportSelect() {
  const current = elements.reportSelect.value;
  const options = [new Option('Select a case…', '')];
  [...cases].sort(compareCases).forEach((item) => {
    options.push(new Option(`${item.id} · ${item.brand}`, item.id));
  });
  elements.reportSelect.replaceChildren(...options);
  if (cases.some((item) => item.id === current)) elements.reportSelect.value = current;
  else {
    elements.reportSelect.value = '';
    clearReportPreview();
  }
}

function renderReportHistory() {
  if (!elements.reportHistoryList) return;
  if (!reports.length) {
    elements.reportHistoryList.replaceChildren(makeElement('p', 'report-history-empty', 'No saved reports yet. Generate a report to create an audit-history entry.'));
    return;
  }
  const rows = reports.map((report) => {
    const row = makeElement('button', 'report-history-item');
    row.type = 'button';
    row.dataset.reportId = String(report.id);
    const copy = document.createElement('span');
    copy.append(
      makeElement('strong', '', `${report.caseId} · ${report.brand}`),
      makeElement('small', '', `Generated ${formatDate(report.generatedAt)}`)
    );
    row.append(copy, makeElement('span', 'history-open', 'View →'));
    return row;
  });
  elements.reportHistoryList.replaceChildren(...rows);
}

function renderAll() {
  renderDashboard();
  renderCases();
  renderReportSelect();
  renderReportHistory();
  renderThreatGraph(elements.graph, [...cases].sort(compareCases), false);
}

function createSvgElement(name, attributes, text) {
  const node = document.createElementNS('http://www.w3.org/2000/svg', name);
  Object.entries(attributes).forEach(([key, value]) => node.setAttribute(key, String(value)));
  if (text !== undefined) node.textContent = text;
  return node;
}

function renderDashboardCharts() {
  const riskDistribution = dashboardData?.riskDistribution;
  const platformDistribution = dashboardData?.platformDistribution;
  const colors = { Low: '#4fc3a1', Medium: '#e6a95f', High: '#e56c78' };
  const svg = elements.riskDistributionChart;
  const legend = elements.riskChartLegend;
  svg.replaceChildren();
  legend.replaceChildren();

  if (!riskDistribution || !platformDistribution) {
    svg.append(createSvgElement('text', { x: 60, y: 64, class: 'chart-unavailable' }, 'Unavailable'));
    elements.platformDistributionChart.replaceChildren(
      makeElement('p', 'chart-empty', 'Dashboard analytics are unavailable. Reload to try again.')
    );
    return;
  }

  const total = Object.values(riskDistribution).reduce((sum, count) => sum + count, 0);
  const riskBands = { Low: '0–39', Medium: '40–69', High: '70–100' };
  const radius = 40;
  const circumference = 2 * Math.PI * radius;
  svg.append(createSvgElement('circle', {
    cx: 60, cy: 60, r: radius, class: 'chart-ring'
  }));
  let offset = 0;
  Object.entries(riskDistribution).forEach(([level, count]) => {
    if (count > 0 && total > 0) {
      const length = circumference * count / total;
      svg.append(createSvgElement('circle', {
        cx: 60,
        cy: 60,
        r: radius,
        class: 'chart-segment',
        stroke: colors[level] || '#71869d',
        'stroke-dasharray': `${length} ${circumference - length}`,
        'stroke-dashoffset': String(-offset),
        transform: 'rotate(-90 60 60)'
      }));
      offset += length;
    }
    const item = makeElement('div', 'chart-legend-item');
    item.append(
      makeElement('i', `chart-swatch risk-swatch-${level.toLowerCase()}`),
      makeElement('span', '', `${level} · ${riskBands[level] || 'score'}`),
      makeElement('strong', '', String(count))
    );
    legend.append(item);
  });
  svg.append(
    createSvgElement('text', { x: 60, y: 58, class: 'chart-total' }, String(total)),
    createSvgElement('text', { x: 60, y: 73, class: 'chart-total-label' }, 'cases')
  );
  svg.setAttribute('aria-label', `Risk distribution across ${total} cases`);

  const platformChart = elements.platformDistributionChart;
  platformChart.replaceChildren();
  if (platformDistribution.length === 0) {
    platformChart.append(makeElement('p', 'chart-empty', 'Add an investigation to see platform totals.'));
    return;
  }
  const maximum = Math.max(...platformDistribution.map((item) => item.count));
  platformDistribution.forEach(({ platform, count }) => {
    const row = makeElement('div', 'platform-chart-row');
    const heading = makeElement('div', 'platform-chart-heading');
    heading.append(
      makeElement('span', '', platform),
      makeElement('strong', '', `${count} ${count === 1 ? 'case' : 'cases'}`)
    );
    const track = makeElement('span', 'platform-chart-track');
    const fill = makeElement('span', 'platform-chart-fill');
    fill.style.width = `${maximum ? count / maximum * 100 : 0}%`;
    track.append(fill);
    row.append(heading, track);
    platformChart.append(row);
  });
}

function selectCase(id) {
  if (!cases.some((item) => item.id === id)) return;
  selectedCaseId = id;
  document.querySelectorAll('[data-select-case-id]').forEach((row) => {
    row.classList.toggle('is-selected', row.dataset.selectCaseId === id);
  });
  renderEvidenceAnalysis(id);
  renderThreatGraph(elements.graph, [...cases].sort(compareCases), false);
  renderThreatGraph(elements.dashboardGraph, [...cases].sort(compareCases).slice(0, 6), true);
}

function renderThreatGraph(svg, items, compact) {
  if (!svg) return;
  const empty = document.getElementById('graphEmpty');
  if (empty && svg === elements.graph) empty.classList.toggle('hidden', items.length > 0);
  svg.classList.toggle('hidden', items.length === 0);
  svg.replaceChildren();
  if (items.length === 0) {
    if (!compact) document.getElementById('graphSummary').textContent = '0 entities mapped';
    return;
  }

  const columns = 3;
  const rowHeight = compact ? 105 : 130;
  const top = compact ? 50 : 53;
  const rows = Math.ceil(items.length / columns);
  const height = Math.max(compact ? 195 : 355, top + rows * rowHeight + 35);
  const viewWidth = 800;
  svg.setAttribute('viewBox', `0 0 ${viewWidth} ${height}`);
  svg.setAttribute('height', String(height));
  svg.setAttribute('preserveAspectRatio', 'xMidYMin meet');
  const points = items.map((caseItem, index) => ({
    caseItem,
    x: 130 + (index % columns) * 270,
    y: top + Math.floor(index / columns) * rowHeight
  }));

  let linkCount = 0;
  const pointById = new Map(points.map((point) => [point.caseItem.id, point]));
  for (const relationship of dashboardData?.relationships || []) {
    const left = pointById.get(relationship.source);
    const right = pointById.get(relationship.target);
    if (!left || !right) continue;
    linkCount += 1;
    svg.append(createSvgElement('line', {
      x1: left.x, y1: left.y, x2: right.x, y2: right.y, class: 'graph-edge'
    }));
    const label = relationship.indicators.join(', ');
    const labelX = (left.x + right.x) / 2;
    const labelY = (left.y + right.y) / 2 - 5;
    svg.append(createSvgElement('text', {
      x: labelX, y: labelY, class: 'graph-edge-label'
    }, label.length > 28 ? `${label.slice(0, 25)}…` : label));
  }

  points.forEach(({ caseItem, x, y }) => {
    const risk = getRisk(caseItem);
    const domain = getHostname(caseItem.url) || caseItem.url;
    const group = createSvgElement('g', {
      class: 'graph-node',
      role: 'button',
      tabindex: '0',
      'aria-label': `${caseItem.brand}, ${domain}, risk ${risk.value}. Select for evidence details.`
    });
    group.append(createSvgElement('rect', {
      x: x - 93,
      y: y - 31,
      width: 186,
      height: 63,
      rx: 7,
      class: `node-card${risk.level === 'high' ? ' node-high' : ''}${caseItem.id === selectedCaseId ? ' node-selected' : ''}`
    }));
    group.append(createSvgElement('circle', {
      cx: x - 75, cy: y - 9, r: 4, class: 'node-dot'
    }));
    group.append(createSvgElement('text', {
      x: x - 64, y: y - 6, class: 'node-title'
    }, caseItem.brand.length > 22 ? `${caseItem.brand.slice(0, 20)}…` : caseItem.brand));
    group.append(createSvgElement('text', {
      x: x - 75, y: y + 10, class: 'node-subtitle'
    }, domain.length > 27 ? `${domain.slice(0, 24)}…` : domain));
    group.append(createSvgElement('text', {
      x: x - 75, y: y + 23, class: 'node-subtitle'
    }, `${caseItem.id} · ${caseItem.platform}`));
    group.append(createSvgElement('text', {
      x: x + 75, y: y - 7, class: `node-risk ${risk.level}`
    }, String(risk.value)));
    const choose = () => {
      selectCase(caseItem.id);
    };
    group.addEventListener('click', choose);
    group.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        choose();
      }
    });
    svg.append(group);
  });
  if (!compact) {
    document.getElementById('graphSummary').textContent = `${items.length} ${items.length === 1 ? 'entity' : 'entities'} mapped · ${linkCount} ${linkCount === 1 ? 'link' : 'links'}`;
  }
}

function renderEvidenceAnalysis(id) {
  const caseItem = cases.find((item) => item.id === id);
  document.getElementById('analysisTitle').textContent = caseItem
    ? `Evidence · ${caseItem.brand}`
    : 'Evidence & analysis';
  document.getElementById('analysisCaseLabel').textContent = caseItem
    ? `SELECTED · ${caseItem.id}`
    : 'SELECT A CASE';
  if (!caseItem) {
    const empty = document.createElement('div');
    empty.className = 'analysis-empty';
    empty.append(
      makeElement('span', '', '◎'),
      makeElement('strong', '', 'Select an investigation'),
      makeElement('p', '', 'Select a case row or graph node to review only that investigation’s evidence and demo score.')
    );
    elements.evidenceAnalysis.replaceChildren(empty);
    return;
  }
  const risk = getRisk(caseItem);
  const body = makeElement('div', 'analysis-body');
  const asset = makeElement('div', 'analysis-asset');
  asset.append(
    makeElement('span', 'analysis-avatar', caseItem.brand.trim().charAt(0).toUpperCase() || '?'),
    makeElement('span', '', '')
  );
  const copy = asset.lastElementChild;
  copy.append(
    makeElement('strong', '', caseItem.brand),
    makeElement('small', '', `${getHostname(caseItem.url)} · ${caseItem.platform}`)
  );
  body.append(asset);
  const scoreRow = makeElement('div', 'analysis-score-row');
  scoreRow.append(makeElement('span', '', `RISK INDICATOR · ${getRiskLabel(risk.level).toUpperCase()}`));
  const score = makeElement('strong', 'analysis-score', String(risk.value));
  score.append(makeElement('em', '', ' / 100'));
  scoreRow.append(score);
  body.append(scoreRow);
  const recommendation = makeElement('div', 'analysis-recommendation');
  recommendation.append(makeElement('strong', '', 'HUMAN REVIEW RECOMMENDED'), document.createTextNode(risk.recommendation));
  body.append(recommendation);
  body.append(makeElement('p', 'analysis-reasons-title', 'CONTRIBUTING SIGNALS'));
  const reasons = makeElement('ul', 'analysis-reasons');
  risk.reasons.forEach((reason) => {
    const item = document.createElement('li');
    item.append(makeElement('span', 'reason-mark', '◆'), document.createTextNode(reason.text));
    reasons.append(item);
  });
  body.append(reasons);
  const note = makeElement('p', 'analysis-reasons-title', 'EVIDENCE NOTE');
  note.style.marginTop = '12px';
  body.append(note, makeElement('p', 'analysis-evidence', caseItem.observations || 'No observations provided.'));
  const related = getRelatedCases(caseItem);
  body.append(makeElement('p', 'analysis-related', related.length
    ? `${related.length} case${related.length === 1 ? '' : 's'} share an explicit indicator.`
    : 'No explicit shared-indicator matches.'));
  elements.evidenceAnalysis.replaceChildren(body);
}

function showToast(message) {
  elements.toast.textContent = message;
  elements.toast.classList.add('is-visible');
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => elements.toast.classList.remove('is-visible'), 3400);
}

function renderTourStep() {
  const step = tourSteps[tourStepIndex];
  document.getElementById('tourProgressLabel').textContent = `STEP ${tourStepIndex + 1} OF ${tourSteps.length}`;
  document.getElementById('tourProgressFill').style.width = `${((tourStepIndex + 1) / tourSteps.length) * 100}%`;
  document.getElementById('tourStepNumber').textContent = String(tourStepIndex + 1).padStart(2, '0');
  document.getElementById('tourStepTitle').textContent = step.title;
  document.getElementById('tourStepDescription').textContent = step.description;
  document.getElementById('tourHighlights').replaceChildren(
    ...step.highlights.map((highlight) => makeElement('li', '', highlight))
  );
  document.getElementById('tourBack').disabled = tourStepIndex === 0;
  document.getElementById('tourNext').innerHTML = tourStepIndex === tourSteps.length - 1
    ? 'Finish tour'
    : 'Next step <span aria-hidden="true">→</span>';
}

function openGuidedDemo() {
  tourStepIndex = 0;
  renderTourStep();
  elements.tourDialog.showModal();
}

function setView(view) {
  const views = {
    dashboard: { element: elements.dashboardView, title: 'Dashboard' },
    cases: { element: elements.casesView, title: 'Threat detections' },
    graph: { element: elements.graphView, title: 'Threat Graph' },
    reports: { element: elements.reportsView, title: 'Reports' },
    settings: { element: elements.settingsView, title: 'Settings' }
  };
  if (!views[view]) return;
  Object.entries(views).forEach(([key, value]) => {
    const active = key === view;
    value.element.hidden = !active;
    value.element.classList.toggle('is-visible', active);
  });
  document.querySelectorAll('.nav-link[data-view]').forEach((button) => {
    const active = button.dataset.view === view;
    button.classList.toggle('is-active', active);
    if (active) button.setAttribute('aria-current', 'page');
    else button.removeAttribute('aria-current');
  });
  document.getElementById('pageCrumb').textContent = views[view].title;
  document.getElementById('sidebar').classList.remove('is-open');
  document.getElementById('menuButton').setAttribute('aria-expanded', 'false');
}

function validateUrl(rawValue) {
  const value = rawValue.trim();
  if (!value) return { error: 'Enter the suspicious profile, website, or app listing URL.' };
  let url;
  try {
    url = new URL(value);
  } catch {
    return { error: 'Enter a complete URL, including https:// or http://.' };
  }
  if (!['http:', 'https:'].includes(url.protocol) || !url.hostname.includes('.') || /\s/.test(value)) {
    return { error: 'Enter a valid website or profile URL using http:// or https://.' };
  }
  return { value: url.href };
}

function openCaseForm() {
  clearFormErrors();
  elements.caseForm.reset();
  updateAssetUrlGuidance();
  document.getElementById('formMessage').classList.add('hidden');
  elements.caseDialog.showModal();
  document.getElementById('brandName').focus();
}

function updateAssetUrlGuidance() {
  const platform = document.getElementById('platform').value;
  const isAppStore = platform === 'Google Play' || platform === 'Apple App Store';
  const assetUrlLabel = document.getElementById('assetUrlLabel');
  const assetUrlHint = document.getElementById('assetUrlHint');
  const profileUrl = document.getElementById('profileUrl');
  if (!assetUrlLabel || !assetUrlHint || !profileUrl) return;
  assetUrlLabel.textContent = isAppStore
    ? 'Suspicious app listing URL'
    : 'Suspicious profile or website URL';
  assetUrlHint.textContent = isAppStore
    ? 'Paste the public Google Play or Apple App Store listing URL. This demo does not query the store.'
    : 'Use a full public social profile or website URL with https:// or http://.';
  profileUrl.placeholder = isAppStore
    ? 'https://play.google.com/store/apps/details?id=…'
    : 'https://example.com/profile';
}

function clearFormErrors() {
  ['brandError', 'platformError', 'urlError'].forEach((id) => {
    document.getElementById(id).textContent = '';
  });
}

async function handleCaseSubmit(event) {
  event.preventDefault();
  clearFormErrors();
  const formMessage = document.getElementById('formMessage');
  formMessage.classList.add('hidden');
  formMessage.textContent = '';
  const brand = document.getElementById('brandName').value.trim();
  const platform = document.getElementById('platform').value;
  const urlResult = validateUrl(document.getElementById('profileUrl').value);
  let valid = true;
  if (!brand) {
    document.getElementById('brandError').textContent = 'Enter the brand name.';
    valid = false;
  }
  if (!platform) {
    document.getElementById('platformError').textContent = 'Choose a platform.';
    valid = false;
  }
  if (urlResult.error) {
    document.getElementById('urlError').textContent = urlResult.error;
    valid = false;
  }
  if (!valid) return;

  const caseData = {
    brand,
    url: urlResult.value,
    platform,
    observations: document.getElementById('observations').value.trim(),
    indicators: document.getElementById('indicators').value.split(',').map((value) => value.trim()).filter(Boolean)
  };
  const submitButton = document.getElementById('submitCase');
  if (submitButton) {
    submitButton.disabled = true;
    submitButton.textContent = 'Saving…';
  }
  try {
    const result = await apiRequest('/api/cases', {
      method: 'POST',
      body: JSON.stringify(caseData)
    });
    cases = [result.case, ...cases];
    const analyticsError = await refreshDashboardData();
    websiteCheckResults.delete(result.case.id);
    safeBrowsingResults.delete(result.case.id);
    selectedCaseId = result.case.id;
    elements.caseDialog.close();
    renderAll();
    showToast(analyticsError
      ? `${result.case.id} saved in SQLite, but dashboard analytics could not refresh: ${analyticsError}`
      : `${result.case.id} saved in the SQLite database.`);
    showCaseDetails(result.case.id);
  } catch (error) {
    formMessage.textContent = error.message;
    formMessage.classList.remove('hidden');
  } finally {
    if (submitButton) {
      submitButton.disabled = false;
      submitButton.innerHTML = 'Analyze &amp; save <span>→</span>';
    }
  }
}

function getRelatedCases(target) {
  return (dashboardData?.relationships || [])
    .filter((relationship) => relationship.source === target.id || relationship.target === target.id)
    .map((relationship) => {
      const relatedId = relationship.source === target.id ? relationship.target : relationship.source;
      const caseItem = cases.find((candidate) => candidate.id === relatedId);
      if (!caseItem) return null;
      return {
        caseItem,
        reasons: [`explicitly shared indicator${relationship.indicators.length > 1 ? 's' : ''}: ${relationship.indicators.join(', ')}`]
      };
    })
    .filter((match) => match !== null);
}

function addDetailItem(container, label, value, wide) {
  const item = makeElement('div', wide ? 'detail-item wide' : 'detail-item');
  item.append(makeElement('span', 'detail-label', label));
  const content = makeElement('div', 'detail-value');
  if (value instanceof Node) content.append(value);
  else content.textContent = value || 'Not provided';
  item.append(content);
  container.append(item);
}

function showCaseDetails(id) {
  const caseItem = cases.find((item) => item.id === id);
  if (!caseItem) {
    showToast('That case is no longer available.');
    return;
  }
  document.getElementById('detailTitle').textContent = caseItem.brand;
  document.getElementById('detailEyebrow').textContent = `${caseItem.id}${caseItem.demo ? ' · SAMPLE DEMO CASE' : ''}`;
  const container = document.getElementById('detailContent');
  const grid = makeElement('div', 'detail-grid');
  addDetailItem(grid, 'Platform', caseItem.platform);
  addDetailItem(grid, 'Status', createStatusBadge(caseItem.status));
  const link = document.createElement('a');
  link.href = caseItem.url;
  link.target = '_blank';
  link.rel = 'noopener noreferrer';
  link.textContent = caseItem.url;
  addDetailItem(grid, 'Profile / app listing URL', link, true);
  if (caseItem.platform === 'Website') {
    const checkPanel = makeElement('div', 'website-check-panel');
    checkPanel.append(makeElement(
      'p',
      'website-check-note',
      'Make one on-demand request to this public website. No background monitoring starts, and this check does not change the risk score.'
    ));
    const checkButton = makeElement('button', 'button button-secondary button-small website-check-button', '↻ Check website now');
    checkButton.type = 'button';
    checkButton.dataset.websiteCheckId = caseItem.id;
    const checkState = websiteCheckResults.get(caseItem.id);
    if (checkState?.loading) {
      checkButton.disabled = true;
      checkButton.textContent = 'Checking website…';
    }
    checkPanel.append(checkButton);
    if (checkState?.result) {
      const result = checkState.result;
      const checkedAt = new Intl.DateTimeFormat(undefined, {
        dateStyle: 'medium',
        timeStyle: 'short'
      }).format(new Date(result.checkedAt));
      checkPanel.append(
        makeElement(
          'p',
          `website-check-result ${result.reachable ? 'is-reachable' : 'is-unreachable'}`,
          `${result.reachable ? 'Responded' : 'HTTP error response'} · HTTP ${result.statusCode} · Checked ${checkedAt}`
        )
      );
      if (result.title) {
        checkPanel.append(makeElement('p', 'website-check-title', `Page title: ${result.title}`));
      }
    } else if (checkState?.error) {
      checkPanel.append(makeElement('p', 'website-check-result is-unreachable', checkState.error));
    }
    addDetailItem(grid, 'Manual website check', checkPanel, true);
  }
  const reputationPanel = makeElement('div', 'website-check-panel');
  reputationPanel.append(makeElement(
    'p',
    'website-check-note',
    'Checks this URL against Google Safe Browsing threat lists. Clicking sends the full case URL to Google. A result is not a guarantee.'
  ));
  const reputationButton = makeElement(
    'button',
    'button button-secondary button-small website-check-button',
    'Check with Google Safe Browsing'
  );
  reputationButton.type = 'button';
  reputationButton.dataset.safeBrowsingCheckId = caseItem.id;
  reputationButton.disabled = !safeBrowsingConfigured;
  if (!safeBrowsingConfigured) {
    reputationButton.title = 'The app owner must configure GOOGLE_SAFE_BROWSING_API_KEY on the server.';
  }
  const reputationState = safeBrowsingResults.get(caseItem.id);
  if (reputationState?.loading) {
    reputationButton.disabled = true;
    reputationButton.textContent = 'Checking Google Safe Browsing…';
  }
  reputationPanel.append(reputationButton);
  if (!safeBrowsingConfigured) {
    reputationPanel.append(makeElement(
      'p',
      'website-check-result is-unreachable',
      'Not configured. The app owner must set GOOGLE_SAFE_BROWSING_API_KEY on the server.'
    ));
  } else if (reputationState?.result) {
    const result = reputationState.result;
    const checkedAt = new Intl.DateTimeFormat(undefined, {
      dateStyle: 'medium',
      timeStyle: 'short'
    }).format(new Date(result.checkedAt));
    const isListed = result.verdict === 'known_threat';
    reputationPanel.append(makeElement(
      'p',
      `website-check-result ${isListed ? 'is-unreachable' : 'is-reachable'}`,
      isListed
        ? `Google reports a known threat · ${result.threatTypes.join(', ')} · Checked ${checkedAt}`
        : `No match found in the queried Google lists · Checked ${checkedAt}`
    ));
    reputationPanel.append(makeElement(
      'p',
      'website-check-title',
      'No match is not proof that a URL is safe; the service only reports entries found on its lists.'
    ));
  } else if (reputationState?.error) {
    reputationPanel.append(makeElement('p', 'website-check-result is-unreachable', reputationState.error));
  }
  addDetailItem(grid, 'Real-world URL reputation', reputationPanel, true);

  const risk = getRisk(caseItem);
  const score = makeElement('div', 'detail-score');
  score.append(makeElement('strong', '', `${risk.value}/100`), createRiskIndicator(caseItem, true));
  addDetailItem(grid, 'Explainable demo risk indicator', score);
  addDetailItem(grid, 'Review recommendation', risk.recommendation, true);
  const reasonList = document.createElement('ul');
  reasonList.className = 'reason-list';
  risk.reasons.forEach((reason) => reasonList.append(makeElement('li', '', reason.text)));
  addDetailItem(grid, 'Rules that contributed', reasonList, true);
  addDetailItem(grid, 'Evidence / observations', caseItem.observations, true);
  addDetailItem(grid, 'Explicitly entered shared indicators', caseItem.indicators.join(', '), true);

  const related = getRelatedCases(caseItem);
  const relatedContent = document.createElement('div');
  if (related.length) {
    const list = document.createElement('ul');
    list.className = 'related-list';
    related.forEach(({ caseItem: other, reasons }) => {
      const item = document.createElement('li');
      item.append(makeElement('strong', '', `${other.id} · ${other.brand}`), document.createTextNode(` — linked by ${reasons.join('; ')}.`));
      list.append(item);
    });
    relatedContent.append(list);
  } else {
    relatedContent.append(makeElement('span', 'related-none', 'No other case has an exact matching shared indicator.'));
  }
  addDetailItem(grid, 'Related cases', relatedContent, true);
  addDetailItem(grid, 'Added', formatDate(caseItem.createdAt));
  const demoText = caseItem.demo
    ? 'This is an illustrative sample case. It is not a verified real-world report.'
    : 'Saved in the local SQLite database. Google Safe Browsing URL reputation is available as a separate, manual lookup when configured.';
  addDetailItem(grid, 'Data note', demoText, true);
  container.replaceChildren(grid);
  if (!elements.detailDialog.open) elements.detailDialog.showModal();
}

async function runManualWebsiteCheck(id) {
  const caseItem = cases.find((item) => item.id === id);
  if (!caseItem || caseItem.platform !== 'Website') {
    showToast('Manual website checks are available for Website cases only.');
    return;
  }
  if (!backendReady) {
    showToast('The local Flask server is not connected. Start the server and reload.');
    return;
  }

  websiteCheckResults.set(id, { loading: true });
  if (elements.detailDialog.open) showCaseDetails(id);
  try {
    const response = await apiRequest(
      `/api/cases/${encodeURIComponent(id)}/website-check`,
      { method: 'POST', body: JSON.stringify({}) }
    );
    websiteCheckResults.set(id, { result: response.check });
    if (elements.detailDialog.open && document.getElementById('detailEyebrow').textContent.startsWith(id)) {
      showCaseDetails(id);
    }
    showToast(`Manual check finished: HTTP ${response.check.statusCode}. This is not a safety verdict.`);
  } catch (error) {
    websiteCheckResults.set(id, { error: error.message });
    if (elements.detailDialog.open && document.getElementById('detailEyebrow').textContent.startsWith(id)) {
      showCaseDetails(id);
    }
    showToast(error.message);
  }
}

async function runSafeBrowsingCheck(id) {
  const caseItem = cases.find((item) => item.id === id);
  if (!caseItem) {
    showToast('That case is no longer available.');
    return;
  }
  if (!safeBrowsingConfigured) {
    showToast('Google Safe Browsing is not configured. Ask the app owner to add the server API key.');
    return;
  }
  if (!backendReady) {
    showToast('The local Flask server is not connected. Start the server and reload.');
    return;
  }

  safeBrowsingResults.set(id, { loading: true });
  if (elements.detailDialog.open) showCaseDetails(id);
  try {
    const response = await apiRequest(
      `/api/cases/${encodeURIComponent(id)}/safe-browsing-check`,
      { method: 'POST', body: JSON.stringify({}) }
    );
    safeBrowsingResults.set(id, { result: response.check });
    if (elements.detailDialog.open && document.getElementById('detailEyebrow').textContent.startsWith(id)) {
      showCaseDetails(id);
    }
    showToast(response.check.verdict === 'known_threat'
      ? 'Google Safe Browsing reports a known threat. Review the listed categories.'
      : 'Google Safe Browsing found no match in the queried lists. This is not a safety verdict.');
  } catch (error) {
    safeBrowsingResults.set(id, { error: error.message });
    if (elements.detailDialog.open && document.getElementById('detailEyebrow').textContent.startsWith(id)) {
      showCaseDetails(id);
    }
    showToast(error.message);
  }
}

function renderReportPreview(caseItem, report) {
  const risk = getRisk(caseItem);
  const wrapper = makeElement('article', 'report-document');
  wrapper.append(makeElement('h3', '', `Case summary · ${caseItem.id}`));
  const addParagraph = (label, value) => {
    const p = document.createElement('p');
    p.append(makeElement('strong', '', `${label}: `), document.createTextNode(value));
    wrapper.append(p);
  };
  addParagraph('Brand', caseItem.brand);
  addParagraph('Platform', caseItem.platform);
  addParagraph('Profile / app listing URL', caseItem.url);
  addParagraph('Status', caseItem.status);
  addParagraph('Date added', formatDate(caseItem.createdAt));
  const scoreLine = makeElement('p');
  scoreLine.append(makeElement('strong', '', 'Explainable demo risk indicator: '), document.createTextNode(`${risk.value}/100 · ${getRiskLabel(risk.level)}`));
  wrapper.append(scoreLine);
  wrapper.append(makeElement('h4', '', 'Contributing rules'));
  const reasons = document.createElement('ul');
  risk.reasons.forEach((reason) => reasons.append(makeElement('li', '', reason.text)));
  wrapper.append(reasons);
  wrapper.append(makeElement('h4', '', 'Review recommendation'));
  wrapper.append(makeElement('p', '', risk.recommendation));
  wrapper.append(makeElement('h4', '', 'Evidence / observations'));
  wrapper.append(makeElement('p', '', caseItem.observations || 'No observations were provided.'));
  wrapper.append(makeElement('h4', '', 'Related cases'));
  const related = getRelatedCases(caseItem);
  if (related.length) {
    const relatedList = document.createElement('ul');
    related.forEach(({ caseItem: other, reasons: why }) => relatedList.append(makeElement('li', '', `${other.id} · ${other.brand} — linked by ${why.join('; ')}.`)));
    wrapper.append(relatedList);
  } else {
    wrapper.append(makeElement('p', '', 'No other case has an exact matching shared indicator.'));
  }
  wrapper.append(makeElement('p', 'report-warning', 'Demo only: this rule-based score is an indicator, not proof of fraud or a Google Safe Browsing result. Reputation lookup is separate and must be run manually.'));
  elements.reportOutput.replaceChildren(wrapper);
  document.getElementById('reportPreviewMeta').textContent = `${caseItem.brand} · ${formatDate(caseItem.createdAt)}`;
  generatedReport = report;
  document.getElementById('downloadReport').disabled = false;
}

function clearReportPreview() {
  const placeholder = document.createElement('div');
  placeholder.className = 'report-placeholder';
  placeholder.append(
    makeElement('span', '', '▤'),
    makeElement('strong', '', 'Your report will appear here'),
    makeElement('p', '', 'Select a case and generate a report to see its investigation summary.')
  );
  elements.reportOutput.replaceChildren(placeholder);
  document.getElementById('reportPreviewMeta').textContent = 'Select a case to begin';
  document.getElementById('downloadReport').disabled = true;
  generatedReport = '';
}

async function generateSelectedReport() {
  const caseItem = cases.find((item) => item.id === elements.reportSelect.value);
  if (!caseItem) {
    showToast('Select a case before generating a report.');
    return;
  }
  try {
    const result = await apiRequest(`/api/cases/${encodeURIComponent(caseItem.id)}/reports`, {
      method: 'POST',
      body: JSON.stringify({})
    });
    generatedReport = result.report.content;
    reports = [{
      id: result.report.id,
      caseId: result.report.caseId,
      brand: result.report.brand,
      generatedAt: result.report.generatedAt
    }, ...reports];
    const analyticsError = await refreshDashboardData();
    renderReportPreview(caseItem, generatedReport);
    renderAll();
    showToast(analyticsError
      ? `Report saved to SQLite, but dashboard analytics could not refresh: ${analyticsError}`
      : 'Report generated and saved to SQLite report history.');
  } catch (error) {
    showToast(error.message);
  }
}

async function openSavedReport(reportId) {
  try {
    const result = await apiRequest(`/api/reports/${encodeURIComponent(reportId)}`);
    generatedReport = result.report.content;
    document.getElementById('reportPreviewMeta').textContent =
      `${result.report.caseId} · ${result.report.brand} · ${formatDate(result.report.generatedAt)}`;
    const wrapper = makeElement('article', 'report-document');
    wrapper.append(makeElement('pre', 'saved-report-text', result.report.content));
    elements.reportOutput.replaceChildren(wrapper);
    document.getElementById('downloadReport').disabled = false;
    showToast('Saved report loaded from SQLite history.');
  } catch (error) {
    showToast(error.message);
  }
}

function downloadGeneratedReport() {
  if (!generatedReport) {
    showToast('Generate a report before downloading.');
    return;
  }
  const selected = cases.find((item) => item.id === elements.reportSelect.value);
  const safeId = selected ? selected.id.toLocaleLowerCase().replace(/[^a-z0-9-]/g, '') : 'case';
  const blob = new Blob([generatedReport], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `brandshield-report-${safeId}.txt`;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  showToast('Report downloaded as a text file.');
}

function exportCasesBackup() {
  const contents = JSON.stringify({
    exportedAt: new Date().toISOString(),
    format: 'BrandShield AI case backup',
    cases
  }, null, 2);
  const blob = new Blob([contents], { type: 'application/json;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = 'brandshield-cases-backup.json';
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  showToast('Local case backup exported as JSON.');
}

async function importCasesBackup(file) {
  if (!file) return;
  try {
    const backup = JSON.parse(await file.text());
    const importedCases = Array.isArray(backup) ? backup : backup.cases;
    if (!Array.isArray(importedCases) || !importedCases.every(isValidCase)) {
      throw new Error('This is not a valid BrandShield case backup.');
    }
    const result = await apiRequest('/api/migrate', {
      method: 'POST',
      body: JSON.stringify({ cases: importedCases })
    });
    await refreshData();
    showToast(`${result.migrated} cases imported into SQLite.`);
  } catch (error) {
    showToast(error instanceof SyntaxError ? 'The selected file is not valid JSON.' : error.message);
  } finally {
    document.getElementById('caseBackupInput').value = '';
  }
}

async function resetDemoData() {
  const approved = window.confirm('Reset SQLite to the original sample cases? All current investigations and saved report history will be permanently removed.');
  if (!approved) return;
  try {
    const result = await apiRequest('/api/reset-demo', {
      method: 'POST',
      body: JSON.stringify({})
    });
    cases = result.cases;
    reports = [];
    const analyticsError = await refreshDashboardData();
    websiteCheckResults.clear();
    safeBrowsingResults.clear();
    selectedCaseId = '';
    elements.search.value = '';
    elements.globalSearch.value = '';
    elements.riskFilter.value = 'all';
    elements.statusFilter.value = 'all';
    clearReportPreview();
    renderAll();
    showToast(analyticsError
      ? `Workspace reset, but dashboard analytics could not refresh: ${analyticsError}`
      : 'SQLite workspace reset to the original sample cases.');
  } catch (error) {
    showToast(error.message);
  }
}

async function deleteSelectedCase() {
  const id = document.getElementById('detailEyebrow').textContent.split(' · ')[0];
  const caseItem = cases.find((item) => item.id === id);
  if (!caseItem) return;
  if (!window.confirm(`Delete ${id} (${caseItem.brand}) and its saved report history? This cannot be undone.`)) return;
  try {
    await apiRequest(`/api/cases/${encodeURIComponent(id)}`, { method: 'DELETE' });
    cases = cases.filter((item) => item.id !== id);
    reports = reports.filter((report) => report.caseId !== id);
    const analyticsError = await refreshDashboardData();
    websiteCheckResults.delete(id);
    safeBrowsingResults.delete(id);
    selectedCaseId = '';
    elements.detailDialog.close();
    renderAll();
    showToast(analyticsError
      ? `${id} and its reports were deleted, but dashboard analytics could not refresh: ${analyticsError}`
      : `${id} and its reports were deleted from SQLite.`);
  } catch (error) {
    showToast(error.message);
  }
}

document.querySelectorAll('.nav-link[data-view]').forEach((button) => {
  button.addEventListener('click', () => setView(button.dataset.view));
});
document.querySelectorAll('[data-view-link]').forEach((button) => {
  button.addEventListener('click', (event) => {
    event.preventDefault();
    setView(button.dataset.viewLink);
  });
});
document.querySelectorAll('[data-open-case]').forEach((button) => button.addEventListener('click', openCaseForm));
document.querySelectorAll('[data-dashboard-filter]').forEach((button) => {
  button.addEventListener('click', () => openDashboardMetric(button.dataset.dashboardFilter));
});
document.getElementById('menuButton').addEventListener('click', () => {
  const sidebar = document.getElementById('sidebar');
  const open = sidebar.classList.toggle('is-open');
  document.getElementById('menuButton').setAttribute('aria-expanded', String(open));
});
document.getElementById('closeCaseDialog').addEventListener('click', () => elements.caseDialog.close());
document.getElementById('cancelCase').addEventListener('click', () => elements.caseDialog.close());
document.getElementById('closeDetailDialog').addEventListener('click', () => elements.detailDialog.close());
document.getElementById('detailCloseButton').addEventListener('click', () => elements.detailDialog.close());
document.getElementById('openTour').addEventListener('click', openGuidedDemo);
document.getElementById('closeTour').addEventListener('click', () => elements.tourDialog.close());
document.getElementById('platform').addEventListener('change', updateAssetUrlGuidance);
document.getElementById('tourBack').addEventListener('click', () => {
  if (tourStepIndex > 0) {
    tourStepIndex -= 1;
    renderTourStep();
  }
});
document.getElementById('tourNext').addEventListener('click', () => {
  if (tourStepIndex === tourSteps.length - 1) {
    elements.tourDialog.close();
    return;
  }
  tourStepIndex += 1;
  renderTourStep();
});
document.getElementById('tourOpenView').addEventListener('click', () => {
  const { view } = tourSteps[tourStepIndex];
  elements.tourDialog.close();
  setView(view);
});
elements.caseForm.addEventListener('submit', handleCaseSubmit);
document.getElementById('deleteCase').addEventListener('click', deleteSelectedCase);
elements.search.addEventListener('input', () => {
  elements.globalSearch.value = elements.search.value;
  renderCases();
});
elements.globalSearch.addEventListener('input', () => {
  elements.search.value = elements.globalSearch.value;
  setView('cases');
  renderCases();
});
elements.riskFilter.addEventListener('change', renderCases);
elements.statusFilter.addEventListener('change', renderCases);
document.getElementById('clearFilters').addEventListener('click', () => {
  dashboardCaseScope = '';
  elements.search.value = '';
  elements.globalSearch.value = '';
  elements.riskFilter.value = 'all';
  elements.statusFilter.value = 'all';
  renderCases();
});
document.getElementById('resetDemoData').addEventListener('click', resetDemoData);
document.getElementById('exportCases').addEventListener('click', exportCasesBackup);
document.getElementById('importCases').addEventListener('click', () => document.getElementById('caseBackupInput').click());
document.getElementById('caseBackupInput').addEventListener('change', (event) => {
  importCasesBackup(event.currentTarget.files[0]);
});
document.getElementById('generateReport').addEventListener('click', generateSelectedReport);
document.getElementById('downloadReport').addEventListener('click', downloadGeneratedReport);
elements.reportSelect.addEventListener('change', clearReportPreview);
document.addEventListener('click', (event) => {
  const safeBrowsingButton = event.target.closest('[data-safe-browsing-check-id]');
  if (safeBrowsingButton) {
    runSafeBrowsingCheck(safeBrowsingButton.dataset.safeBrowsingCheckId);
    return;
  }
  const websiteCheckButton = event.target.closest('[data-website-check-id]');
  if (websiteCheckButton) {
    runManualWebsiteCheck(websiteCheckButton.dataset.websiteCheckId);
    return;
  }
  const reportButton = event.target.closest('[data-report-id]');
  if (reportButton) {
    openSavedReport(reportButton.dataset.reportId);
    return;
  }
  const button = event.target.closest('[data-details-id]');
  if (button) {
    selectCase(button.dataset.detailsId);
    showCaseDetails(button.dataset.detailsId);
    return;
  }
  const row = event.target.closest('[data-select-case-id]');
  if (row && !event.target.closest('button, select, a')) {
    selectCase(row.dataset.selectCaseId);
  }
});
document.addEventListener('keydown', (event) => {
  const row = event.target.closest('[data-select-case-id]');
  if (row && event.target === row && (event.key === 'Enter' || event.key === ' ')) {
    event.preventDefault();
    selectCase(row.dataset.selectCaseId);
  }
});
document.addEventListener('change', (event) => {
  const select = event.target.closest('.status-select');
  if (!select) return;
  const caseItem = cases.find((item) => item.id === select.dataset.caseId);
  if (!caseItem || !CASE_STATUSES.includes(select.value)) {
    renderAll();
    return;
  }
  if (!backendReady) {
    showToast('The local Flask server is not connected. Start the server and reload.');
    renderAll();
    return;
  }
  const updatedStatus = select.value;
  select.disabled = true;
  apiRequest(`/api/cases/${encodeURIComponent(caseItem.id)}`, {
    method: 'PUT',
    body: JSON.stringify({ status: updatedStatus })
  }).then(async (result) => {
    cases = cases.map((item) => item.id === caseItem.id ? result.case : item);
    const analyticsError = await refreshDashboardData();
    renderAll();
    if (elements.detailDialog.open && document.getElementById('detailEyebrow').textContent.startsWith(caseItem.id)) {
      showCaseDetails(caseItem.id);
    }
    showToast(analyticsError
      ? `${caseItem.id} status saved, but dashboard analytics could not refresh: ${analyticsError}`
      : `${caseItem.id} status updated in SQLite.`);
  }).catch((error) => {
    showToast(error.message);
    renderAll();
  });
});
document.addEventListener('keydown', (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key.toLocaleLowerCase() === 'k') {
    event.preventDefault();
    elements.globalSearch.focus();
  }
});

setView('dashboard');
initializeApp();
