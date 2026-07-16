import React, { useState, useEffect } from 'react';

// Full record with unmasked SSN/DOB — only ever fetched one case at a time via
// GET /api/assessments/{id}, never in bulk (HIPAA minimum-necessary standard).
type Consultation = {
  id: number;
  patient_name: string;
  ssn: string;
  dob: string;
  symptoms: string;
  declared_duration: number;
  insurance_provider: 'PUBLIC' | 'PRIVATE';
  ai_risk_level: string;
  ai_confidence: number;
  ai_summary: string;
  status: 'PENDING_APPROVAL' | 'APPROVED' | 'OVERRIDDEN' | 'REJECTED';
  clinician_notes?: string;
  clinician_id?: string;
  created_at: string;
  governance_flags: string;
};

// Case-queue view — SSN/DOB masked server-side (GET /api/assessments). Never
// contains full identifiers; open a case to get the full Consultation record.
type ConsultationSummary = {
  id: number;
  patient_name: string;
  ssn_masked: string;
  dob_year: string;
  symptoms: string;
  declared_duration: number;
  insurance_provider: 'PUBLIC' | 'PRIVATE';
  ai_risk_level: string;
  ai_confidence: number;
  ai_summary: string;
  status: 'PENDING_APPROVAL' | 'APPROVED' | 'OVERRIDDEN' | 'REJECTED';
  clinician_notes?: string;
  clinician_id?: string;
  created_at: string;
  governance_flags: string;
};

type ComplianceMetrics = {
  total_assessments: number;
  total_completed: number;
  approved: number;
  overridden: number;
  rejected: number;
  human_override_rate: number;
  active_risks_count: number;
  active_risks: Array<{
    id: number;
    timestamp: string;
    hazard_type: string;
    severity: string;
    details: string;
  }>;
};

type BiasGroup = {
  nationality: string; // Used to represent Insurance Provider in the UI structure
  assessments: number;
  high_risk_count: number;
  high_risk_rate: number;
  ratio_to_overall: number | null;
  flagged: boolean;
  sufficient_sample: boolean;
};

type BiasMetrics = {
  total_scored_assessments: number;
  overall_high_risk_rate: number;
  by_nationality: BiasGroup[];
};

type ModelEval = {
  metrics: {
    precision: number;
    recall: number;
    false_positive_rate: number;
    accuracy: number;
  };
  confusion: {
    tp: number;
    fp: number;
    tn: number;
    fn: number;
  };
  dataset: {
    n_cases: number;
    caveat: string;
  };
};

type AuditLog = {
  id: number;
  consultation_id: number;
  timestamp: string;
  model_name: string;
  prompt_hash: string;
  api_latency_ms: number;
  human_action: string;
  override_reason?: string;
  clinician_id: string;
};

export default function App() {
  // Authentication state
  const [token, setToken] = useState<string | null>(localStorage.getItem('clinician_token'));
  const [authInput, setAuthInput] = useState('');
  
  // Data states
  const [consultations, setConsultations] = useState<ConsultationSummary[]>([]);
  const [selectedCase, setSelectedCase] = useState<Consultation | null>(null);
  const [selectedCaseLoading, setSelectedCaseLoading] = useState(false);
  
  // Form states
  const [patientName, setPatientName] = useState('');
  const [ssn, setSsn] = useState('');
  const [dob, setDob] = useState('');
  const [symptoms, setSymptoms] = useState('');
  const [duration, setDuration] = useState('');
  const [insurance, setInsurance] = useState('PUBLIC');

  // Oversight checklists
  const [identityVerified, setIdentityVerified] = useState(false);
  const [historyVerified, setHistoryVerified] = useState(false);
  const [notesVerified, setNotesVerified] = useState(false);
  const [oversightAction, setOversightAction] = useState('');
  const [clinicianNotes, setClinicianNotes] = useState('');
  const [overrideReason, setOverrideReason] = useState('');

  // Compliance metrics & logs
  const [metrics, setMetrics] = useState<ComplianceMetrics | null>(null);
  const [biasMetrics, setBiasMetrics] = useState<BiasMetrics | null>(null);
  const [modelEval, setModelEval] = useState<ModelEval | null>(null);
  const [auditChainStatus, setAuditChainStatus] = useState<{ intact: boolean; entries_checked: number } | null>(null);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);

  // UI state
  const [activeTab, setActiveTab] = useState<'details' | 'compliance' | 'instructions'>('details');
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  useEffect(() => {
    if (token) {
      fetchAllData();
    }
  }, [token]);

  const authHeaders = () => ({
    'Authorization': `Bearer ${token}`
  });

  const fetchAllData = async () => {
    try {
      // 1. Get Consultations
      const resConsult = await fetch('/api/assessments', { headers: authHeaders() });
      if (resConsult.status === 401) {
        handleLogout();
        return;
      }
      const dataConsult = await resConsult.json();
      setConsultations(dataConsult);

      // Refresh the open case's full detail (status, clinician notes, etc.) — re-fetched
      // from the single-record endpoint since the bulk list no longer carries full PII.
      if (selectedCase) {
        fetchCaseDetail(selectedCase.id);
      }

      // 2. Get Compliance Metrics
      const resMetrics = await fetch('/api/compliance/metrics', { headers: authHeaders() });
      if (resMetrics.ok) setMetrics(await resMetrics.json());

      // 3. Get Bias/Disparity Metrics
      const resBias = await fetch('/api/compliance/bias-metrics', { headers: authHeaders() });
      if (resBias.ok) setBiasMetrics(await resBias.json());

      // 4. Get Model Evaluation Harness results
      const resEval = await fetch('/api/compliance/model-eval', { headers: authHeaders() });
      if (resEval.ok) setModelEval(await resEval.json());

      // 5. Get Audit Chain Hashing status
      const resChain = await fetch('/api/compliance/audit-chain', { headers: authHeaders() });
      if (resChain.ok) setAuditChainStatus(await resChain.json());

      // 6. Get raw audit logs
      const resLogs = await fetch('/api/audit-logs', { headers: authHeaders() });
      if (resLogs.ok) setAuditLogs(await resLogs.json());

    } catch (err) {
      console.error("Error fetching dashboard data", err);
    }
  };

  // Full unmasked PII/PHI is only ever fetched for ONE case at a time, on explicit
  // selection — never as a side effect of loading the queue (minimum-necessary standard).
  const fetchCaseDetail = async (id: number) => {
    setSelectedCaseLoading(true);
    try {
      const res = await fetch(`/api/assessments/${id}`, { headers: authHeaders() });
      if (res.status === 401) {
        handleLogout();
        return;
      }
      if (res.ok) {
        setSelectedCase(await res.json());
      }
    } catch (err) {
      console.error('Error fetching case detail', err);
    } finally {
      setSelectedCaseLoading(false);
    }
  };

  const handleSelectCase = (item: ConsultationSummary) => {
    if (item.status === 'PENDING_APPROVAL') {
      setOversightAction('');
      setIdentityVerified(false);
      setHistoryVerified(false);
      setNotesVerified(false);
      setOverrideReason('');
    }
    fetchCaseDetail(item.id);
  };

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    if (authInput.trim()) {
      localStorage.setItem('clinician_token', authInput.trim());
      setToken(authInput.trim());
      setErrorMessage(null);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('clinician_token');
    setToken(null);
    setConsultations([]);
    setSelectedCase(null);
  };

  const handleCreateConsultation = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setErrorMessage(null);
    setSuccessMessage(null);

    try {
      const response = await fetch('/api/assessments', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify({
          patient_name: patientName,
          ssn,
          dob,
          symptoms,
          declared_duration: Number(duration),
          insurance_provider: insurance,
        }),
      });

      const result = await response.json();

      if (!response.ok) {
        setErrorMessage(result.detail || 'An error occurred during consultation creation.');
        setLoading(false);
        fetchAllData();
        return;
      }

      setPatientName('');
      setSsn('');
      setDob('');
      setSymptoms('');
      setDuration('');
      setInsurance('PUBLIC');
      setSuccessMessage(`Consultation created successfully for Case ID: ${result.id}`);
      fetchAllData();
    } catch (err) {
      setErrorMessage('Could not connect to the backend server.');
    } finally {
      setLoading(false);
    }
  };

  const handleOversightSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCase) return;

    if (!identityVerified || !historyVerified || !notesVerified) {
      setErrorMessage('All verification checklist items must be manually reviewed and checked.');
      return;
    }

    if (!oversightAction) {
      setErrorMessage('Please select a human oversight action (Approve, Override, or Reject).');
      return;
    }

    if (oversightAction === 'OVERRIDDEN' && (!overrideReason || overrideReason.trim().length < 5)) {
      setErrorMessage('An override justification (minimum 5 characters) is required when changing the AI triage recommendation.');
      return;
    }

    setLoading(true);
    setErrorMessage(null);
    setSuccessMessage(null);

    try {
      const response = await fetch(`/api/assessments/${selectedCase.id}/oversight`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify({
          action: oversightAction,
          clinician_notes: clinicianNotes || "Reviewed and completed.",
          override_reason: oversightAction === 'OVERRIDDEN' ? overrideReason : null,
        }),
      });

      const result = await response.json();

      if (!response.ok) {
        setErrorMessage(result.detail || 'Failed to submit oversight decision.');
      } else {
        setSuccessMessage(`Oversight decision successfully recorded for Case #${selectedCase.id}`);
        // Reset checklist
        setIdentityVerified(false);
        setHistoryVerified(false);
        setNotesVerified(false);
        setOversightAction('');
        setClinicianNotes('');
        setOverrideReason('');
        fetchAllData();
      }
    } catch (err) {
      setErrorMessage('Error communicating with database.');
    } finally {
      setLoading(false);
    }
  };

  const handleResolveRisk = async (riskId: number) => {
    try {
      const response = await fetch(`/api/compliance/risks/${riskId}/resolve`, {
        method: 'POST',
        headers: authHeaders(),
      });
      if (response.ok) {
        fetchAllData();
      }
    } catch (err) {
      console.error(err);
    }
  };

  if (!token) {
    return (
      <div className="login-container">
        <form onSubmit={handleLogin} className="login-card">
          <h1>HealthAssist AI</h1>
          <h3>ISO 42001 & EU AI Act Compliance Portal</h3>
          <p>Sign in using a Clinician Bearer Token. Plaintext credentials are found in <code>database/demo_credentials.json</code> after backend boot.</p>
          <div className="input-group">
            <label>Bearer Token</label>
            <input 
              type="text" 
              placeholder="Paste Dr. Alice's or Dr. Ben's token here" 
              value={authInput} 
              onChange={(e) => setAuthInput(e.target.value)}
              required 
            />
          </div>
          <button type="submit">Authenticate Session</button>
        </form>
      </div>
    );
  }

  return (
    <div className="app-container">
      {/* HEADER */}
      <header className="main-header">
        <div className="header-logo">
          <h1>HealthAssist <span>AI</span></h1>
          <span className="badge-aims">ISO 42001 AIMS Enabled</span>
        </div>
        <div className="header-status">
          <div className="status-item">
            <span className="dot dot-green"></span>
            <span>Clinician: <strong>{localStorage.getItem('clinician_token') ? 'Dr. Active Session' : 'Dr. Guest'}</strong></span>
          </div>
          <button className="btn-logout" onClick={handleLogout}>Revoke Token</button>
        </div>
      </header>

      {/* DISCLOSURE BANNER (ISO 42001 / EU AI Act Art 13) */}
      <div className="disclosure-banner">
        ⚠️ <strong>Notice to Operators:</strong> HealthAssist AI provides triage summaries and recommendations based on algorithmic processing. All outputs are advisory, non-actionable, and pending clinician approval.
      </div>

      {/* MAIN LAYOUT */}
      <div className="main-layout">
        {/* LEFT COLUMN: CASE MANAGEMENT LIST */}
        <section className="column case-list-section">
          <h2>Active Triage Caseload</h2>
          <div className="case-scroll">
            {consultations.length === 0 ? (
              <p className="empty-text">No consultation records. Submit symptoms below.</p>
            ) : (
              consultations.map((item) => (
                <div
                  key={item.id}
                  className={`case-item ${selectedCase?.id === item.id ? 'selected' : ''}`}
                  onClick={() => handleSelectCase(item)}
                >
                  <div className="case-item-header">
                    <span className="case-id">Case #{item.id}</span>
                    <span className={`status-badge status-${item.status.toLowerCase()}`}>
                      {item.status.replace('_', ' ')}
                    </span>
                  </div>
                  <div className="case-item-body">
                    <p><strong>Patient:</strong> {item.patient_name}</p>
                    <p><strong>Symptoms:</strong> {item.symptoms.substring(0, 45)}...</p>
                    <div className="case-item-footer">
                      <span>Triage: <strong className={`risk-${item.ai_risk_level?.toLowerCase()}`}>{item.ai_risk_level}</strong></span>
                      <span className="case-time">{item.created_at.split(' ')[1] || ''}</span>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </section>

        {/* MIDDLE COLUMN: REGISTRATION AND INTAKE FORM */}
        <section className="column intake-section">
          <h2>Patient Symptom Registration</h2>
          <form onSubmit={handleCreateConsultation} className="intake-form">
            <div className="form-row">
              <div className="input-group">
                <label>Patient Name</label>
                <input 
                  type="text" 
                  value={patientName} 
                  onChange={(e) => setPatientName(e.target.value)} 
                  placeholder="e.g. John Doe"
                  required 
                />
              </div>
              <div className="input-group">
                <label>SSN (PII - Encrypted)</label>
                <input 
                  type="text" 
                  value={ssn} 
                  onChange={(e) => setSsn(e.target.value)} 
                  placeholder="XXX-XX-XXXX"
                  required 
                />
              </div>
            </div>

            <div className="form-row">
              <div className="input-group">
                <label>Date of Birth (Encrypted)</label>
                <input 
                  type="text" 
                  value={dob} 
                  onChange={(e) => setDob(e.target.value)} 
                  placeholder="YYYY-MM-DD"
                  required 
                />
              </div>
              <div className="input-group">
                <label>Insurance Provider</label>
                <select value={insurance} onChange={(e) => setInsurance(e.target.value)}>
                  <option value="PUBLIC">PUBLIC Insurance</option>
                  <option value="PRIVATE">PRIVATE Insurance</option>
                </select>
              </div>
            </div>

            <div className="form-row">
              <div className="input-group">
                <label>Symptom Duration (Days)</label>
                <input 
                  type="number" 
                  value={duration} 
                  onChange={(e) => setDuration(e.target.value)} 
                  placeholder="e.g. 5"
                  required 
                />
              </div>
            </div>

            <div className="input-group">
              <label>Symptom Logs / Clinical Notes</label>
              <textarea 
                value={symptoms} 
                onChange={(e) => setSymptoms(e.target.value)} 
                placeholder="Describe patient symptoms. Protected attributes (religion/politics) and PII elements (emails/phones) will be automatically pre-screened and redacted before AI processing."
                rows={4}
                required 
              />
            </div>

            <button type="submit" disabled={loading}>
              {loading ? 'Analyzing Symptoms...' : 'Analyze Symptoms & Register'}
            </button>
          </form>

          {/* Feedback messages */}
          {errorMessage && <div className="alert alert-error">{errorMessage}</div>}
          {successMessage && <div className="alert alert-success">{successMessage}</div>}
        </section>

        {/* RIGHT COLUMN: WORKSPACE TABS */}
        <section className="column workspace-section">
          <nav className="tab-navigation">
            <button 
              className={activeTab === 'details' ? 'active' : ''} 
              onClick={() => setActiveTab('details')}
            >
              Consultation Review
            </button>
            <button 
              className={activeTab === 'compliance' ? 'active' : ''} 
              onClick={() => setActiveTab('compliance')}
            >
              AIMS Compliance
            </button>
            <button 
              className={activeTab === 'instructions' ? 'active' : ''} 
              onClick={() => setActiveTab('instructions')}
            >
              Operator Guide
            </button>
          </nav>

          <div className="tab-content">
            {activeTab === 'details' && (
              <div className="details-tab">
                {selectedCaseLoading ? (
                  <p className="empty-text">Loading case details…</p>
                ) : selectedCase ? (
                  <>
                    <h3>Consultation Case #{selectedCase.id}</h3>
                    <div className="case-pii-card">
                      <h4>Decrypted Patient Details (Authorized Clinician Session)</h4>
                      <p><strong>Name:</strong> {selectedCase.patient_name}</p>
                      <p><strong>SSN:</strong> {selectedCase.ssn}</p>
                      <p><strong>DOB:</strong> {selectedCase.dob}</p>
                      <p><strong>Insurance:</strong> {selectedCase.insurance_provider}</p>
                      <p><strong>Symptoms Duration:</strong> {selectedCase.declared_duration} days</p>
                    </div>

                    <div className="case-analysis-card">
                      <h4>AI Recommendation Summary</h4>
                      <div className="risk-badge-row">
                        <span>Risk Rating: <strong className={`risk-${selectedCase.ai_risk_level?.toLowerCase()}`}>{selectedCase.ai_risk_level}</strong></span>
                        <span>Confidence: <strong>{(selectedCase.ai_confidence * 100).toFixed(0)}%</strong></span>
                      </div>
                      <p className="ai-summary-text">{selectedCase.ai_summary}</p>
                    </div>

                    {selectedCase.status === 'PENDING_APPROVAL' ? (
                      <form onSubmit={handleOversightSubmit} className="oversight-form">
                        <h4>Clinician Human Oversight Checklist</h4>
                        <div className="checklist-group">
                          <label className="checkbox-label">
                            <input 
                              type="checkbox" 
                              checked={identityVerified} 
                              onChange={(e) => setIdentityVerified(e.target.checked)} 
                            />
                            I have verified patient identity against clinical records.
                          </label>
                          <label className="checkbox-label">
                            <input 
                              type="checkbox" 
                              checked={historyVerified} 
                              onChange={(e) => setHistoryVerified(e.target.checked)} 
                            />
                            I have cross-checked medical history with current symptoms.
                          </label>
                          <label className="checkbox-label">
                            <input 
                              type="checkbox" 
                              checked={notesVerified} 
                              onChange={(e) => setNotesVerified(e.target.checked)} 
                            />
                            I have confirmed that the clinical logs are complete.
                          </label>
                        </div>

                        <div className="oversight-actions">
                          <div className="action-selectors">
                            <label>
                              <input 
                                type="radio" 
                                name="oversight_action" 
                                value="APPROVED" 
                                checked={oversightAction === 'APPROVED'}
                                onChange={() => setOversightAction('APPROVED')}
                              />
                              Approve Summary
                            </label>
                            <label>
                              <input 
                                type="radio" 
                                name="oversight_action" 
                                value="OVERRIDDEN" 
                                checked={oversightAction === 'OVERRIDDEN'}
                                onChange={() => setOversightAction('OVERRIDDEN')}
                              />
                              Override Diagnosis
                            </label>
                            <label>
                              <input 
                                type="radio" 
                                name="oversight_action" 
                                value="REJECTED" 
                                checked={oversightAction === 'REJECTED'}
                                onChange={() => setOversightAction('REJECTED')}
                              />
                              Reject Case
                            </label>
                          </div>

                          {oversightAction === 'OVERRIDDEN' && (
                            <div className="input-group">
                              <label>Written Override Rationale *</label>
                              <textarea
                                value={overrideReason}
                                onChange={(e) => setOverrideReason(e.target.value)}
                                placeholder="Explain why you are overriding the AI triage risk assessment level..."
                                rows={2}
                                required
                              />
                            </div>
                          )}

                          <div className="input-group">
                            <label>Clinician Review Notes</label>
                            <input
                              type="text"
                              value={clinicianNotes}
                              onChange={(e) => setClinicianNotes(e.target.value)}
                              placeholder="e.g. Standard care guidelines provided."
                            />
                          </div>

                          <button type="submit" disabled={loading}>Submit Decision</button>
                        </div>
                      </form>
                    ) : (
                      <div className="oversight-completed-card">
                        <h4>✅ Clinician Review Logged</h4>
                        <p><strong>Action:</strong> <span className={`status-badge status-${selectedCase.status.toLowerCase()}`}>{selectedCase.status}</span></p>
                        <p><strong>Reviewer ID:</strong> {selectedCase.clinician_id}</p>
                        {selectedCase.clinician_notes && <p><strong>Notes:</strong> {selectedCase.clinician_notes}</p>}
                        {selectedCase.status === 'OVERRIDDEN' && (
                          <div className="override-reason-box">
                            <strong>Override Rationale:</strong> {selectedCase.clinician_notes}
                          </div>
                        )}
                      </div>
                    )}
                  </>
                ) : (
                  <p className="empty-text">Select a patient consultation case on the left to review details and perform human oversight checkoffs.</p>
                )}
              </div>
            )}

            {activeTab === 'compliance' && (
              <div className="compliance-tab">
                <h3>AIMS Compliance Control Panel</h3>

                {/* OVERRIDE RATE ANALYTICS */}
                <div className="compliance-row">
                  <div className="metric-card">
                    <span className="metric-label">Clinician Override Rate (A.9)</span>
                    <span className="metric-value">
                      {metrics?.human_override_rate !== undefined ? `${metrics.human_override_rate}%` : '0%'}
                    </span>
                    {metrics && metrics.human_override_rate > 30 ? (
                      <span className="text-warning">⚠️ High Override Rate (check model drift)</span>
                    ) : metrics && metrics.human_override_rate > 5 ? (
                      <span className="text-success">🟢 Healthy Clinician-in-the-Loop</span>
                    ) : (
                      <span className="text-error">🔴 Low Override Rate (possible automation bias)</span>
                    )}
                  </div>

                  {/* TAMPER-EVIDENT CHAIN BADGE */}
                  <div className="metric-card">
                    <span className="metric-label">Audit Log Chain Security (A.6)</span>
                    <span className={`chain-badge ${auditChainStatus?.intact ? 'intact' : 'broken'}`}>
                      {auditChainStatus?.intact ? '🟢 Integrity Hashed & Intact' : '🔴 Tampering Detected!'}
                    </span>
                    <span className="metric-subtext">Checked {auditChainStatus?.entries_checked || 0} entries</span>
                  </div>
                </div>

                {/* BIAS DISPARITY (NIST MEASURE) */}
                <div className="bias-card">
                  <h4>Insurance Provider Disparity (NIST AI RMF MEASURE)</h4>
                  {biasMetrics && biasMetrics.by_nationality.length > 0 ? (
                    <div className="bias-table-container">
                      <table className="bias-table">
                        <thead>
                          <tr>
                            <th>Insurance</th>
                            <th>Cases</th>
                            <th>High Risk Rate</th>
                            <th>Ratio to Avg</th>
                            <th>Status</th>
                          </tr>
                        </thead>
                        <tbody>
                          {biasMetrics.by_nationality.map((g) => (
                            <tr key={g.nationality}>
                              <td>{g.nationality}</td>
                              <td>{g.assessments}</td>
                              <td>{(g.high_risk_rate * 100).toFixed(1)}%</td>
                              <td>{g.ratio_to_overall ? `${g.ratio_to_overall}x` : 'N/A'}</td>
                              <td>
                                {g.flagged ? (
                                  <span className="badge-flagged">🔴 Disparity Warning</span>
                                ) : (
                                  <span className="badge-clean">🟢 Compliant</span>
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <p className="empty-text">Insufficient clinical cases scored to calculate disparity metrics (need 5+ cases per insurance class).</p>
                  )}
                </div>

                {/* LIVE RISK REGISTER */}
                <div className="risks-card">
                  <h4>Continuous Risk Register (AIMS Clause 8.2)</h4>
                  <div className="risk-log-container">
                    {metrics && metrics.active_risks.length > 0 ? (
                      metrics.active_risks.map((risk) => (
                        <div key={risk.id} className={`risk-log-item severity-${risk.severity.toLowerCase()}`}>
                          <div className="risk-log-header">
                            <span className="risk-hazard">{risk.hazard_type}</span>
                            <span className="risk-severity">{risk.severity}</span>
                          </div>
                          <p>{risk.details}</p>
                          <button onClick={() => handleResolveRisk(risk.id)}>Mitigated & Resolve</button>
                        </div>
                      ))
                    ) : (
                      <p className="empty-text">No active risk events. System is operating within compliance limits.</p>
                    )}
                  </div>
                </div>

                {/* ACCURACY EVALUATION REPORT */}
                <div className="eval-card">
                  <h4>Clinical Fallback Engine Accuracy Report</h4>
                  {modelEval ? (
                    <div className="eval-grid">
                      <div className="eval-metric">
                        <span className="label">Measured Accuracy</span>
                        <span className="val">{(modelEval.metrics.accuracy * 100).toFixed(0)}%</span>
                      </div>
                      <div className="eval-metric">
                        <span className="label">Precision</span>
                        <span className="val">{modelEval.metrics.precision.toFixed(2)}</span>
                      </div>
                      <div className="eval-metric">
                        <span className="label">Recall</span>
                        <span className="val">{modelEval.metrics.recall.toFixed(2)}</span>
                      </div>
                      <div className="eval-metric">
                        <span className="label">Confusion Matrix</span>
                        <span className="val-sub">
                          TP: {modelEval.confusion.tp} | FP: {modelEval.confusion.fp} | FN: {modelEval.confusion.fn} | TN: {modelEval.confusion.tn}
                        </span>
                      </div>
                    </div>
                  ) : (
                    <p className="empty-text">No evaluation report found.</p>
                  )}
                </div>

                {/* AUDIT LOGS DISPLAY */}
                <div className="eval-card">
                  <h4>Traceability Audit Logs (A.6)</h4>
                  <div className="risk-log-container">
                    {auditLogs.length > 0 ? (
                      auditLogs.map((log) => (
                        <div key={log.id} className="risk-log-item" style={{ borderLeftColor: 'var(--primary)' }}>
                          <div className="risk-log-header">
                            <span>Case #{log.consultation_id} - {log.human_action.replace('_', ' ')}</span>
                            <span>{log.clinician_id}</span>
                          </div>
                          <p style={{ fontSize: '0.75rem', marginBottom: '4px' }}>
                            <strong>Model:</strong> {log.model_name} | <strong>Latency:</strong> {log.api_latency_ms}ms
                          </p>
                          {log.override_reason && (
                            <p style={{ fontSize: '0.75rem', color: 'var(--warning)', marginBottom: '4px' }}>
                              <strong>Override Justification:</strong> {log.override_reason}
                            </p>
                          )}
                          <p className="case-time" style={{ fontSize: '0.7rem' }}>
                            <strong>Prompt Hash:</strong> {log.prompt_hash.substring(0, 32)}...
                          </p>
                        </div>
                      ))
                    ) : (
                      <p className="empty-text">No audit logs recorded yet.</p>
                    )}
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'instructions' && (
              <div className="instructions-tab">
                <h3>Operator & Clinician Guide</h3>
                <p>This portal serves as a Decision Support Interface (DSI) for clinical symptom classification.</p>
                
                <h4>Clinician Oversight Requirements</h4>
                <ul>
                  <li>Clinicians must confirm the identity of the patient on the physical record before checking off approvals.</li>
                  <li>Symptom logs should be cross-referenced with previous records to identify discrepancies in reported duration.</li>
                  <li>Triage level decisions (LOW, MEDIUM, HIGH) generated by AI are purely recommendations. The clinician retains full authority to override.</li>
                </ul>

                <h4>System Disclosures</h4>
                <p>HealthAssist AI is governed by an AI Management System in accordance with ISO 42001:2023. Audit logs are kept for a minimum of 6 months.</p>
              </div>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
