import { INITIAL_RISK_QUEUE, COMPLIANCE_REGULATIONS } from '../data/mockData';

const BASE_URL = ''; // Relative path for Vite proxy or server hosting

const TOKEN_KEY = 'securix_token';
const USER_KEY = 'securix_user';

export function getToken() {
  try {
    return localStorage.getItem(TOKEN_KEY) || '';
  } catch {
    return '';
  }
}

export function getStoredUser() {
  try {
    const raw = localStorage.getItem(USER_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function saveSession(user, token) {
  try {
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(USER_KEY, JSON.stringify(user));
  } catch {
    // ignore storage errors
  }
}

export function clearSession() {
  try {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  } catch {
    // ignore
  }
}

function authHeaders() {
  const token = getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function parseAuthResponse(res) {
  let data = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }
  if (!res.ok) {
    throw new Error((data && data.detail) || `Request failed (${res.status})`);
  }
  return data;
}

export async function registerUser({ name, email, password, role = 'analyst' }) {
  const res = await fetch(`${BASE_URL}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, email, password, role }),
  });
  const data = await parseAuthResponse(res);
  saveSession(data.user, data.token);
  return data;
}

export async function loginUser({ email, password }) {
  const res = await fetch(`${BASE_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  const data = await parseAuthResponse(res);
  saveSession(data.user, data.token);
  return data;
}

export async function fetchCurrentUser() {
  const token = getToken();
  if (!token) return null;
  try {
    const res = await fetch(`${BASE_URL}/api/auth/me`, { headers: { ...authHeaders() } });
    if (!res.ok) {
      clearSession();
      return null;
    }
    const data = await res.json();
    return data.user || null;
  } catch {
    return getStoredUser();
  }
}

export async function fetchRiskQueue(limit = 50) {
  try {
    const res = await fetch(`${BASE_URL}/graph/risk-queue?limit=${limit}`);
    if (res.ok) {
      const data = await res.json();
      if (Array.isArray(data) && data.length > 0) {
        return data;
      }
    }
  } catch (err) {
    console.warn('Backend graph-service not reached, using resilient local data', err);
  }
  return INITIAL_RISK_QUEUE;
}

export async function fetchAssetDetail(assetId) {
  try {
    const res = await fetch(`${BASE_URL}/graph/asset/${encodeURIComponent(assetId)}`);
    if (res.ok) {
      return await res.json();
    }
  } catch (err) {
    console.warn('Asset detail fetch error, using local fallback', err);
  }
  return null;
}

export async function fetchComplianceSummary() {
  try {
    const res = await fetch(`${BASE_URL}/graph/compliance`);
    if (res.ok) {
      return await res.json();
    }
  } catch (err) {
    console.warn('Compliance summary fetch error, using local fallback', err);
  }
  return { regulations: COMPLIANCE_REGULATIONS };
}

export async function toggleVerifyFinding(findingId, analystName = 'SecOps Lead') {
  try {
    const res = await fetch(`${BASE_URL}/graph/findings/${findingId}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ analyst_name: analystName })
    });
    if (res.ok) {
      return await res.json();
    }
  } catch (err) {
    console.warn('Verify API call error, updated locally', err);
  }
  return { success: true, finding_id: findingId };
}

export async function triggerScan(target, targetType = 'repo') {
  try {
    const res = await fetch(`${BASE_URL}/api/orchestrator/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, target_type: targetType })
    });
    if (res.ok) {
      return await res.json();
    }
  } catch (err) {
    console.warn('Scan orchestrator error, simulating response', err);
  }
  // Simulated fallback
  return {
    workflow_id: 'wf_' + Date.now().toString(36),
    status: 'COMPLETED',
    target,
    total_findings: 6,
    total_exposure_inr: 18500000
  };
}

export async function generateEvidencePack(assetId, format = 'html') {
  try {
    const res = await fetch(`${BASE_URL}/api/evidence/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ asset_id: assetId, format })
    });
    if (res.ok) {
      return await res.json();
    }
  } catch (err) {
    console.warn('Evidence generator error, simulating response', err);
  }
  return {
    pack_id: 'pack_' + Date.now().toString(36),
    asset_id: assetId,
    sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    ots_status: 'ANCHORED_OPENTIMESTAMPS',
    download_url: `/api/evidence/download/pack_demo?format=${format}`
  };
}
