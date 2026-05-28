import axios from 'axios'

// Base URL of our FastAPI backend
const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const api = axios.create({
  baseURL: BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Start a new scan - returns { scan_id, status, poll_url }
export const startScan = async (target, portStart, portEnd, timeout = 1.0) => {
  const response = await api.post('/scan', {
    target,
    port_range_start: portStart,
    port_range_end: portEnd,
    timeout,
  })
  return response.data
}

// Get scan status and results by ID
export const getScan = async (scanId) => {
  const response = await api.get(`/scan/${scanId}`)
  return response.data
}

// Get list of all scans this session
export const listScans = async () => {
  const response = await api.get('/scans')
  return response.data
}

// Delete a scan
export const deleteScan = async (scanId) => {
  await api.delete(`/scan/${scanId}`)
}
