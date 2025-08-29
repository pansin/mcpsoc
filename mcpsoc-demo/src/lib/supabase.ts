import { createClient } from '@supabase/supabase-js'

const supabaseUrl = 'https://xyaogkcqygcwkgkkacej.supabase.co'
const supabaseAnonKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Inh5YW9na2NxeWdjd2tna2thY2VqIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTM3NzYzMjYsImV4cCI6MjA2OTM1MjMyNn0.Nsod_t5Xm3Tb0C49NWbH9fRiB8HaZthwHgvJmJzWjVE'

export const supabase = createClient(supabaseUrl, supabaseAnonKey)

// 数据库类型定义
export interface SecurityEvent {
  id: number
  timestamp: string
  source: string
  event_type: string
  severity: string
  raw_data: any
  processed_data?: any
  entities?: any
  tags?: string[]
  description?: string
  created_at: string
}

export interface ThreatIndicator {
  id: number
  indicator_type: string
  indicator_value: string
  confidence: number
  threat_types?: string[]
  first_seen: string
  last_seen: string
  source: string
  metadata?: any
  expires_at?: string
  is_active: boolean
}

export interface MCPServer {
  id: number
  name: string
  description?: string
  server_type: string
  vendor?: string
  version?: string
  status: string
  endpoint_url?: string
  capabilities?: any
  config?: any
  last_heartbeat?: string
  created_at: string
  updated_at: string
}

export interface Detection {
  id: number
  rule_name: string
  rule_type: string
  severity: string
  event_ids?: number[]
  source_ips?: string[]
  target_ips?: string[]
  description?: string
  details?: any
  status: string
  assigned_to?: string
  created_at: string
  updated_at: string
}

export interface Workflow {
  id: number
  name: string
  description?: string
  workflow_type: string
  trigger_conditions?: any
  actions?: any
  status: string
  execution_count: number
  last_executed?: string
  created_by?: string
  created_at: string
  updated_at: string
}