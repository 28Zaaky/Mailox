export interface VulnerabilityOut {
  id: string
  cve_id: string
  title: string | null
  description: string | null
  published_at: string | null
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | null
  cvss_v3_score: number | null
  in_cisa_kev: boolean
  exploit_available: boolean
  relevance: string
  affected_product_count: number
}

export interface AffectedRangeOut {
  product_name: string
  introduced_version: string | null
  fixed_version: string | null
  last_affected_version: string | null
  version_type: string
  version_constraints: string[]
}

export interface VulnerabilityDetail extends VulnerabilityOut {
  cvss_v3_vector: string | null
  cwe_ids: string[]
  references: string[]
  exploit_references: string[]
  kev_date_added: string | null
  kev_required_action: string | null
  kev_due_date: string | null
  affected_ranges: AffectedRangeOut[]
  sources: Array<{ source_name: string; source_url: string | null; retrieved_at: string }>
}

export interface ProductOut {
  id: string
  canonical_name: string
  vendor: string | null
  category: string
  aliases: string[]
  cve_count: number
}

export interface SyncStatusOut {
  source_name: string
  last_sync_at: string | null
  last_success_at: string | null
  total_fetched: number
  records_added: number
  records_updated: number
  records_failed: number
  is_running: boolean
  error_msg: string | null
}

export interface VulnListResponse {
  items: VulnerabilityOut[]
  total: number
  page: number
  per_page: number
}

export interface VulnFilters {
  severity?: string[]
  in_cisa_kev?: boolean
  exploit_available?: boolean
  search?: string
  page?: number
  per_page?: number
  product?: string
}
