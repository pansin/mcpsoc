import { useState, useEffect } from 'react'
import { Shield, Search, Activity, AlertTriangle, Server, Eye, BarChart3, Target } from 'lucide-react'
import ThreatMonitor from './components/ThreatMonitor'
import ThreatAnalysis from './components/ThreatAnalysis'
import SystemDashboard from './components/SystemDashboard'
import './App.css'

interface SecurityEvent {
  id: number
  timestamp: string
  source: string
  event_type: string
  severity: string
  src_ip?: string
  dst_ip?: string
  action?: string
  threat_level?: string
}

interface MCPServer {
  id: string
  name: string
  type: string
  status: string
  last_seen: string
}

function App() {
  const [query, setQuery] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [queryResult, setQueryResult] = useState<any>(null)
  const [securityEvents, setSecurityEvents] = useState<SecurityEvent[]>([])
  const [mcpServers, setMcpServers] = useState<MCPServer[]>([])
  const [activeTab, setActiveTab] = useState<'overview' | 'monitor' | 'analysis' | 'dashboard'>('overview')

  // 模拟数据加载
  useEffect(() => {
    // 模拟安全事件数据
    setSecurityEvents([
      {
        id: 1,
        timestamp: new Date(Date.now() - 3600000).toISOString(),
        source: 'firewall',
        event_type: 'connection_blocked',
        severity: 'high',
        src_ip: '192.168.1.100',
        dst_ip: '10.0.0.5',
        action: 'blocked',
        threat_level: 'high'
      },
      {
        id: 2,
        timestamp: new Date(Date.now() - 1800000).toISOString(),
        source: 'waf',
        event_type: 'sql_injection_attempt',
        severity: 'critical',
        src_ip: '203.0.113.10',
        dst_ip: '10.0.0.1',
        action: 'blocked',
        threat_level: 'critical'
      },
      {
        id: 3,
        timestamp: new Date(Date.now() - 900000).toISOString(),
        source: 'antivirus',
        event_type: 'malware_detected',
        severity: 'high',
        action: 'quarantined',
        threat_level: 'high'
      }
    ])

    // 模拟MCP服务器数据
    setMcpServers([
      {
        id: 'firewall-pfsense-01',
        name: 'pfSense Firewall',
        type: 'firewall',
        status: 'connected',
        last_seen: new Date().toISOString()
      },
      {
        id: 'waf-modsecurity-01',
        name: 'ModSecurity WAF',
        type: 'waf',
        status: 'connected',
        last_seen: new Date().toISOString()
      },
      {
        id: 'av-clamav-01',
        name: 'ClamAV Antivirus',
        type: 'antivirus',
        status: 'connected',
        last_seen: new Date().toISOString()
      }
    ])
  }, [])

  const handleQuery = async () => {
    if (!query.trim()) return

    setIsLoading(true)
    
    // 模拟API调用
    setTimeout(() => {
      setQueryResult({
        query_id: 'query-' + Date.now(),
        status: 'completed',
        result: {
          summary: `分析查询: "${query}"`,
          data: [
            {
              timestamp: new Date().toISOString(),
              finding: '发现3个相关的安全事件',
              confidence: 0.92
            }
          ]
        },
        insights: [
          {
            type: 'threat_indicator',
            severity: 'medium',
            message: '检测到可疑的网络活动模式',
            confidence: 0.85
          }
        ],
        actions: [
          {
            action: 'investigate_further',
            target: 'network_traffic',
            reason: '异常流量模式需要进一步调查',
            priority: 'medium'
          }
        ],
        execution_time: 1.2
      })
      setIsLoading(false)
    }, 1500)
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-50'
      case 'high': return 'text-orange-600 bg-orange-50'
      case 'medium': return 'text-yellow-600 bg-yellow-50'
      case 'low': return 'text-green-600 bg-green-50'
      default: return 'text-gray-600 bg-gray-50'
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'connected': return 'text-green-600 bg-green-50'
      case 'disconnected': return 'text-red-600 bg-red-50'
      case 'error': return 'text-red-600 bg-red-50'
      default: return 'text-gray-600 bg-gray-50'
    }
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center">
              <Shield className="h-8 w-8 text-blue-600 mr-3" />
              <h1 className="text-2xl font-bold text-gray-900">MCPSoc</h1>
              <span className="ml-2 text-sm text-gray-500">智能安全运营中心</span>
            </div>
            <div className="flex items-center space-x-4">
              <div className="flex items-center text-sm text-gray-600">
                <Activity className="h-4 w-4 mr-1" />
                系统状态: 正常
              </div>
            </div>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Tab Navigation */}
        <div className="bg-white rounded-lg shadow mb-8">
          <div className="border-b border-gray-200">
            <nav className="flex space-x-8 px-6">
              {[
                { id: 'overview', label: '概览', icon: Eye },
                { id: 'monitor', label: '实时监控', icon: Activity },
                { id: 'analysis', label: '威胁分析', icon: Target },
                { id: 'dashboard', label: '系统监控', icon: BarChart3 }
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`flex items-center py-4 px-1 border-b-2 font-medium text-sm ${
                    activeTab === tab.id
                      ? 'border-blue-500 text-blue-600'
                      : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                  }`}
                >
                  <tab.icon className="h-4 w-4 mr-2" />
                  {tab.label}
                </button>
              ))}
            </nav>
          </div>
        </div>

        {/* Tab Content */}
        {activeTab === 'overview' && (
          <div className="space-y-8">
            {/* Query Interface */}
            <div className="bg-white rounded-lg shadow">
              <div className="p-6">
                <h2 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                  <Search className="h-5 w-5 mr-2" />
                  安全查询
                </h2>
                <div className="flex space-x-4">
                  <input
                    type="text"
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    placeholder="输入您的安全查询，例如：查找过去24小时内的高危威胁事件"
                    className="flex-1 px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    onKeyPress={(e) => e.key === 'Enter' && handleQuery()}
                  />
                  <button
                    onClick={handleQuery}
                    disabled={isLoading}
                    className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center"
                  >
                    {isLoading ? (
                      <>
                        <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                        分析中...
                      </>
                    ) : (
                      <>
                        <Search className="h-4 w-4 mr-2" />
                        查询
                      </>
                    )}
                  </button>
                </div>
              </div>

              {/* Query Results */}
              {queryResult && (
                <div className="border-t p-6">
                  <h3 className="text-md font-semibold text-gray-900 mb-4">查询结果</h3>
                  <div className="bg-gray-50 rounded-lg p-4 mb-4">
                    <p className="text-sm text-gray-700 mb-2">
                      <strong>摘要:</strong> {queryResult.result.summary}
                    </p>
                    <p className="text-sm text-gray-600">
                      执行时间: {queryResult.execution_time}秒
                    </p>
                  </div>

                  {queryResult.insights && queryResult.insights.length > 0 && (
                    <div className="mb-4">
                      <h4 className="text-sm font-semibold text-gray-900 mb-2">威胁洞察</h4>
                      {queryResult.insights.map((insight: any, index: number) => (
                        <div key={index} className="flex items-start space-x-3 p-3 bg-blue-50 rounded-lg mb-2">
                          <AlertTriangle className="h-5 w-5 text-blue-600 mt-0.5" />
                          <div>
                            <p className="text-sm text-gray-900">{insight.message}</p>
                            <p className="text-xs text-gray-600">置信度: {(insight.confidence * 100).toFixed(0)}%</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {queryResult.actions && queryResult.actions.length > 0 && (
                    <div>
                      <h4 className="text-sm font-semibold text-gray-900 mb-2">推荐行动</h4>
                      {queryResult.actions.map((action: any, index: number) => (
                        <div key={index} className="flex items-center justify-between p-3 bg-yellow-50 rounded-lg mb-2">
                          <div>
                            <p className="text-sm text-gray-900">{action.reason}</p>
                            <p className="text-xs text-gray-600">目标: {action.target}</p>
                          </div>
                          <span className={`px-2 py-1 text-xs rounded-full ${
                            action.priority === 'high' ? 'bg-red-100 text-red-800' :
                            action.priority === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                            'bg-green-100 text-green-800'
                          }`}>
                            {action.priority}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              {/* Security Events */}
              <div className="bg-white rounded-lg shadow">
                <div className="p-6">
                  <h2 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                    <AlertTriangle className="h-5 w-5 mr-2" />
                    最新安全事件
                  </h2>
                  <div className="space-y-4">
                    {securityEvents.map((event) => (
                      <div key={event.id} className="border rounded-lg p-4">
                        <div className="flex items-center justify-between mb-2">
                          <span className={`px-2 py-1 text-xs rounded-full ${getSeverityColor(event.severity)}`}>
                            {event.severity}
                          </span>
                          <span className="text-xs text-gray-500">
                            {new Date(event.timestamp).toLocaleString()}
                          </span>
                        </div>
                        <h3 className="text-sm font-semibold text-gray-900 mb-1">
                          {event.event_type.replace(/_/g, ' ').toUpperCase()}
                        </h3>
                        <p className="text-sm text-gray-600 mb-2">
                          来源: {event.source}
                        </p>
                        {event.src_ip && (
                          <div className="text-xs text-gray-500">
                            {event.src_ip} → {event.dst_ip} ({event.action})
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* MCP Servers */}
              <div className="bg-white rounded-lg shadow">
                <div className="p-6">
                  <h2 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                    <Server className="h-5 w-5 mr-2" />
                    MCP 服务器状态
                  </h2>
                  <div className="space-y-4">
                    {mcpServers.map((server) => (
                      <div key={server.id} className="border rounded-lg p-4">
                        <div className="flex items-center justify-between mb-2">
                          <h3 className="text-sm font-semibold text-gray-900">
                            {server.name}
                          </h3>
                          <span className={`px-2 py-1 text-xs rounded-full ${getStatusColor(server.status)}`}>
                            {server.status}
                          </span>
                        </div>
                        <div className="flex items-center justify-between text-xs text-gray-500">
                          <span>类型: {server.type}</span>
                          <span>最后活跃: {new Date(server.last_seen).toLocaleString()}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {/* Statistics */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
              <div className="bg-white rounded-lg shadow p-6">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <AlertTriangle className="h-8 w-8 text-red-600" />
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-500">今日威胁事件</p>
                    <p className="text-2xl font-semibold text-gray-900">23</p>
                  </div>
                </div>
              </div>

              <div className="bg-white rounded-lg shadow p-6">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <Shield className="h-8 w-8 text-green-600" />
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-500">已阻止攻击</p>
                    <p className="text-2xl font-semibold text-gray-900">18</p>
                  </div>
                </div>
              </div>

              <div className="bg-white rounded-lg shadow p-6">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <Server className="h-8 w-8 text-blue-600" />
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-500">活跃服务器</p>
                    <p className="text-2xl font-semibold text-gray-900">{mcpServers.filter(s => s.status === 'connected').length}</p>
                  </div>
                </div>
              </div>

              <div className="bg-white rounded-lg shadow p-6">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <Eye className="h-8 w-8 text-purple-600" />
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-500">今日查询</p>
                    <p className="text-2xl font-semibold text-gray-900">156</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* 实时威胁监控 */}
        {activeTab === 'monitor' && <ThreatMonitor />}

        {/* 威胁分析 */}
        {activeTab === 'analysis' && <ThreatAnalysis />}

        {/* 系统监控仪表板 */}
        {activeTab === 'dashboard' && <SystemDashboard />}
      </div>
    </div>
  )
}

export default App
