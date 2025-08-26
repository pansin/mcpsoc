import React, { useState, useEffect } from 'react'
import { Server, Wifi, Activity, AlertTriangle, CheckCircle, XCircle, Clock, BarChart3 } from 'lucide-react'

interface MCPServerStatus {
  id: string
  name: string
  type: string
  status: 'connected' | 'disconnected' | 'error' | 'warning'
  last_seen: string
  uptime: string
  response_time: number
  requests_per_minute: number
  error_rate: number
  version: string
  capabilities: string[]
  health_checks: HealthCheck[]
}

interface HealthCheck {
  name: string
  status: 'healthy' | 'warning' | 'critical'
  message: string
  last_check: string
}

interface SystemMetrics {
  cpu_usage: number
  memory_usage: number
  disk_usage: number
  network_in: number
  network_out: number
  active_connections: number
  total_requests: number
  error_count: number
}

const SystemDashboard: React.FC = () => {
  const [mcpServers, setMcpServers] = useState<MCPServerStatus[]>([])
  const [systemMetrics, setSystemMetrics] = useState<SystemMetrics | null>(null)
  const [selectedServer, setSelectedServer] = useState<string | null>(null)
  const [isAutoRefresh, setIsAutoRefresh] = useState(true)

  useEffect(() => {
    // 模拟MCP服务器数据
    const mockServers: MCPServerStatus[] = [
      {
        id: 'pfsense-firewall-01',
        name: 'pfSense Firewall',
        type: 'firewall',
        status: 'connected',
        last_seen: new Date().toISOString(),
        uptime: '15d 8h 32m',
        response_time: 45,
        requests_per_minute: 120,
        error_rate: 0.2,
        version: '1.0.0',
        capabilities: ['block_ip', 'get_firewall_logs', 'update_rules'],
        health_checks: [
          { name: 'API响应', status: 'healthy', message: '正常响应', last_check: new Date().toISOString() },
          { name: '规则同步', status: 'healthy', message: '规则已同步', last_check: new Date().toISOString() },
          { name: '日志收集', status: 'warning', message: '日志延迟5分钟', last_check: new Date().toISOString() }
        ]
      },
      {
        id: 'modsecurity-waf-01',
        name: 'ModSecurity WAF',
        type: 'waf',
        status: 'connected',
        last_seen: new Date().toISOString(),
        uptime: '8d 14h 22m',
        response_time: 32,
        requests_per_minute: 850,
        error_rate: 0.1,
        version: '1.0.0',
        capabilities: ['analyze_request', 'block_ip', 'get_attack_logs'],
        health_checks: [
          { name: '威胁检测', status: 'healthy', message: '检测引擎正常', last_check: new Date().toISOString() },
          { name: '规则更新', status: 'healthy', message: '规则库最新', last_check: new Date().toISOString() },
          { name: '性能监控', status: 'healthy', message: '性能良好', last_check: new Date().toISOString() }
        ]
      },
      {
        id: 'clamav-antivirus-01',
        name: 'ClamAV Antivirus',
        type: 'antivirus',
        status: 'connected',
        last_seen: new Date().toISOString(),
        uptime: '12d 3h 45m',
        response_time: 78,
        requests_per_minute: 45,
        error_rate: 0.05,
        version: '1.0.0',
        capabilities: ['scan_file', 'scan_directory', 'update_database'],
        health_checks: [
          { name: '病毒库', status: 'healthy', message: '病毒库已更新', last_check: new Date().toISOString() },
          { name: '扫描引擎', status: 'healthy', message: '扫描引擎正常', last_check: new Date().toISOString() },
          { name: '隔离功能', status: 'healthy', message: '隔离功能正常', last_check: new Date().toISOString() }
        ]
      },
      {
        id: 'threat-intel-01',
        name: 'Threat Intelligence',
        type: 'threat_intel',
        status: 'warning',
        last_seen: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
        uptime: '25d 12h 18m',
        response_time: 156,
        requests_per_minute: 28,
        error_rate: 1.2,
        version: '1.0.0',
        capabilities: ['query_ioc', 'check_reputation', 'get_threat_feed'],
        health_checks: [
          { name: 'IOC数据库', status: 'healthy', message: 'IOC数据库正常', last_check: new Date().toISOString() },
          { name: '威胁源', status: 'warning', message: '部分威胁源连接超时', last_check: new Date().toISOString() },
          { name: 'API限制', status: 'warning', message: '接近API调用限制', last_check: new Date().toISOString() }
        ]
      }
    ]

    // 模拟系统指标
    const mockMetrics: SystemMetrics = {
      cpu_usage: 45 + Math.random() * 10,
      memory_usage: 68 + Math.random() * 10,
      disk_usage: 72 + Math.random() * 5,
      network_in: 1200 + Math.random() * 200,
      network_out: 850 + Math.random() * 150,
      active_connections: 156 + Math.floor(Math.random() * 20),
      total_requests: 12450 + Math.floor(Math.random() * 100),
      error_count: 23 + Math.floor(Math.random() * 5)
    }

    setMcpServers(mockServers)
    setSystemMetrics(mockMetrics)

    // 自动刷新数据
    const interval = setInterval(() => {
      if (isAutoRefresh) {
        // 更新系统指标
        setSystemMetrics(prev => prev ? {
          ...prev,
          cpu_usage: Math.max(0, Math.min(100, prev.cpu_usage + (Math.random() - 0.5) * 10)),
          memory_usage: Math.max(0, Math.min(100, prev.memory_usage + (Math.random() - 0.5) * 5)),
          network_in: Math.max(0, prev.network_in + (Math.random() - 0.5) * 100),
          network_out: Math.max(0, prev.network_out + (Math.random() - 0.5) * 100),
          active_connections: Math.max(0, prev.active_connections + Math.floor((Math.random() - 0.5) * 10)),
          total_requests: prev.total_requests + Math.floor(Math.random() * 10)
        } : null)

        // 更新服务器响应时间
        setMcpServers(prev => prev.map(server => ({
          ...server,
          response_time: Math.max(10, server.response_time + (Math.random() - 0.5) * 20),
          requests_per_minute: Math.max(0, server.requests_per_minute + (Math.random() - 0.5) * 20)
        })))
      }
    }, 2000)

    return () => clearInterval(interval)
  }, [isAutoRefresh])

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'connected': return <CheckCircle className="h-5 w-5 text-green-500" />
      case 'warning': return <AlertTriangle className="h-5 w-5 text-yellow-500" />
      case 'error': 
      case 'disconnected': return <XCircle className="h-5 w-5 text-red-500" />
      default: return <AlertTriangle className="h-5 w-5 text-gray-500" />
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'connected': return 'bg-green-100 text-green-800 border-green-200'
      case 'warning': return 'bg-yellow-100 text-yellow-800 border-yellow-200'
      case 'error':
      case 'disconnected': return 'bg-red-100 text-red-800 border-red-200'
      default: return 'bg-gray-100 text-gray-800 border-gray-200'
    }
  }

  const getHealthStatusColor = (status: string) => {
    switch (status) {
      case 'healthy': return 'text-green-600'
      case 'warning': return 'text-yellow-600'
      case 'critical': return 'text-red-600'
      default: return 'text-gray-600'
    }
  }

  const formatUptime = (uptime: string) => {
    return uptime
  }

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
  }

  if (!systemMetrics) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* 系统监控头部 */}
      <div className="flex justify-between items-center">
        <h2 className="text-xl font-semibold text-gray-900 flex items-center">
          <BarChart3 className="h-6 w-6 mr-2 text-blue-600" />
          系统监控仪表板
        </h2>
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <div className={`h-3 w-3 rounded-full ${isAutoRefresh ? 'bg-green-500 animate-pulse' : 'bg-gray-400'}`}></div>
            <span className="text-sm text-gray-600">
              {isAutoRefresh ? '自动刷新' : '已暂停'}
            </span>
          </div>
          <button
            onClick={() => setIsAutoRefresh(!isAutoRefresh)}
            className={`px-4 py-2 rounded-md text-sm font-medium ${
              isAutoRefresh 
                ? 'bg-red-600 text-white hover:bg-red-700' 
                : 'bg-green-600 text-white hover:bg-green-700'
            }`}
          >
            {isAutoRefresh ? '暂停刷新' : '开启刷新'}
          </button>
        </div>
      </div>

      {/* 系统指标卡片 */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white p-6 rounded-lg shadow border">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">CPU使用率</p>
              <p className="text-2xl font-bold text-blue-600">{systemMetrics.cpu_usage.toFixed(1)}%</p>
            </div>
            <div className="p-3 bg-blue-100 rounded-full">
              <Activity className="h-6 w-6 text-blue-600" />
            </div>
          </div>
          <div className="mt-4">
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div 
                className="bg-blue-600 h-2 rounded-full transition-all duration-300" 
                style={{ width: `${systemMetrics.cpu_usage}%` }}
              ></div>
            </div>
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg shadow border">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">内存使用率</p>
              <p className="text-2xl font-bold text-green-600">{systemMetrics.memory_usage.toFixed(1)}%</p>
            </div>
            <div className="p-3 bg-green-100 rounded-full">
              <BarChart3 className="h-6 w-6 text-green-600" />
            </div>
          </div>
          <div className="mt-4">
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div 
                className="bg-green-600 h-2 rounded-full transition-all duration-300" 
                style={{ width: `${systemMetrics.memory_usage}%` }}
              ></div>
            </div>
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg shadow border">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">活跃连接</p>
              <p className="text-2xl font-bold text-purple-600">{systemMetrics.active_connections}</p>
            </div>
            <div className="p-3 bg-purple-100 rounded-full">
              <Wifi className="h-6 w-6 text-purple-600" />
            </div>
          </div>
          <div className="mt-4 flex items-center">
            <span className="text-sm text-gray-600">
              网络: ↑{formatBytes(systemMetrics.network_out)}/s ↓{formatBytes(systemMetrics.network_in)}/s
            </span>
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg shadow border">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">总请求数</p>
              <p className="text-2xl font-bold text-orange-600">{systemMetrics.total_requests.toLocaleString()}</p>
            </div>
            <div className="p-3 bg-orange-100 rounded-full">
              <Activity className="h-6 w-6 text-orange-600" />
            </div>
          </div>
          <div className="mt-4 flex items-center">
            <span className="text-sm text-red-600">
              错误: {systemMetrics.error_count}
            </span>
          </div>
        </div>
      </div>

      {/* MCP服务器状态 */}
      <div className="bg-white rounded-lg shadow border">
        <div className="p-6 border-b border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900 flex items-center">
            <Server className="h-5 w-5 mr-2" />
            MCP服务器状态 ({mcpServers.length})
          </h3>
        </div>
        
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 p-6">
          {mcpServers.map((server) => (
            <div 
              key={server.id} 
              className={`border rounded-lg p-4 cursor-pointer transition-all ${
                selectedServer === server.id ? 'border-blue-500 bg-blue-50' : 'border-gray-200 hover:border-gray-300'
              }`}
              onClick={() => setSelectedServer(selectedServer === server.id ? null : server.id)}
            >
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center space-x-3">
                  {getStatusIcon(server.status)}
                  <div>
                    <h4 className="text-sm font-medium text-gray-900">{server.name}</h4>
                    <p className="text-xs text-gray-500">{server.type} • {server.version}</p>
                  </div>
                </div>
                <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full border ${getStatusColor(server.status)}`}>
                  {server.status === 'connected' ? '已连接' : 
                   server.status === 'warning' ? '警告' : 
                   server.status === 'error' ? '错误' : '已断开'}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-gray-600">运行时间:</span>
                  <span className="ml-1 font-medium">{formatUptime(server.uptime)}</span>
                </div>
                <div>
                  <span className="text-gray-600">响应时间:</span>
                  <span className="ml-1 font-medium">{server.response_time.toFixed(0)}ms</span>
                </div>
                <div>
                  <span className="text-gray-600">请求/分钟:</span>
                  <span className="ml-1 font-medium">{server.requests_per_minute.toFixed(0)}</span>
                </div>
                <div>
                  <span className="text-gray-600">错误率:</span>
                  <span className="ml-1 font-medium">{server.error_rate.toFixed(1)}%</span>
                </div>
              </div>

              {/* 展开的详细信息 */}
              {selectedServer === server.id && (
                <div className="mt-4 pt-4 border-t border-gray-200">
                  <div className="space-y-3">
                    <div>
                      <h5 className="text-sm font-medium text-gray-900 mb-2">健康检查</h5>
                      <div className="space-y-1">
                        {server.health_checks.map((check, index) => (
                          <div key={index} className="flex items-center justify-between text-sm">
                            <span className="text-gray-700">{check.name}</span>
                            <div className="flex items-center space-x-2">
                              <span className={`font-medium ${getHealthStatusColor(check.status)}`}>
                                {check.status === 'healthy' ? '正常' : 
                                 check.status === 'warning' ? '警告' : '严重'}
                              </span>
                              <span className="text-gray-500">•</span>
                              <span className="text-gray-500">{check.message}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div>
                      <h5 className="text-sm font-medium text-gray-900 mb-2">可用功能</h5>
                      <div className="flex flex-wrap gap-1">
                        {server.capabilities.map((capability) => (
                          <span 
                            key={capability}
                            className="px-2 py-1 text-xs bg-gray-100 text-gray-700 rounded"
                          >
                            {capability}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div className="flex items-center justify-between text-xs text-gray-500">
                      <span>
                        最后更新: {new Date(server.last_seen).toLocaleString('zh-CN')}
                      </span>
                      <div className="flex space-x-2">
                        <button className="px-2 py-1 bg-blue-600 text-white rounded text-xs hover:bg-blue-700">
                          重启
                        </button>
                        <button className="px-2 py-1 bg-gray-600 text-white rounded text-xs hover:bg-gray-700">
                          日志
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default SystemDashboard