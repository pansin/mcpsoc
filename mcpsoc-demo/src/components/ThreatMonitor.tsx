import React, { useState, useEffect } from 'react'
import { AlertTriangle, Shield, Activity, TrendingUp, Clock, MapPin, Zap } from 'lucide-react'

interface ThreatEvent {
  id: string
  timestamp: string
  type: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  source_ip: string
  target: string
  description: string
  status: 'active' | 'mitigated' | 'investigating'
  location?: string
  attack_vector?: string
  confidence: number
}

interface ThreatStats {
  total_threats: number
  active_threats: number
  mitigated_threats: number
  critical_threats: number
  last_24h_increase: number
}

const ThreatMonitor: React.FC = () => {
  const [threats, setThreats] = useState<ThreatEvent[]>([])
  const [stats, setStats] = useState<ThreatStats>({
    total_threats: 0,
    active_threats: 0,
    mitigated_threats: 0,
    critical_threats: 0,
    last_24h_increase: 0
  })
  const [isRealTime, setIsRealTime] = useState(true)
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all')

  // 模拟实时威胁数据
  useEffect(() => {
    const generateMockThreat = (): ThreatEvent => {
      const types = ['SQL Injection', 'XSS Attack', 'DDoS', 'Malware', 'Brute Force', 'Data Exfiltration']
      const severities: ('low' | 'medium' | 'high' | 'critical')[] = ['low', 'medium', 'high', 'critical']
      const statuses: ('active' | 'mitigated' | 'investigating')[] = ['active', 'mitigated', 'investigating']
      const locations = ['Beijing, CN', 'New York, US', 'London, UK', 'Tokyo, JP', 'Sydney, AU']
      const vectors = ['Web Application', 'Email', 'Network', 'Endpoint', 'Cloud Service']
      
      return {
        id: `threat-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        timestamp: new Date().toISOString(),
        type: types[Math.floor(Math.random() * types.length)],
        severity: severities[Math.floor(Math.random() * severities.length)],
        source_ip: `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
        target: `/api/v1/${['users', 'admin', 'login', 'data', 'files'][Math.floor(Math.random() * 5)]}`,
        description: `检测到来自${locations[Math.floor(Math.random() * locations.length)]}的${types[Math.floor(Math.random() * types.length)]}攻击`,
        status: statuses[Math.floor(Math.random() * statuses.length)],
        location: locations[Math.floor(Math.random() * locations.length)],
        attack_vector: vectors[Math.floor(Math.random() * vectors.length)],
        confidence: Math.random() * 0.4 + 0.6 // 0.6-1.0
      }
    }

    // 初始化威胁数据
    const initialThreats = Array.from({ length: 15 }, generateMockThreat)
    setThreats(initialThreats)

    // 更新统计数据
    const updateStats = (threatList: ThreatEvent[]) => {
      const critical = threatList.filter(t => t.severity === 'critical').length
      const active = threatList.filter(t => t.status === 'active').length
      const mitigated = threatList.filter(t => t.status === 'mitigated').length
      
      setStats({
        total_threats: threatList.length,
        active_threats: active,
        mitigated_threats: mitigated,
        critical_threats: critical,
        last_24h_increase: Math.floor(Math.random() * 20) + 5
      })
    }

    updateStats(initialThreats)

    // 实时数据更新
    const interval = setInterval(() => {
      if (isRealTime) {
        const newThreat = generateMockThreat()
        setThreats(prev => {
          const updated = [newThreat, ...prev].slice(0, 50) // 保持最新50条
          updateStats(updated)
          return updated
        })
      }
    }, 3000) // 每3秒添加新威胁

    return () => clearInterval(interval)
  }, [isRealTime])

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical': return <AlertTriangle className="h-4 w-4 text-red-500" />
      case 'high': return <AlertTriangle className="h-4 w-4 text-orange-500" />
      case 'medium': return <Shield className="h-4 w-4 text-yellow-500" />
      case 'low': return <Shield className="h-4 w-4 text-green-500" />
      default: return <Shield className="h-4 w-4 text-gray-500" />
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-100 text-red-800 border-red-200'
      case 'high': return 'bg-orange-100 text-orange-800 border-orange-200'
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200'
      case 'low': return 'bg-green-100 text-green-800 border-green-200'
      default: return 'bg-gray-100 text-gray-800 border-gray-200'
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'bg-red-100 text-red-800'
      case 'mitigated': return 'bg-green-100 text-green-800'
      case 'investigating': return 'bg-blue-100 text-blue-800'
      default: return 'bg-gray-100 text-gray-800'
    }
  }

  const filteredThreats = threats.filter(threat => 
    selectedSeverity === 'all' || threat.severity === selectedSeverity
  )

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp)
    const now = new Date()
    const diffMs = now.getTime() - date.getTime()
    const diffMins = Math.floor(diffMs / 60000)
    
    if (diffMins < 1) return '刚刚'
    if (diffMins < 60) return `${diffMins}分钟前`
    if (diffMins < 1440) return `${Math.floor(diffMins / 60)}小时前`
    return date.toLocaleDateString('zh-CN')
  }

  return (
    <div className="space-y-6">
      {/* 实时监控头部 */}
      <div className="flex justify-between items-center">
        <div className="flex items-center space-x-4">
          <h2 className="text-xl font-semibold text-gray-900 flex items-center">
            <Activity className="h-6 w-6 mr-2 text-blue-600" />
            实时威胁监控
          </h2>
          <div className="flex items-center space-x-2">
            <div className={`h-3 w-3 rounded-full ${isRealTime ? 'bg-green-500 animate-pulse' : 'bg-gray-400'}`}></div>
            <span className="text-sm text-gray-600">
              {isRealTime ? '实时监控中' : '监控已暂停'}
            </span>
          </div>
        </div>
        
        <div className="flex items-center space-x-4">
          <select 
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="px-3 py-1 border border-gray-300 rounded-md text-sm"
          >
            <option value="all">所有级别</option>
            <option value="critical">严重</option>
            <option value="high">高危</option>
            <option value="medium">中危</option>
            <option value="low">低危</option>
          </select>
          
          <button
            onClick={() => setIsRealTime(!isRealTime)}
            className={`px-4 py-2 rounded-md text-sm font-medium ${
              isRealTime 
                ? 'bg-red-600 text-white hover:bg-red-700' 
                : 'bg-green-600 text-white hover:bg-green-700'
            }`}
          >
            {isRealTime ? '暂停监控' : '启动监控'}
          </button>
        </div>
      </div>

      {/* 威胁统计卡片 */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white p-6 rounded-lg shadow border">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">总威胁数</p>
              <p className="text-2xl font-bold text-gray-900">{stats.total_threats}</p>
            </div>
            <div className="p-3 bg-blue-100 rounded-full">
              <Shield className="h-6 w-6 text-blue-600" />
            </div>
          </div>
          <div className="mt-4 flex items-center">
            <TrendingUp className="h-4 w-4 text-green-500 mr-1" />
            <span className="text-sm text-green-600">+{stats.last_24h_increase} 过去24小时</span>
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg shadow border">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">活跃威胁</p>
              <p className="text-2xl font-bold text-red-600">{stats.active_threats}</p>
            </div>
            <div className="p-3 bg-red-100 rounded-full">
              <AlertTriangle className="h-6 w-6 text-red-600" />
            </div>
          </div>
          <div className="mt-4 flex items-center">
            <Zap className="h-4 w-4 text-red-500 mr-1" />
            <span className="text-sm text-red-600">需要立即处理</span>
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg shadow border">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">已缓解</p>
              <p className="text-2xl font-bold text-green-600">{stats.mitigated_threats}</p>
            </div>
            <div className="p-3 bg-green-100 rounded-full">
              <Shield className="h-6 w-6 text-green-600" />
            </div>
          </div>
          <div className="mt-4 flex items-center">
            <Activity className="h-4 w-4 text-green-500 mr-1" />
            <span className="text-sm text-green-600">威胁已处理</span>
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg shadow border">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">严重威胁</p>
              <p className="text-2xl font-bold text-red-600">{stats.critical_threats}</p>
            </div>
            <div className="p-3 bg-red-100 rounded-full">
              <AlertTriangle className="h-6 w-6 text-red-600" />
            </div>
          </div>
          <div className="mt-4 flex items-center">
            <AlertTriangle className="h-4 w-4 text-red-500 mr-1" />
            <span className="text-sm text-red-600">高优先级处理</span>
          </div>
        </div>
      </div>

      {/* 威胁事件列表 */}
      <div className="bg-white rounded-lg shadow border">
        <div className="p-6 border-b border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900 flex items-center">
            <Clock className="h-5 w-5 mr-2" />
            实时威胁事件 ({filteredThreats.length})
          </h3>
        </div>
        
        <div className="max-h-96 overflow-y-auto">
          {filteredThreats.length === 0 ? (
            <div className="p-8 text-center text-gray-500">
              <Shield className="h-12 w-12 mx-auto mb-4 text-gray-400" />
              <p>当前没有威胁事件</p>
            </div>
          ) : (
            <div className="divide-y divide-gray-200">
              {filteredThreats.map((threat) => (
                <div key={threat.id} className="p-4 hover:bg-gray-50 transition-colors">
                  <div className="flex items-start justify-between">
                    <div className="flex items-start space-x-3">
                      <div className="flex-shrink-0 mt-1">
                        {getSeverityIcon(threat.severity)}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center space-x-2 mb-1">
                          <h4 className="text-sm font-medium text-gray-900">{threat.type}</h4>
                          <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full border ${getSeverityColor(threat.severity)}`}>
                            {threat.severity}
                          </span>
                          <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full ${getStatusColor(threat.status)}`}>
                            {threat.status === 'active' ? '活跃' : threat.status === 'mitigated' ? '已缓解' : '调查中'}
                          </span>
                        </div>
                        <p className="text-sm text-gray-600 mb-2">{threat.description}</p>
                        <div className="flex items-center space-x-4 text-xs text-gray-500">
                          <span>源IP: {threat.source_ip}</span>
                          <span>目标: {threat.target}</span>
                          {threat.location && (
                            <span className="flex items-center">
                              <MapPin className="h-3 w-3 mr-1" />
                              {threat.location}
                            </span>
                          )}
                          <span>置信度: {Math.round(threat.confidence * 100)}%</span>
                        </div>
                      </div>
                    </div>
                    <div className="flex-shrink-0 text-right">
                      <p className="text-xs text-gray-500">{formatTimestamp(threat.timestamp)}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default ThreatMonitor