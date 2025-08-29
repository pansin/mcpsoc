import React, { useState, useEffect } from 'react'
import { BarChart3, PieChart, TrendingUp, MapPin, Clock, Target, Zap, Eye, AlertCircle } from 'lucide-react'

interface ThreatAnalysis {
  id: string
  threat_type: string
  severity: string
  confidence: number
  impact_score: number
  attack_vector: string
  source_location: string
  target_systems: string[]
  ioc_indicators: IOCIndicator[]
  timeline: TimelineEvent[]
  recommendations: Recommendation[]
  related_threats: string[]
}

interface IOCIndicator {
  type: 'ip' | 'domain' | 'hash' | 'url' | 'email'
  value: string
  description: string
  confidence: number
  first_seen: string
  last_seen: string
}

interface TimelineEvent {
  timestamp: string
  event: string
  description: string
  severity: string
}

interface Recommendation {
  action: string
  priority: 'low' | 'medium' | 'high' | 'critical'
  description: string
  estimated_time: string
  success_probability: number
}

interface ThreatStats {
  attack_types: { [key: string]: number }
  severity_distribution: { [key: string]: number }
  hourly_trends: { hour: string; count: number }[]
  geographical_distribution: { country: string; count: number; percentage: number }[]
}

const ThreatAnalysis: React.FC = () => {
  const [selectedThreatId, setSelectedThreatId] = useState<string>('threat-001')
  const [threatAnalysis, setThreatAnalysis] = useState<ThreatAnalysis | null>(null)
  const [threatStats, setThreatStats] = useState<ThreatStats | null>(null)
  const [activeTab, setActiveTab] = useState<'analysis' | 'indicators' | 'timeline' | 'recommendations'>('analysis')

  useEffect(() => {
    // 模拟威胁分析数据
    const mockAnalysis: ThreatAnalysis = {
      id: selectedThreatId,
      threat_type: 'Advanced Persistent Threat (APT)',
      severity: 'critical',
      confidence: 0.94,
      impact_score: 8.7,
      attack_vector: 'Spear Phishing Email',
      source_location: 'Eastern Europe (Estimated)',
      target_systems: ['Web Server', 'Database Server', 'User Workstations'],
      ioc_indicators: [
        {
          type: 'ip',
          value: '185.220.101.42',
          description: 'C&C服务器IP地址',
          confidence: 0.95,
          first_seen: '2024-01-15T08:30:00Z',
          last_seen: '2024-01-18T14:22:00Z'
        },
        {
          type: 'domain',
          value: 'secure-update.net',
          description: '恶意域名，用于钓鱼攻击',
          confidence: 0.88,
          first_seen: '2024-01-14T12:15:00Z',
          last_seen: '2024-01-18T16:45:00Z'
        },
        {
          type: 'hash',
          value: 'e3b0c44298fc1c149afbf4c8996fb924',
          description: '恶意软件文件哈希',
          confidence: 0.92,
          first_seen: '2024-01-15T09:20:00Z',
          last_seen: '2024-01-18T11:30:00Z'
        },
        {
          type: 'email',
          value: 'admin@secure-update.net',
          description: '钓鱼邮件发送者',
          confidence: 0.79,
          first_seen: '2024-01-14T10:05:00Z',
          last_seen: '2024-01-18T15:20:00Z'
        }
      ],
      timeline: [
        {
          timestamp: '2024-01-14T10:00:00Z',
          event: '初始入侵',
          description: '检测到钓鱼邮件发送给多个员工',
          severity: 'medium'
        },
        {
          timestamp: '2024-01-15T08:30:00Z',
          event: '载荷执行',
          description: '恶意软件在受害者机器上执行',
          severity: 'high'
        },
        {
          timestamp: '2024-01-15T12:45:00Z',
          event: '横向移动',
          description: '攻击者尝试访问内网其他系统',
          severity: 'high'
        },
        {
          timestamp: '2024-01-16T14:20:00Z',
          event: '权限提升',
          description: '获得管理员权限',
          severity: 'critical'
        },
        {
          timestamp: '2024-01-17T09:15:00Z',
          event: '数据窃取',
          description: '开始窃取敏感数据',
          severity: 'critical'
        },
        {
          timestamp: '2024-01-18T16:30:00Z',
          event: '威胁发现',
          description: 'SOC团队发现并开始响应',
          severity: 'medium'
        }
      ],
      recommendations: [
        {
          action: '立即隔离受感染系统',
          priority: 'critical',
          description: '断开受感染主机的网络连接，防止进一步传播',
          estimated_time: '立即执行',
          success_probability: 0.95
        },
        {
          action: '封锁恶意IP和域名',
          priority: 'critical',
          description: '在防火墙和DNS服务器中封锁已识别的IOC',
          estimated_time: '30分钟',
          success_probability: 0.90
        },
        {
          action: '重置受影响用户密码',
          priority: 'high',
          description: '强制重置所有潜在受影响用户的密码',
          estimated_time: '2小时',
          success_probability: 0.85
        },
        {
          action: '全网恶意软件扫描',
          priority: 'high',
          description: '在所有系统上运行全面的恶意软件扫描',
          estimated_time: '4小时',
          success_probability: 0.80
        },
        {
          action: '加强邮件安全策略',
          priority: 'medium',
          description: '更新邮件过滤规则，防止类似攻击',
          estimated_time: '1天',
          success_probability: 0.75
        }
      ],
      related_threats: ['threat-002', 'threat-005', 'threat-012']
    }

    // 模拟威胁统计数据
    const mockStats: ThreatStats = {
      attack_types: {
        'SQL注入': 25,
        'XSS攻击': 18,
        '恶意软件': 22,
        'DDoS攻击': 15,
        '钓鱼攻击': 12,
        '暴力破解': 8
      },
      severity_distribution: {
        '严重': 12,
        '高危': 28,
        '中危': 45,
        '低危': 15
      },
      hourly_trends: [
        { hour: '00:00', count: 5 },
        { hour: '02:00', count: 3 },
        { hour: '04:00', count: 2 },
        { hour: '06:00', count: 8 },
        { hour: '08:00', count: 15 },
        { hour: '10:00', count: 22 },
        { hour: '12:00', count: 18 },
        { hour: '14:00', count: 25 },
        { hour: '16:00', count: 20 },
        { hour: '18:00', count: 12 },
        { hour: '20:00', count: 8 },
        { hour: '22:00', count: 6 }
      ],
      geographical_distribution: [
        { country: '中国', count: 35, percentage: 35 },
        { country: '美国', count: 25, percentage: 25 },
        { country: '俄罗斯', count: 15, percentage: 15 },
        { country: '德国', count: 10, percentage: 10 },
        { country: '其他', count: 15, percentage: 15 }
      ]
    }

    setThreatAnalysis(mockAnalysis)
    setThreatStats(mockStats)
  }, [selectedThreatId])

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'critical': return 'bg-red-100 text-red-800 border-red-200'
      case 'high': return 'bg-orange-100 text-orange-800 border-orange-200'
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200'
      case 'low': return 'bg-green-100 text-green-800 border-green-200'
      default: return 'bg-gray-100 text-gray-800 border-gray-200'
    }
  }

  const getIOCIcon = (type: string) => {
    switch (type) {
      case 'ip': return <Target className="h-4 w-4" />
      case 'domain': return <MapPin className="h-4 w-4" />
      case 'hash': return <Eye className="h-4 w-4" />
      case 'url': return <Target className="h-4 w-4" />
      case 'email': return <AlertCircle className="h-4 w-4" />
      default: return <Target className="h-4 w-4" />
    }
  }

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString('zh-CN')
  }

  if (!threatAnalysis || !threatStats) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* 威胁分析头部 */}
      <div className="bg-white rounded-lg shadow border p-6">
        <div className="flex justify-between items-start">
          <div>
            <h2 className="text-xl font-semibold text-gray-900 mb-2">
              威胁深度分析
            </h2>
            <div className="flex items-center space-x-4 text-sm text-gray-600">
              <span>威胁ID: {threatAnalysis.id}</span>
              <span>类型: {threatAnalysis.threat_type}</span>
              <span className={`px-2 py-1 rounded-full ${getPriorityColor(threatAnalysis.severity)}`}>
                {threatAnalysis.severity}
              </span>
            </div>
          </div>
          <div className="text-right">
            <div className="text-2xl font-bold text-red-600">{Math.round(threatAnalysis.confidence * 100)}%</div>
            <div className="text-sm text-gray-600">置信度</div>
          </div>
        </div>

        {/* 威胁摘要指标 */}
        <div className="mt-6 grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-gray-50 p-4 rounded-lg">
            <div className="text-sm text-gray-600">影响评分</div>
            <div className="text-xl font-bold text-orange-600">{threatAnalysis.impact_score}/10</div>
          </div>
          <div className="bg-gray-50 p-4 rounded-lg">
            <div className="text-sm text-gray-600">攻击向量</div>
            <div className="text-sm font-medium text-gray-900">{threatAnalysis.attack_vector}</div>
          </div>
          <div className="bg-gray-50 p-4 rounded-lg">
            <div className="text-sm text-gray-600">源位置</div>
            <div className="text-sm font-medium text-gray-900">{threatAnalysis.source_location}</div>
          </div>
          <div className="bg-gray-50 p-4 rounded-lg">
            <div className="text-sm text-gray-600">受影响系统</div>
            <div className="text-sm font-medium text-gray-900">{threatAnalysis.target_systems.length}个</div>
          </div>
        </div>
      </div>

      {/* Tab导航 */}
      <div className="bg-white rounded-lg shadow border">
        <div className="border-b border-gray-200">
          <nav className="flex space-x-8 px-6">
            {[
              { id: 'analysis', label: '威胁分析', icon: BarChart3 },
              { id: 'indicators', label: 'IOC指标', icon: Target },
              { id: 'timeline', label: '攻击时间线', icon: Clock },
              { id: 'recommendations', label: '响应建议', icon: Zap }
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

        <div className="p-6">
          {/* 威胁分析Tab */}
          {activeTab === 'analysis' && (
            <div className="space-y-6">
              {/* 攻击类型分布 */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">攻击类型分布</h3>
                  <div className="space-y-3">
                    {Object.entries(threatStats.attack_types).map(([type, count]) => (
                      <div key={type} className="flex items-center justify-between">
                        <span className="text-sm text-gray-700">{type}</span>
                        <div className="flex items-center space-x-2">
                          <div className="w-24 bg-gray-200 rounded-full h-2">
                            <div 
                              className="bg-blue-600 h-2 rounded-full" 
                              style={{ width: `${(count / Math.max(...Object.values(threatStats.attack_types))) * 100}%` }}
                            ></div>
                          </div>
                          <span className="text-sm font-medium text-gray-900 w-8">{count}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">严重程度分布</h3>
                  <div className="space-y-3">
                    {Object.entries(threatStats.severity_distribution).map(([severity, count]) => (
                      <div key={severity} className="flex items-center justify-between">
                        <span className="text-sm text-gray-700">{severity}</span>
                        <div className="flex items-center space-x-2">
                          <div className="w-24 bg-gray-200 rounded-full h-2">
                            <div 
                              className={`h-2 rounded-full ${
                                severity === '严重' ? 'bg-red-600' :
                                severity === '高危' ? 'bg-orange-600' :
                                severity === '中危' ? 'bg-yellow-600' : 'bg-green-600'
                              }`}
                              style={{ width: `${(count / Math.max(...Object.values(threatStats.severity_distribution))) * 100}%` }}
                            ></div>
                          </div>
                          <span className="text-sm font-medium text-gray-900 w-8">{count}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* 地理分布 */}
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-4">地理位置分布</h3>
                <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
                  {threatStats.geographical_distribution.map((geo) => (
                    <div key={geo.country} className="bg-gray-50 p-4 rounded-lg text-center">
                      <div className="text-lg font-bold text-gray-900">{geo.count}</div>
                      <div className="text-sm text-gray-600">{geo.country}</div>
                      <div className="text-xs text-gray-500">{geo.percentage}%</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* IOC指标Tab */}
          {activeTab === 'indicators' && (
            <div>
              <h3 className="text-lg font-semibold text-gray-900 mb-4">威胁指标 (IOC)</h3>
              <div className="space-y-4">
                {threatAnalysis.ioc_indicators.map((ioc, index) => (
                  <div key={index} className="border border-gray-200 rounded-lg p-4">
                    <div className="flex items-start justify-between">
                      <div className="flex items-start space-x-3">
                        <div className="flex-shrink-0 mt-1">
                          {getIOCIcon(ioc.type)}
                        </div>
                        <div className="flex-1">
                          <div className="flex items-center space-x-2 mb-2">
                            <span className="font-mono text-sm bg-gray-100 px-2 py-1 rounded">
                              {ioc.value}
                            </span>
                            <span className="px-2 py-1 text-xs font-medium bg-blue-100 text-blue-800 rounded">
                              {ioc.type.toUpperCase()}
                            </span>
                          </div>
                          <p className="text-sm text-gray-700 mb-2">{ioc.description}</p>
                          <div className="flex items-center space-x-4 text-xs text-gray-500">
                            <span>首次发现: {formatTimestamp(ioc.first_seen)}</span>
                            <span>最近发现: {formatTimestamp(ioc.last_seen)}</span>
                          </div>
                        </div>
                      </div>
                      <div className="flex-shrink-0 text-right">
                        <div className="text-sm font-medium text-gray-900">
                          {Math.round(ioc.confidence * 100)}%
                        </div>
                        <div className="text-xs text-gray-500">置信度</div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 时间线Tab */}
          {activeTab === 'timeline' && (
            <div>
              <h3 className="text-lg font-semibold text-gray-900 mb-4">攻击时间线</h3>
              <div className="space-y-4">
                {threatAnalysis.timeline.map((event, index) => (
                  <div key={index} className="flex items-start space-x-4">
                    <div className="flex-shrink-0 w-2 h-2 bg-blue-600 rounded-full mt-2"></div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center space-x-2 mb-1">
                        <h4 className="text-sm font-medium text-gray-900">{event.event}</h4>
                        <span className={`px-2 py-1 text-xs font-medium rounded-full ${getPriorityColor(event.severity)}`}>
                          {event.severity}
                        </span>
                      </div>
                      <p className="text-sm text-gray-700 mb-1">{event.description}</p>
                      <p className="text-xs text-gray-500">{formatTimestamp(event.timestamp)}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 响应建议Tab */}
          {activeTab === 'recommendations' && (
            <div>
              <h3 className="text-lg font-semibold text-gray-900 mb-4">响应建议</h3>
              <div className="space-y-4">
                {threatAnalysis.recommendations.map((rec, index) => (
                  <div key={index} className="border border-gray-200 rounded-lg p-4">
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex items-center space-x-2">
                        <h4 className="text-sm font-medium text-gray-900">{rec.action}</h4>
                        <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getPriorityColor(rec.priority)}`}>
                          {rec.priority}
                        </span>
                      </div>
                      <div className="text-right">
                        <div className="text-sm font-medium text-green-600">
                          {Math.round(rec.success_probability * 100)}%
                        </div>
                        <div className="text-xs text-gray-500">成功率</div>
                      </div>
                    </div>
                    <p className="text-sm text-gray-700 mb-2">{rec.description}</p>
                    <div className="flex items-center justify-between text-xs text-gray-500">
                      <span>预计时间: {rec.estimated_time}</span>
                      <button className="px-3 py-1 bg-blue-600 text-white rounded text-xs hover:bg-blue-700">
                        执行操作
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default ThreatAnalysis