import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

// 格式化时间
export function formatTimestamp(timestamp: string): string {
  const date = new Date(timestamp)
  return date.toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  })
}

// 获取严重程度颜色
export function getSeverityColor(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'text-red-500 bg-red-500/10 border-red-500/20'
    case 'high':
      return 'text-orange-500 bg-orange-500/10 border-orange-500/20'
    case 'medium':
      return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20'
    case 'low':
      return 'text-green-500 bg-green-500/10 border-green-500/20'
    default:
      return 'text-gray-500 bg-gray-500/10 border-gray-500/20'
  }
}

// 获取状态颜色
export function getStatusColor(status: string): string {
  switch (status.toLowerCase()) {
    case 'active':
    case 'resolved':
    case 'contained':
      return 'text-green-500 bg-green-500/10 border-green-500/20'
    case 'investigating':
    case 'monitoring':
      return 'text-blue-500 bg-blue-500/10 border-blue-500/20'
    case 'open':
      return 'text-red-500 bg-red-500/10 border-red-500/20'
    case 'inactive':
      return 'text-gray-500 bg-gray-500/10 border-gray-500/20'
    default:
      return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20'
  }
}