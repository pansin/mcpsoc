package logger

import (
	"os"

	"github.com/sirupsen/logrus"
)

// New 创建新的日志实例
func New(level string) *logrus.Logger {
	log := logrus.New()

	// 设置日志级别
	logLevel, err := logrus.ParseLevel(level)
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	log.SetLevel(logLevel)

	// 设置日志格式
	log.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime:  "timestamp",
			logrus.FieldKeyLevel: "level",
			logrus.FieldKeyMsg:   "message",
		},
	})

	// 设置输出
	log.SetOutput(os.Stdout)

	return log
}

// WithComponent 为特定组件创建日志实例
func WithComponent(log *logrus.Logger, component string) *logrus.Entry {
	return log.WithField("component", component)
}