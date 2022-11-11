package proxy

import (
	"github.com/rollbar/rollbar-go"
	"go.uber.org/zap"
)

type Logger struct {
	Zap         *zap.Logger
	Rollbar     *rollbar.Client
	environment string
}

func logger(env string, zapLog *zap.Logger, rollbarToken string) *Logger {
	return &Logger{
		Zap:         zapLog,
		Rollbar:     rollbar.New(rollbarToken, env, "", "", ""),
		environment: env,
	}
}

func (l *Logger) Info(msg string, fields ...zap.Field) {
	l.Zap.Info(msg, fields...)

	if l.environment != "test" {
		extras := make(map[string]any, len(fields))
		for i := range fields {
			extras[fields[i].Key] = fields[i].Interface
		}
		l.Rollbar.MessageWithExtras(rollbar.INFO, msg, extras)
	}
}
