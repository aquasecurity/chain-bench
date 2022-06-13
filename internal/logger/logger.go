package logger

import (
	"github.com/rs/zerolog"
)

type Logger interface {
	Debug(msg string)
	Debugf(msg string, v ...interface{})
	Info(msg string)
	Infof(msg string, v ...interface{})
	Warn(msg string)
	Warnf(msg string, v ...interface{})
	Error(err error, msg string) error
	Errorf(err error, msg string, v ...interface{}) error
	Panic(msg string)
	Panicf(msg string, v ...interface{})
}

type ArgonLogger struct {
	context string
}

func NewLogger(context string) Logger {
	return &ArgonLogger{context: context}
}

func (l *ArgonLogger) appendFieldsToLogger(event *zerolog.Event) *zerolog.Event {
	return event.Str("context", l.context)
}

func (l *ArgonLogger) Debug(msg string) {
	l.appendFieldsToLogger(logger.Debug()).Msg(msg)
}

func (l *ArgonLogger) Debugf(msg string, v ...interface{}) {
	l.appendFieldsToLogger(logger.Debug()).Msgf(msg, v...)
}

func (l *ArgonLogger) Info(msg string) {
	l.appendFieldsToLogger(logger.Info()).Msg(msg)
}

func (l *ArgonLogger) Infof(msg string, v ...interface{}) {
	l.appendFieldsToLogger(logger.Info()).Msgf(msg, v...)
}

func (l *ArgonLogger) Warn(msg string) {
	l.appendFieldsToLogger(logger.Warn()).Msg(msg)
}

func (l *ArgonLogger) Warnf(msg string, v ...interface{}) {
	l.appendFieldsToLogger(logger.Warn()).Msgf(msg, v...)
}

func (l *ArgonLogger) Error(err error, msg string) error {
	if err != nil {
		l.appendFieldsToLogger(logger.Error()).Str("error", err.Error()).Msg(msg)
	} else {
		l.appendFieldsToLogger(logger.Error()).Msg(msg)
	}
	return err
}

func (l *ArgonLogger) Errorf(err error, msg string, v ...interface{}) error {
	if err != nil {
		l.appendFieldsToLogger(logger.Error()).Str("error", err.Error()).Msgf(msg, v...)
	} else {
		l.appendFieldsToLogger(logger.Error()).Msgf(msg, v...)
	}
	return err
}

func (l *ArgonLogger) Panic(msg string) {
	l.appendFieldsToLogger(logger.Panic()).Msg(msg)
}

func (l *ArgonLogger) Panicf(msg string, v ...interface{}) {
	l.appendFieldsToLogger(logger.Panic()).Msgf(msg, v...)
}
