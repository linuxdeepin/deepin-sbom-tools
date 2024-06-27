// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

package log

import (
	"fmt"
	"log"
	"os"
)

// Priority is the data type of log level.
type Priority int

// Definitions of log level, the larger of the value, the higher of
// the priority.
const (
	LevelDisable Priority = iota
	LevelFatal
	LevelPanic
	LevelError
	LevelWarning
	LevelInfo
	LevelDebug
)

type myLog struct {
	log   *log.Logger
	level Priority
}

var logger *myLog

func NewLogger(prefix string, level Priority) {
	logger = &myLog{log: log.New(os.Stdout, prefix, log.LstdFlags|log.Lshortfile), level: LevelWarning}
	logger.level = level
}

func (l *myLog) isNeedLog(level Priority) bool {
	return level <= l.level
}

// SetLogLevel reset the log level.
func SetLogLevel(level Priority) {
	logger.level = level
}

func (l *myLog) Debug(v ...interface{}) {
	if !l.isNeedLog(LevelDebug) {
		return
	}
	l.log.SetPrefix("[Debug] ")
	l.log.Output(3, fmt.Sprintln(v...))
}

func (l *myLog) Debugf(format string, v ...interface{}) {
	if !l.isNeedLog(LevelDebug) {
		return
	}
	l.log.SetPrefix("[Debug] ")
	l.log.Output(3, fmt.Sprintf(format, v...))
}

func (l *myLog) Info(v ...interface{}) {
	if !l.isNeedLog(LevelInfo) {
		return
	}
	l.log.SetPrefix("[Info] ")
	l.log.Output(3, fmt.Sprintln(v...))
}

func (l *myLog) Infof(format string, v ...interface{}) {
	if !l.isNeedLog(LevelInfo) {
		return
	}
	l.log.SetPrefix("[Info] ")
	l.log.Output(3, fmt.Sprintf(format, v...))
}

func (l *myLog) Warning(v ...interface{}) {
	if !l.isNeedLog(LevelWarning) {
		return
	}
	l.log.SetPrefix("[Warning] ")
	l.log.Output(3, fmt.Sprintln(v...))
}

func (l *myLog) Error(v ...interface{}) {
	if !l.isNeedLog(LevelError) {
		return
	}
	l.log.SetPrefix("[Error] ")
	l.log.Output(3, fmt.Sprintln(v...))
}

func (l *myLog) Errorf(format string, v ...interface{}) {
	if !l.isNeedLog(LevelError) {
		return
	}
	l.log.SetPrefix("[Error] ")
	l.log.Output(3, fmt.Sprintf(format, v...))
}

func (l *myLog) Panic(v ...interface{}) {
	s := fmt.Sprint(v...)
	l.log.SetPrefix("[Panic] ")
	l.log.Output(3, s)
	panic(s)
}

func Debug(v ...interface{}) {
	logger.Debug(v...)
}

func Debugf(format string, v ...interface{}) {
	logger.Debugf(format, v...)
}

func Info(v ...interface{}) {
	logger.Info(v...)
}
func Infof(format string, v ...interface{}) {
	logger.Infof(format, v...)
}

func Warning(v ...interface{}) {
	logger.Warning(v...)
}

func Error(v ...interface{}) {
	logger.Error(v...)
}

func Errorf(format string, v ...interface{}) {
	logger.Errorf(format, v...)
}

func Panic(v ...interface{}) {
	logger.Panic(v...)
}
