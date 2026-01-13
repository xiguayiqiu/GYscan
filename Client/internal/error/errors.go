package error

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
)

type ErrorCode int

const (
	ErrSuccess ErrorCode = iota
	ErrInvalidArgs
	ErrConnectionFailed
	ErrAuthFailed
	ErrTimeout
	ErrNotFound
	ErrPermissionDenied
	ErrInternal
	ErrFileNotFound
	ErrNetworkError
	ErrValidationFailed
	ErrModuleNotFound
)

type GYscanError struct {
	Code     ErrorCode
	Message  string
	Module   string
	Details  interface{}
	ExitCode int
}

func (e *GYscanError) Error() string {
	return fmt.Sprintf("[%s] %s", e.Module, e.Message)
}

func (e *GYscanError) Unwrap() error {
	return errors.New(e.Message)
}

func New(code ErrorCode, module string, format string, args ...interface{}) *GYscanError {
	return &GYscanError{
		Code:     code,
		Module:   module,
		Message:  fmt.Sprintf(format, args...),
		ExitCode: getExitCode(code),
	}
}

func getExitCode(code ErrorCode) int {
	switch code {
	case ErrSuccess:
		return 0
	case ErrInvalidArgs, ErrValidationFailed:
		return 1
	case ErrAuthFailed, ErrPermissionDenied:
		return 2
	case ErrConnectionFailed, ErrTimeout, ErrNetworkError:
		return 3
	case ErrNotFound, ErrFileNotFound, ErrModuleNotFound:
		return 4
	default:
		return 1
	}
}

func (e *GYscanError) Handle() {
	PrintError(e)
	os.Exit(e.ExitCode)
}

func PrintError(err error) {
	if e, ok := err.(*GYscanError); ok {
		switch e.Code {
		case ErrAuthFailed:
			fmt.Fprintf(os.Stderr, "[-] 认证失败: %s\n", e.Message)
		case ErrTimeout:
			fmt.Fprintf(os.Stderr, "[-] 操作超时: %s\n", e.Message)
		case ErrPermissionDenied:
			fmt.Fprintf(os.Stderr, "[-] 权限不足: %s\n", e.Message)
		case ErrConnectionFailed:
			fmt.Fprintf(os.Stderr, "[-] 连接失败: %s\n", e.Message)
		case ErrNotFound:
			fmt.Fprintf(os.Stderr, "[-] 未找到: %s\n", e.Message)
		case ErrInvalidArgs:
			fmt.Fprintf(os.Stderr, "[-] 无效参数: %s\n", e.Message)
		default:
			fmt.Fprintf(os.Stderr, "[-] 错误: %s\n", e.Message)
		}
		if e.Details != nil {
			fmt.Fprintf(os.Stderr, "    详情: %v\n", e.Details)
		}
		return
	}
	fmt.Fprintf(os.Stderr, "[-] 错误: %v\n", err)
}

type ErrorHandler struct {
	Module    string
	DebugMode bool
}

func NewHandler(module string) *ErrorHandler {
	return &ErrorHandler{Module: module}
}

func (h *ErrorHandler) Wrap(err error, format string, args ...interface{}) error {
	if err == nil {
		return nil
	}
	newMsg := fmt.Sprintf(format, args...)
	return fmt.Errorf("[%s] %s: %w", h.Module, newMsg, err)
}

func (h *ErrorHandler) Handle(err error, exit bool) {
	if err == nil {
		return
	}
	PrintError(err)
	if exit {
		os.Exit(1)
	}
}

func (h *ErrorHandler) Log(err error) {
	if err == nil {
		return
	}
	pc, _, _, _ := runtime.Caller(1)
	fn := runtime.FuncForPC(pc)
	fmt.Fprintf(os.Stderr, "[%s] 日志: %s - %v\n", h.Module, fn.Name(), err)
}

func IsTimeout(err error) bool {
	return errors.Is(err, contextDeadlineExceeded) || contains(err, "timeout")
}

func IsAuthError(err error) bool {
	return contains(err, "auth") || contains(err, "permission") || contains(err, "denied")
}

func IsConnectionError(err error) bool {
	return contains(err, "connection") || contains(err, "refused") || contains(err, "network")
}

func contains(err error, substr string) bool {
	return err != nil && containsString(err.Error(), substr)
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

var contextDeadlineExceeded = context.DeadlineExceeded
