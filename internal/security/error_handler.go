package security

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/sirupsen/logrus"
)

// ErrorType 定义错误类型
const (
	ErrorTypeValidation   = "validation"
	ErrorTypeGeneration   = "generation"
	ErrorTypeExecution    = "execution"
	ErrorTypeNetwork      = "network"
	ErrorTypeFileSystem   = "filesystem"
	ErrorTypePermission   = "permission"
	ErrorTypeTimeout      = "timeout"
)

// ErrorSeverity 定义错误严重程度
const (
	ErrorSeverityLow      = "low"
	ErrorSeverityMedium   = "medium"
	ErrorSeverityHigh     = "high"
	ErrorSeverityCritical = "critical"
)

// CustomError 自定义错误结构
type CustomError struct {
	Type        string                 // 错误类型
	Severity    string                 // 严重程度
	Message     string                 // 错误消息
	Operation   string                 // 操作名称
	Context     map[string]interface{} // 上下文信息
	OriginalErr error                  // 原始错误
	StackTrace  string                 // 堆栈跟踪
}

// Error 实现error接口
func (e *CustomError) Error() string {
	return fmt.Sprintf("[%s:%s] %s: %s", e.Type, e.Severity, e.Operation, e.Message)
}

// Unwrap 实现错误链
func (e *CustomError) Unwrap() error {
	return e.OriginalErr
}

// ErrorHandler 错误处理器
type ErrorHandler struct {
	Logger *logrus.Logger
}

// NewErrorHandler 创建错误处理器
func NewErrorHandler(logger *logrus.Logger) *ErrorHandler {
	return &ErrorHandler{
		Logger: logger,
	}
}

// NewError 创建新的自定义错误
func (h *ErrorHandler) NewError(errorType, severity, operation, message string, originalErr error) *CustomError {
	err := &CustomError{
		Type:        errorType,
		Severity:    severity,
		Message:     message,
		Operation:   operation,
		OriginalErr: originalErr,
		StackTrace:  h.getStackTrace(),
		Context:     make(map[string]interface{}),
	}

	// 记录错误
	h.logError(err)

	return err
}

// WrapError 包装现有错误
func (h *ErrorHandler) WrapError(errorType, severity, operation, message string, originalErr error) *CustomError {
	if customErr, ok := originalErr.(*CustomError); ok {
		// 已经是自定义错误，直接返回
		return customErr
	}

	return h.NewError(errorType, severity, operation, message, originalErr)
}

// HandleError 处理错误
func (h *ErrorHandler) HandleError(err error, operation string) error {
	if err == nil {
		return nil
	}

	// 如果已经是自定义错误，直接返回
	if customErr, ok := err.(*CustomError); ok {
		return customErr
	}

	// 根据错误类型和内容判断严重程度
	errorType := ErrorTypeExecution
	severity := ErrorSeverityMedium

	// 分析错误内容
	errStr := err.Error()
	switch {
	case strings.Contains(errStr, "permission"):
		errorType = ErrorTypePermission
		severity = ErrorSeverityHigh
	case strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline"):
		errorType = ErrorTypeTimeout
		severity = ErrorSeverityMedium
	case strings.Contains(errStr, "network") || strings.Contains(errStr, "connection"):
		errorType = ErrorTypeNetwork
		severity = ErrorSeverityHigh
	case strings.Contains(errStr, "file") || strings.Contains(errStr, "directory"):
		errorType = ErrorTypeFileSystem
		severity = ErrorSeverityMedium
	}

	return h.NewError(errorType, severity, operation, errStr, err)
}

// ValidateParameters 参数验证
func (h *ErrorHandler) ValidateParameters(params map[string]interface{}) error {
	for key, value := range params {
		switch v := value.(type) {
		case string:
			if strings.TrimSpace(v) == "" {
				return h.NewError(ErrorTypeValidation, ErrorSeverityMedium, 
					"ValidateParameters", fmt.Sprintf("参数 %s 不能为空", key), nil)
			}
		case int:
			if v <= 0 {
				return h.NewError(ErrorTypeValidation, ErrorSeverityMedium,
					"ValidateParameters", fmt.Sprintf("参数 %s 必须大于0", key), nil)
			}
		case []string:
			if len(v) == 0 {
				return h.NewError(ErrorTypeValidation, ErrorSeverityMedium,
					"ValidateParameters", fmt.Sprintf("参数 %s 不能为空数组", key), nil)
			}
		}
	}

	return nil
}

// CheckRecover 检查panic并恢复
func (h *ErrorHandler) CheckRecover(operation string) {
	if r := recover(); r != nil {
		err := fmt.Errorf("panic recovered: %v", r)
		customErr := h.NewError(ErrorTypeExecution, ErrorSeverityCritical, 
			operation, "发生panic", err)
		
		h.Logger.Errorf("Panic recovered: %v", customErr)
	}
}

// getStackTrace 获取堆栈跟踪
func (h *ErrorHandler) getStackTrace() string {
	buf := make([]byte, 1024)
	n := runtime.Stack(buf, false)
	return string(buf[:n])
}

// logError 记录错误
func (h *ErrorHandler) logError(err *CustomError) {
	if h.Logger == nil {
		return
	}

	fields := logrus.Fields{
		"type":      err.Type,
		"severity":  err.Severity,
		"operation": err.Operation,
		"context":   err.Context,
	}

	if err.OriginalErr != nil {
		fields["original_error"] = err.OriginalErr.Error()
	}

	switch err.Severity {
	case ErrorSeverityCritical:
		h.Logger.WithFields(fields).Error(err.Message)
	case ErrorSeverityHigh:
		h.Logger.WithFields(fields).Error(err.Message)
	case ErrorSeverityMedium:
		h.Logger.WithFields(fields).Warn(err.Message)
	case ErrorSeverityLow:
		h.Logger.WithFields(fields).Info(err.Message)
	default:
		h.Logger.WithFields(fields).Error(err.Message)
	}
}

// ErrorContext 错误上下文构建器
type ErrorContext struct {
	context map[string]interface{}
}

// NewErrorContext 创建错误上下文
func NewErrorContext() *ErrorContext {
	return &ErrorContext{
		context: make(map[string]interface{}),
	}
}

// WithParam 添加参数
func (ec *ErrorContext) WithParam(key string, value interface{}) *ErrorContext {
	ec.context[key] = value
	return ec
}

// WithParams 批量添加参数
func (ec *ErrorContext) WithParams(params map[string]interface{}) *ErrorContext {
	for k, v := range params {
		ec.context[k] = v
	}
	return ec
}

// Build 构建上下文
func (ec *ErrorContext) Build() map[string]interface{} {
	return ec.context
}

// ErrorHelper 错误辅助函数
var ErrorHelper = struct {
	// 常见错误创建函数
	InvalidParameter    func(paramName string) *CustomError
	FileNotFound       func(filePath string) *CustomError
	NetworkError       func(operation string) *CustomError
	PermissionDenied   func(resource string) *CustomError
	TimeoutError       func(operation string) *CustomError
	GenerationFailed   func(component string) *CustomError
}{
	InvalidParameter: func(paramName string) *CustomError {
		return &CustomError{
			Type:      ErrorTypeValidation,
			Severity:  ErrorSeverityMedium,
			Message:   fmt.Sprintf("参数 %s 无效", paramName),
			Operation: "参数验证",
		}
	},
	FileNotFound: func(filePath string) *CustomError {
		return &CustomError{
			Type:      ErrorTypeFileSystem,
			Severity:  ErrorSeverityMedium,
			Message:   fmt.Sprintf("文件不存在: %s", filePath),
			Operation: "文件操作",
		}
	},
	NetworkError: func(operation string) *CustomError {
		return &CustomError{
			Type:      ErrorTypeNetwork,
			Severity:  ErrorSeverityHigh,
			Message:   fmt.Sprintf("网络操作失败: %s", operation),
			Operation: operation,
		}
	},
	PermissionDenied: func(resource string) *CustomError {
		return &CustomError{
			Type:      ErrorTypePermission,
			Severity:  ErrorSeverityHigh,
			Message:   fmt.Sprintf("权限不足: %s", resource),
			Operation: "权限检查",
		}
	},
	TimeoutError: func(operation string) *CustomError {
		return &CustomError{
			Type:      ErrorTypeTimeout,
			Severity:  ErrorSeverityMedium,
			Message:   fmt.Sprintf("操作超时: %s", operation),
			Operation: operation,
		}
	},
	GenerationFailed: func(component string) *CustomError {
		return &CustomError{
			Type:      ErrorTypeGeneration,
			Severity:  ErrorSeverityHigh,
			Message:   fmt.Sprintf("生成失败: %s", component),
			Operation: "代码生成",
		}
	},
}