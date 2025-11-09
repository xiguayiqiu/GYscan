package security

import (
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
)

// TimeWindow 时间窗口定义
type TimeWindow struct {
	StartHour int `json:"start_hour"` // 开始小时 (0-23)
	EndHour   int `json:"end_hour"`   // 结束小时 (0-23)
	Days      []int `json:"days"`      // 允许的天数 (0-6, 0=周日, 6=周六)
}

// TimeEvasion 时间规避管理
type TimeEvasion struct {
	// 业务时段规避
	BusinessHours []TimeWindow `json:"business_hours"`
	
	// 节假日规避
	Holidays      []time.Time  `json:"holidays"`
	
	// 配置参数
	MaxWaitTime   time.Duration `json:"max_wait_time"` // 最大等待时间
	CheckInterval time.Duration `json:"check_interval"` // 检查间隔
}

// NewTimeEvasion 创建时间规避实例
func NewTimeEvasion() *TimeEvasion {
	return &TimeEvasion{
		BusinessHours: []TimeWindow{
			{StartHour: 9, EndHour: 17, Days: []int{1, 2, 3, 4, 5}}, // 工作日 9-17点
		},
		Holidays:      []time.Time{},
		MaxWaitTime:   24 * time.Hour,
		CheckInterval: 1 * time.Minute,
	}
}

// IsInBusinessHours 检查当前是否在业务时段内
func (t *TimeEvasion) IsInBusinessHours() bool {
	now := time.Now()
	currentHour := now.Hour()
	currentDay := int(now.Weekday())
	
	for _, window := range t.BusinessHours {
		// 检查是否在允许的天数内
		dayMatch := false
		for _, day := range window.Days {
			if day == currentDay {
				dayMatch = true
				break
			}
		}
		
		if !dayMatch {
			continue
		}
		
		// 检查是否在时间窗口内
		if currentHour >= window.StartHour && currentHour < window.EndHour {
			return true
		}
	}
	
	return false
}

// IsHoliday 检查当前是否是节假日
func (t *TimeEvasion) IsHoliday() bool {
	now := time.Now()
	currentDate := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	
	for _, holiday := range t.Holidays {
		holidayDate := time.Date(holiday.Year(), holiday.Month(), holiday.Day(), 0, 0, 0, 0, holiday.Location())
		if currentDate.Equal(holidayDate) {
			return true
		}
	}
	
	return false
}

// ShouldEvade 检查是否需要规避
func (t *TimeEvasion) ShouldEvade() bool {
	// 如果在业务时段内，需要规避
	if t.IsInBusinessHours() {
		logrus.Infof("[GYscan-Time] 当前在业务时段内，需要规避")
		return true
	}
	
	// 如果是节假日，需要规避
	if t.IsHoliday() {
		logrus.Infof("[GYscan-Time] 当前是节假日，需要规避")
		return true
	}
	
	logrus.Debugf("[GYscan-Time] 当前不在规避时段，可以执行")
	return false
}

// WaitForSafeTime 等待安全时间
func (t *TimeEvasion) WaitForSafeTime() error {
	startTime := time.Now()
	
	for {
		// 检查是否超过最大等待时间
		if time.Since(startTime) > t.MaxWaitTime {
			return fmt.Errorf("等待安全时间超时 (最大等待时间: %v)", t.MaxWaitTime)
		}
		
		// 检查当前是否安全
		if !t.ShouldEvade() {
			logrus.Infof("[GYscan-Time] 安全时间到达，开始执行")
			return nil
		}
		
		// 计算剩余等待时间
		nextCheck := t.calculateNextSafeTime()
		waitDuration := time.Until(nextCheck)
		
		if waitDuration > t.CheckInterval {
			waitDuration = t.CheckInterval
		}
		
		logrus.Infof("[GYscan-Time] 等待安全时间，下次检查: %v (剩余: %v)", 
			nextCheck.Format("2006-01-02 15:04:05"), waitDuration)
		
		time.Sleep(waitDuration)
	}
}

// calculateNextSafeTime 计算下一个安全时间
func (t *TimeEvasion) calculateNextSafeTime() time.Time {
	now := time.Now()
	
	// 检查今天是否还有安全时间
	todayEnd := t.getTodaySafeEnd()
	if todayEnd.After(now) {
		return todayEnd
	}
	
	// 检查明天的安全时间
	tomorrowStart := t.getTomorrowSafeStart()
	return tomorrowStart
}

// getTodaySafeEnd 获取今天的安全结束时间
func (t *TimeEvasion) getTodaySafeEnd() time.Time {
	now := time.Now()
	
	// 找到今天最后一个业务时段的结束时间
	var latestEnd time.Time
	for _, window := range t.BusinessHours {
		if t.isDayInWindow(int(now.Weekday()), window.Days) {
			windowEnd := time.Date(now.Year(), now.Month(), now.Day(), window.EndHour, 0, 0, 0, now.Location())
			if windowEnd.After(latestEnd) {
				latestEnd = windowEnd
			}
		}
	}
	
	return latestEnd
}

// getTomorrowSafeStart 获取明天的安全开始时间
func (t *TimeEvasion) getTomorrowSafeStart() time.Time {
	now := time.Now()
	tomorrow := now.Add(24 * time.Hour)
	
	// 找到明天第一个业务时段的开始时间
	var earliestStart time.Time
	for _, window := range t.BusinessHours {
		if t.isDayInWindow(int(tomorrow.Weekday()), window.Days) {
			windowStart := time.Date(tomorrow.Year(), tomorrow.Month(), tomorrow.Day(), window.StartHour, 0, 0, 0, tomorrow.Location())
			if earliestStart.IsZero() || windowStart.Before(earliestStart) {
				earliestStart = windowStart
			}
		}
	}
	
	return earliestStart
}

// isDayInWindow 检查某天是否在窗口内
func (t *TimeEvasion) isDayInWindow(day int, days []int) bool {
	for _, d := range days {
		if d == day {
			return true
		}
	}
	return false
}

// AddHoliday 添加节假日
func (t *TimeEvasion) AddHoliday(date time.Time) {
	t.Holidays = append(t.Holidays, date)
	logrus.Infof("[GYscan-Time] 添加节假日: %s", date.Format("2006-01-02"))
}

// AddBusinessWindow 添加业务时段窗口
func (t *TimeEvasion) AddBusinessWindow(startHour, endHour int, days []int) {
	window := TimeWindow{
		StartHour: startHour,
		EndHour:   endHour,
		Days:      days,
	}
	t.BusinessHours = append(t.BusinessHours, window)
	
	logrus.Infof("[GYscan-Time] 添加业务时段: %02d:00-%02d:00, 天数: %v", 
		startHour, endHour, days)
}

// GetCurrentStatus 获取当前状态信息
func (t *TimeEvasion) GetCurrentStatus() map[string]interface{} {
	now := time.Now()
	
	status := make(map[string]interface{})
	status["current_time"] = now.Format("2006-01-02 15:04:05")
	status["in_business_hours"] = t.IsInBusinessHours()
	status["is_holiday"] = t.IsHoliday()
	status["should_evade"] = t.ShouldEvade()
	status["business_windows"] = t.BusinessHours
	status["holidays_count"] = len(t.Holidays)
	
	if t.ShouldEvade() {
		nextSafe := t.calculateNextSafeTime()
		status["next_safe_time"] = nextSafe.Format("2006-01-02 15:04:05")
		status["time_until_safe"] = nextSafe.Sub(now).String()
	}
	
	return status
}

// ValidateConfiguration 验证配置有效性
func (t *TimeEvasion) ValidateConfiguration() error {
	// 验证业务时段
	for i, window := range t.BusinessHours {
		if window.StartHour < 0 || window.StartHour > 23 {
			return fmt.Errorf("业务时段 %d 开始小时无效: %d", i, window.StartHour)
		}
		if window.EndHour < 0 || window.EndHour > 23 {
			return fmt.Errorf("业务时段 %d 结束小时无效: %d", i, window.EndHour)
		}
		if window.StartHour >= window.EndHour {
			return fmt.Errorf("业务时段 %d 开始时间必须早于结束时间", i)
		}
		
		for _, day := range window.Days {
			if day < 0 || day > 6 {
				return fmt.Errorf("业务时段 %d 天数无效: %d", i, day)
			}
		}
	}
	
	// 验证等待时间
	if t.MaxWaitTime <= 0 {
		return fmt.Errorf("最大等待时间必须大于0")
	}
	
	if t.CheckInterval <= 0 {
		return fmt.Errorf("检查间隔必须大于0")
	}
	
	return nil
}