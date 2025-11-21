package weakpass

// 这个文件是网站弱口令爆破模块的入口文件，用于导出公共接口

// Weakpass模块提供多种网站认证方式的弱口令爆破功能
// 支持常见的HTTP认证方式和自定义表单认证

// 主要功能:
// - HTTP Basic认证爆破
// - HTTP Digest认证爆破
// - 自定义表单认证爆破
// - 支持Cookie和自定义请求头
// - 结果输出和进度显示
// - 多线程并发爆破
// - 支持代理设置和超时控制

// 使用示例:
//   config := &weakpass.Config{
//       URL:          "http://example.com/login",
//       Method:       "POST",
//       AuthType:     "basic",
//       Username:     "admin",
//       PasswordFile: "passwords.txt",
//       Threads:      4,
//       Timeout:      10,
//       Verbose:      true,
//   }
//   
//   bruteforcer := weakpass.NewBruteforcer(config)
//   results, err := bruteforcer.Bruteforce()

// 注意: 仅可用于授权测试，严禁未授权使用