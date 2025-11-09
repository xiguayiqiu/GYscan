package ssh

// 这个文件是SSH模块的入口文件，用于导出公共接口

// SSH模块提供SSH密码爆破功能，完全按照Hydra工具风格实现

// 主要功能:
// - SSH用户名/密码认证爆破
// - 字典攻击和暴力破解
// - 多线程并发爆破
// - 支持自定义端口和超时设置
// - 结果输出和进度显示

// 使用示例:
//   config := &ssh.SSHConfig{
//       Target:       "192.168.1.1",
//       Port:         22,
//       Username:     "root",
//       PasswordFile: "passwords.txt",
//       Threads:      4,
//       Timeout:      10,
//       Verbose:      true,
//   }
//   
//   bruteforcer := ssh.NewSSHBruteforcer(config)
//   results, err := bruteforcer.Bruteforce()

// 注意: 仅可用于授权测试，严禁未授权使用