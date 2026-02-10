package cupp

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

type CUPP struct{}

func NewCUPP() *CUPP {
	return &CUPP{}
}

func (c *CUPP) Interactive(profile *Profile) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("\r\n[+] 输入目标信息以生成密码字典")
	fmt.Println("[+] 如果不知道某些信息，直接按回车跳过！ ;)\r\n")

	fmt.Print("> 名字: ")
	name, _ := reader.ReadString('\n')
	profile.Name = strings.ToLower(strings.TrimSpace(name))
	for len(profile.Name) == 0 {
		fmt.Println("\r\n[-] 至少需要输入一个名字！")
		fmt.Print("> 名字: ")
		name, _ = reader.ReadString('\n')
		profile.Name = strings.ToLower(strings.TrimSpace(name))
	}

	fmt.Print("> 姓氏: ")
	surname, _ := reader.ReadString('\n')
	profile.Surname = strings.ToLower(strings.TrimSpace(surname))

	fmt.Print("> 昵称: ")
	nick, _ := reader.ReadString('\n')
	profile.Nick = strings.ToLower(strings.TrimSpace(nick))

	fmt.Print("> 出生日期 (DDMMYYYY): ")
	birthdate, _ := reader.ReadString('\n')
	profile.Birthdate = strings.TrimSpace(birthdate)
	for len(profile.Birthdate) != 0 && len(profile.Birthdate) != 8 {
		fmt.Println("\r\n[-] 请输入8位数字表示生日！")
		fmt.Print("> 出生日期 (DDMMYYYY): ")
		birthdate, _ = reader.ReadString('\n')
		profile.Birthdate = strings.TrimSpace(birthdate)
	}

	fmt.Println("\r\n")

	fmt.Print("> 伴侣名字: ")
	wife, _ := reader.ReadString('\n')
	profile.Wife = strings.ToLower(strings.TrimSpace(wife))

	fmt.Print("> 伴侣昵称: ")
	wifen, _ := reader.ReadString('\n')
	profile.Wifen = strings.ToLower(strings.TrimSpace(wifen))

	fmt.Print("> 伴侣生日 (DDMMYYYY): ")
	wifeb, _ := reader.ReadString('\n')
	profile.Wifeb = strings.TrimSpace(wifeb)
	for len(profile.Wifeb) != 0 && len(profile.Wifeb) != 8 {
		fmt.Println("\r\n[-] 请输入8位数字表示生日！")
		fmt.Print("> 伴侣生日 (DDMMYYYY): ")
		wifeb, _ = reader.ReadString('\n')
		profile.Wifeb = strings.TrimSpace(wifeb)
	}

	fmt.Println("\r\n")

	fmt.Print("> 孩子名字: ")
	kid, _ := reader.ReadString('\n')
	profile.Kid = strings.ToLower(strings.TrimSpace(kid))

	fmt.Print("> 孩子昵称: ")
	kidn, _ := reader.ReadString('\n')
	profile.Kidn = strings.ToLower(strings.TrimSpace(kidn))

	fmt.Print("> 孩子生日 (DDMMYYYY): ")
	kidb, _ := reader.ReadString('\n')
	profile.Kidb = strings.TrimSpace(kidb)
	for len(profile.Kidb) != 0 && len(profile.Kidb) != 8 {
		fmt.Println("\r\n[-] 请输入8位数字表示生日！")
		fmt.Print("> 孩子生日 (DDMMYYYY): ")
		kidb, _ = reader.ReadString('\n')
		profile.Kidb = strings.TrimSpace(kidb)
	}

	fmt.Println("\r\n")

	fmt.Print("> 宠物名字: ")
	pet, _ := reader.ReadString('\n')
	profile.Pet = strings.ToLower(strings.TrimSpace(pet))

	fmt.Print("> 公司名称: ")
	company, _ := reader.ReadString('\n')
	profile.Company = strings.ToLower(strings.TrimSpace(company))

	fmt.Println("\r\n")

	fmt.Print("> 是否要添加一些关于目标的关键词? Y/[N]: ")
	words1, _ := reader.ReadString('\n')
	words1 = strings.ToLower(strings.TrimSpace(words1))
	words2 := ""
	if words1 == "y" {
		fmt.Print("> 请输入关键词，用逗号分隔 [例如: hacker,juice,black]: ")
		words2, _ = reader.ReadString('\n')
		words2 = strings.ReplaceAll(words2, " ", "")
	}
	profile.Words = strings.Split(words2, ",")

	fmt.Print("> 是否要在词汇末尾添加特殊字符? Y/[N]: ")
	spechars1, _ := reader.ReadString('\n')
	profile.Spechars1 = strings.ToLower(strings.TrimSpace(spechars1))

	fmt.Print("> 是否要在词汇末尾添加随机数字? Y/[N]: ")
	randnum, _ := reader.ReadString('\n')
	profile.Randnum = strings.ToLower(strings.TrimSpace(randnum))

	fmt.Print("> 是否要使用Leet模式? (即 leet = 1337) Y/[N]: ")
	leetmode, _ := reader.ReadString('\n')
	profile.Leetmode = strings.ToLower(strings.TrimSpace(leetmode))
}

func (c *CUPP) DownloadWordlist() {
	fmt.Println("\r\n选择要下载的部分:\r\n")

	fmt.Println("     1   Moby            14      french          27      places")
	fmt.Println("     2   afrikaans       15      german          28      polish")
	fmt.Println("     3   american        16      hindi           29      random")
	fmt.Println("     4   aussie          17      hungarian       30      religion")
	fmt.Println("     5   chinese         18      italian         31      russian")
	fmt.Println("     6   computer        19      japanese        32      science")
	fmt.Println("     7   croatian        20      latin           33      spanish")
	fmt.Println("     8   czech           21      literature      34      swahili")
	fmt.Println("     9   danish          22      movieTV         35      swedish")
	fmt.Println("    10   databases       23      music           36      turkish")
	fmt.Println("    11   dictionaries    24      names           37      yiddish")
	fmt.Println("    12   dutch           25      net             38      exit program")
	fmt.Println("    13   finnish         26      norwegian       \r\n")

	fmt.Printf("\r\n文件将从 %s 仓库下载\n", CONFIG.DictURL)
	fmt.Println("提示: 下载字典后，可以使用 -w 选项来改进它\r\n")

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("> 输入数字: ")
	filedown, _ := reader.ReadString('\n')
	filedown = strings.TrimSpace(filedown)

	fmt.Println("\r\n[-] 字典下载功能需要实现HTTP下载支持")
	fmt.Println("[-] 请手动下载或使用其他工具")
}
