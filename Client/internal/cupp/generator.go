package cupp

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
)

func Concats(seq []string, start, stop int) []string {
	result := []string{}
	for _, mystr := range seq {
		for num := start; num < stop; num++ {
			result = append(result, mystr+fmt.Sprintf("%d", num))
		}
	}
	return result
}

func Komb(seq []string, start []string, special string) []string {
	result := []string{}
	for _, mystr := range seq {
		for _, mystr1 := range start {
			result = append(result, mystr+special+mystr1)
		}
	}
	return result
}

func KombWithSpecial(seq []string, special []string) []string {
	result := []string{}
	for _, mystr := range seq {
		for _, spec := range special {
			result = append(result, mystr+spec)
		}
	}
	return result
}

func RemoveDuplicates(items []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

func MakeLeet(x string) string {
	for letter, leetletter := range CONFIG.LeetMap {
		x = strings.ReplaceAll(x, letter, leetletter)
	}
	return x
}

func PrintToFile(filename string, uniqueListFinished []string) {
	sort.Strings(uniqueListFinished)

	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("[ERROR] 无法创建文件 %s: %v\n", filename, err)
		return
	}
	defer file.Close()

	for _, line := range uniqueListFinished {
		file.WriteString(line + "\n")
	}

	fmt.Printf("[+] 字典已保存至 \033[1;31m%s\033[1;m, 共 \033[1;31m%d\033[1;m 个密码\n", filename, len(uniqueListFinished))
}

func GenerateWordlistFromProfile(profile *Profile) []string {
	chars := CONFIG.Chars
	years := CONFIG.Years
	numfrom := CONFIG.NumFrom
	numto := CONFIG.NumTo

	profile.Spechars = []string{}

	if profile.Spechars1 == "y" {
		for _, spec1 := range chars {
			profile.Spechars = append(profile.Spechars, spec1)
			for _, spec2 := range chars {
				profile.Spechars = append(profile.Spechars, spec1+spec2)
				for _, spec3 := range chars {
					profile.Spechars = append(profile.Spechars, spec1+spec2+spec3)
				}
			}
		}
	}

	birthdateYy := ""
	birthdateYyy := ""
	birthdateYyyy := ""
	birthdateXd := ""
	birthdateXm := ""
	birthdateDd := ""
	birthdateMm := ""

	if len(profile.Birthdate) >= 2 {
		birthdateYy = profile.Birthdate[len(profile.Birthdate)-2:]
	}
	if len(profile.Birthdate) >= 3 {
		birthdateYyy = profile.Birthdate[len(profile.Birthdate)-3:]
	}
	if len(profile.Birthdate) >= 4 {
		birthdateYyyy = profile.Birthdate[len(profile.Birthdate)-4:]
	}
	if len(profile.Birthdate) >= 2 {
		birthdateDd = profile.Birthdate[:2]
	}
	if len(profile.Birthdate) >= 4 {
		birthdateMm = profile.Birthdate[2:4]
	}
	if len(profile.Birthdate) >= 2 {
		birthdateXd = profile.Birthdate[1:2]
	}
	if len(profile.Birthdate) >= 4 {
		birthdateXm = profile.Birthdate[3:4]
	}

	wifebYy := ""
	wifebYyy := ""
	wifebYyyy := ""
	wifebXd := ""
	wifebXm := ""
	wifebDd := ""
	wifebMm := ""

	if len(profile.Wifeb) >= 2 {
		wifebYy = profile.Wifeb[len(profile.Wifeb)-2:]
	}
	if len(profile.Wifeb) >= 3 {
		wifebYyy = profile.Wifeb[len(profile.Wifeb)-3:]
	}
	if len(profile.Wifeb) >= 4 {
		wifebYyyy = profile.Wifeb[len(profile.Wifeb)-4:]
	}
	if len(profile.Wifeb) >= 2 {
		wifebDd = profile.Wifeb[:2]
	}
	if len(profile.Wifeb) >= 4 {
		wifebMm = profile.Wifeb[2:4]
	}
	if len(profile.Wifeb) >= 2 {
		wifebXd = profile.Wifeb[1:2]
	}
	if len(profile.Wifeb) >= 4 {
		wifebXm = profile.Wifeb[3:4]
	}

	kidbYy := ""
	kidbYyy := ""
	kidbYyyy := ""
	kidbXd := ""
	kidbXm := ""
	kidbDd := ""
	kidbMm := ""

	if len(profile.Kidb) >= 2 {
		kidbYy = profile.Kidb[len(profile.Kidb)-2:]
	}
	if len(profile.Kidb) >= 3 {
		kidbYyy = profile.Kidb[len(profile.Kidb)-3:]
	}
	if len(profile.Kidb) >= 4 {
		kidbYyyy = profile.Kidb[len(profile.Kidb)-4:]
	}
	if len(profile.Kidb) >= 2 {
		kidbDd = profile.Kidb[:2]
	}
	if len(profile.Kidb) >= 4 {
		kidbMm = profile.Kidb[2:4]
	}
	if len(profile.Kidb) >= 2 {
		kidbXd = profile.Kidb[1:2]
	}
	if len(profile.Kidb) >= 4 {
		kidbXm = profile.Kidb[3:4]
	}

	nameup := strings.Title(profile.Name)
	surnameup := strings.Title(profile.Surname)
	nickup := strings.Title(profile.Nick)
	wifeup := strings.Title(profile.Wife)
	wifenup := strings.Title(profile.Wifen)
	kidup := strings.Title(profile.Kid)
	kidnup := strings.Title(profile.Kidn)
	petup := strings.Title(profile.Pet)
	companyup := strings.Title(profile.Company)

	wordsup := []string{}
	for _, w := range profile.Words {
		wordsup = append(wordsup, strings.Title(w))
	}

	word := append(profile.Words, wordsup...)

	revName := reverseString(profile.Name)
	revNameup := reverseString(nameup)
	revNick := reverseString(profile.Nick)
	revNickup := reverseString(nickup)
	revWife := reverseString(profile.Wife)
	revWifeup := reverseString(wifeup)
	revKid := reverseString(profile.Kid)
	revKidup := reverseString(kidup)

	reverse := []string{revName, revNameup, revNick, revNickup, revWife, revWifeup, revKid, revKidup}
	revN := []string{revName, revNameup, revNick, revNickup}
	revW := []string{revWife, revWifeup}
	revK := []string{revKid, revKidup}

	bds := []string{birthdateYy, birthdateYyy, birthdateYyyy, birthdateXd, birthdateXm, birthdateDd, birthdateMm}

	bdss := []string{}
	for _, bds1 := range bds {
		bdss = append(bdss, bds1)
		for _, bds2 := range bds {
			if indexOf(bds, bds1) != indexOf(bds, bds2) {
				bdss = append(bdss, bds1+bds2)
				for _, bds3 := range bds {
					if indexOf(bds, bds1) != indexOf(bds, bds2) &&
						indexOf(bds, bds2) != indexOf(bds, bds3) &&
						indexOf(bds, bds1) != indexOf(bds, bds3) {
						bdss = append(bdss, bds1+bds2+bds3)
					}
				}
			}
		}
	}

	wbds := []string{wifebYy, wifebYyy, wifebYyyy, wifebXd, wifebXm, wifebDd, wifebMm}

	wbdss := []string{}
	for _, wbds1 := range wbds {
		wbdss = append(wbdss, wbds1)
		for _, wbds2 := range wbds {
			if indexOf(wbds, wbds1) != indexOf(wbds, wbds2) {
				wbdss = append(wbdss, wbds1+wbds2)
				for _, wbds3 := range wbds {
					if indexOf(wbds, wbds1) != indexOf(wbds, wbds2) &&
						indexOf(wbds, wbds2) != indexOf(wbds, wbds3) &&
						indexOf(wbds, wbds1) != indexOf(wbds, wbds3) {
						wbdss = append(wbdss, wbds1+wbds2+wbds3)
					}
				}
			}
		}
	}

	kbds := []string{kidbYy, kidbYyy, kidbYyyy, kidbXd, kidbXm, kidbDd, kidbMm}

	kbdss := []string{}
	for _, kbds1 := range kbds {
		kbdss = append(kbdss, kbds1)
		for _, kbds2 := range kbds {
			if indexOf(kbds, kbds1) != indexOf(kbds, kbds2) {
				kbdss = append(kbdss, kbds1+kbds2)
				for _, kbds3 := range kbds {
					if indexOf(kbds, kbds1) != indexOf(kbds, kbds2) &&
						indexOf(kbds, kbds2) != indexOf(kbds, kbds3) &&
						indexOf(kbds, kbds1) != indexOf(kbds, kbds3) {
						kbdss = append(kbdss, kbds1+kbds2+kbds3)
					}
				}
			}
		}
	}

	kombinaac := []string{profile.Pet, petup, profile.Company, companyup}

	kombina := []string{
		profile.Name, profile.Surname, profile.Nick,
		nameup, surnameup, nickup,
	}

	kombinaw := []string{
		profile.Wife, profile.Wifen, wifeup, wifenup,
		profile.Surname, surnameup,
	}

	kombinak := []string{
		profile.Kid, profile.Kidn, kidup, kidnup,
		profile.Surname, surnameup,
	}

	kombinaa := []string{}
	for _, kombina1 := range kombina {
		kombinaa = append(kombinaa, kombina1)
		for _, kombina2 := range kombina {
			if indexOf(kombina, kombina1) != indexOf(kombina, kombina2) &&
				indexOf(kombina, strings.Title(kombina1)) != indexOf(kombina, strings.Title(kombina2)) {
				kombinaa = append(kombinaa, kombina1+kombina2)
			}
		}
	}

	kombinaaw := []string{}
	for _, kombina1 := range kombinaw {
		kombinaaw = append(kombinaaw, kombina1)
		for _, kombina2 := range kombinaw {
			if indexOf(kombinaw, kombina1) != indexOf(kombinaw, kombina2) &&
				indexOf(kombinaw, strings.Title(kombina1)) != indexOf(kombinaw, strings.Title(kombina2)) {
				kombinaaw = append(kombinaaw, kombina1+kombina2)
			}
		}
	}

	kombinaak := []string{}
	for _, kombina1 := range kombinak {
		kombinaak = append(kombinaak, kombina1)
		for _, kombina2 := range kombinak {
			if indexOf(kombinak, kombina1) != indexOf(kombinak, kombina2) &&
				indexOf(kombinak, strings.Title(kombina1)) != indexOf(kombinak, strings.Title(kombina2)) {
				kombinaak = append(kombinaak, kombina1+kombina2)
			}
		}
	}

	kombi := make(map[int][]string)
	kombi[1] = append(Komb(kombinaa, bdss, ""), Komb(kombinaa, bdss, "_")...)
	kombi[2] = append(Komb(kombinaaw, wbdss, ""), Komb(kombinaaw, wbdss, "_")...)
	kombi[3] = append(Komb(kombinaak, kbdss, ""), Komb(kombinaak, kbdss, "_")...)
	kombi[4] = append(Komb(kombinaa, years, ""), Komb(kombinaa, years, "_")...)
	kombi[5] = append(Komb(kombinaac, years, ""), Komb(kombinaac, years, "_")...)
	kombi[6] = append(Komb(kombinaaw, years, ""), Komb(kombinaaw, years, "_")...)
	kombi[7] = append(Komb(kombinak, years, ""), Komb(kombinak, years, "_")...)
	kombi[8] = append(Komb(word, bdss, ""), Komb(word, bdss, "_")...)
	kombi[9] = append(Komb(word, wbdss, ""), Komb(word, wbdss, "_")...)
	kombi[10] = append(Komb(word, kbdss, ""), Komb(word, kbdss, "_")...)
	kombi[11] = append(Komb(word, years, ""), Komb(word, years, "_")...)
	kombi[12] = []string{}
	kombi[13] = []string{}
	kombi[14] = []string{}
	kombi[15] = []string{}
	kombi[16] = []string{}
	kombi[21] = []string{}

	if profile.Randnum == "y" {
		kombi[12] = Concats(word, numfrom, numto)
		kombi[13] = Concats(kombinaa, numfrom, numto)
		kombi[14] = Concats(kombinaac, numfrom, numto)
		kombi[15] = Concats(kombinaaw, numfrom, numto)
		kombi[16] = Concats(kombinak, numfrom, numto)
		kombi[21] = Concats(reverse, numfrom, numto)
	}

	kombi[17] = append(Komb(reverse, years, ""), Komb(reverse, years, "_")...)
	kombi[18] = append(Komb(revW, wbdss, ""), Komb(revW, wbdss, "_")...)
	kombi[19] = append(Komb(revK, kbdss, ""), Komb(revK, kbdss, "_")...)
	kombi[20] = append(Komb(revN, bdss, ""), Komb(revN, bdss, "_")...)

	komb001 := []string{}
	komb002 := []string{}
	komb003 := []string{}
	komb004 := []string{}
	komb005 := []string{}
	komb006 := []string{}

	if len(profile.Spechars) > 0 {
		komb001 = KombWithSpecial(kombinaa, profile.Spechars)
		komb002 = KombWithSpecial(kombinaac, profile.Spechars)
		komb003 = KombWithSpecial(kombinaaw, profile.Spechars)
		komb004 = KombWithSpecial(kombinak, profile.Spechars)
		komb005 = KombWithSpecial(word, profile.Spechars)
		komb006 = KombWithSpecial(reverse, profile.Spechars)
	}

	kombUnique := make(map[int][]string)
	for i := 1; i <= 21; i++ {
		kombUnique[i] = RemoveDuplicates(kombi[i])
	}

	kombUnique01 := RemoveDuplicates(kombinaa)
	kombUnique02 := RemoveDuplicates(kombinaac)
	kombUnique03 := RemoveDuplicates(kombinaaw)
	kombUnique04 := RemoveDuplicates(kombinak)
	kombUnique05 := RemoveDuplicates(word)
	kombUnique07 := RemoveDuplicates(komb001)
	kombUnique08 := RemoveDuplicates(komb002)
	kombUnique09 := RemoveDuplicates(komb003)
	kombUnique10 := RemoveDuplicates(komb004)
	kombUnique11 := RemoveDuplicates(komb005)
	kombUnique012 := RemoveDuplicates(komb006)

	uniqlist := []string{}
	uniqlist = append(uniqlist, bdss...)
	uniqlist = append(uniqlist, wbdss...)
	uniqlist = append(uniqlist, kbdss...)
	uniqlist = append(uniqlist, reverse...)
	uniqlist = append(uniqlist, kombUnique01...)
	uniqlist = append(uniqlist, kombUnique02...)
	uniqlist = append(uniqlist, kombUnique03...)
	uniqlist = append(uniqlist, kombUnique04...)
	uniqlist = append(uniqlist, kombUnique05...)

	for i := 1; i <= 21; i++ {
		uniqlist = append(uniqlist, kombUnique[i]...)
	}

	uniqlist = append(uniqlist, kombUnique07...)
	uniqlist = append(uniqlist, kombUnique08...)
	uniqlist = append(uniqlist, kombUnique09...)
	uniqlist = append(uniqlist, kombUnique10...)
	uniqlist = append(uniqlist, kombUnique11...)
	uniqlist = append(uniqlist, kombUnique012...)

	uniqueLista := RemoveDuplicates(uniqlist)
	uniqueLeet := []string{}

	if profile.Leetmode == "y" {
		var mutex sync.Mutex
		var wg sync.WaitGroup

		for _, x := range uniqueLista {
			wg.Add(1)
			go func(val string) {
				defer wg.Done()
				leetVal := MakeLeet(val)
				mutex.Lock()
				uniqueLeet = append(uniqueLeet, leetVal)
				mutex.Unlock()
			}(x)
		}
		wg.Wait()
	}

	uniqueList := append(uniqueLista, uniqueLeet...)

	uniqueListFinished := []string{}
	for _, x := range uniqueList {
		if len(x) < CONFIG.WCTo && len(x) > CONFIG.WCFrom {
			uniqueListFinished = append(uniqueListFinished, x)
		}
	}

	return uniqueListFinished
}

func GenerateWordlist(profile *Profile, outputFile string) {
	uniqueListFinished := GenerateWordlistFromProfile(profile)
	PrintToFile(outputFile, uniqueListFinished)
}

func ImproveDictionary(fileToOpen string, concat, leet, numbers, special bool) {
	if _, err := os.Stat(fileToOpen); os.IsNotExist(err) {
		fmt.Printf("Error: 文件 %s 不存在\n", fileToOpen)
		return
	}

	data, err := os.ReadFile(fileToOpen)
	if err != nil {
		fmt.Printf("Error: 无法读取文件 %s: %v\n", fileToOpen, err)
		return
	}

	listic := strings.Split(string(data), "\n")

	chars := CONFIG.Chars
	years := CONFIG.Years
	numfrom := CONFIG.NumFrom
	numto := CONFIG.NumTo

	kombinacija := make(map[int][]string)
	kombUnique := make(map[int][]string)

	cont := []string{""}
	if concat && len(listic) <= CONFIG.Threshold {
		fmt.Println("[+] 连接词汇...")
		for _, cont1 := range listic {
			for _, cont2 := range listic {
				if indexOf(listic, cont1) != indexOf(listic, cont2) {
					cont = append(cont, cont1+cont2)
				}
			}
		}
	} else if concat && len(listic) > CONFIG.Threshold {
		fmt.Printf("[-] 词汇数量 %d 超过阈值 %d，跳过连接\n", len(listic), CONFIG.Threshold)
	}

	specharsList := []string{}
	if special {
		fmt.Println("[+] 添加特殊字符...")
		for _, spec1 := range chars {
			specharsList = append(specharsList, spec1)
			for _, spec2 := range chars {
				specharsList = append(specharsList, spec1+spec2)
				for _, spec3 := range chars {
					specharsList = append(specharsList, spec1+spec2+spec3)
				}
			}
		}
	}

	for i := 0; i < 6; i++ {
		kombinacija[i] = []string{""}
	}

	kombinacija[0] = Komb(listic, years, "")
	if concat {
		kombinacija[1] = Komb(cont, years, "")
	}
	if special {
		kombinacija[2] = Komb(listic, specharsList, "")
		if concat {
			kombinacija[3] = Komb(cont, specharsList, "")
		}
	}
	if numbers {
		kombinacija[4] = Concats(listic, numfrom, numto)
		if concat {
			kombinacija[5] = Concats(cont, numfrom, numto)
		}
	}

	fmt.Println("[+] 正在生成字典...")
	fmt.Println("[+] 正在排序并去除重复...")

	for i := 0; i < 6; i++ {
		kombUnique[i] = RemoveDuplicates(kombinacija[i])
	}

	kombUnique[6] = RemoveDuplicates(listic)
	kombUnique[7] = RemoveDuplicates(cont)

	uniqlist := []string{}
	for i := 0; i < 8; i++ {
		uniqlist = append(uniqlist, kombUnique[i]...)
	}

	uniqueLista := RemoveDuplicates(uniqlist)
	uniqueLeet := []string{}

	if leet {
		fmt.Println("[+] 应用Leet模式...")
		for _, x := range uniqueLista {
			x = MakeLeet(x)
			uniqueLeet = append(uniqueLeet, x)
		}
	}

	uniqueList := append(uniqueLista, uniqueLeet...)

	uniqueListFinished := []string{}
	for _, x := range uniqueList {
		if len(x) > CONFIG.WCFrom && len(x) < CONFIG.WCTo {
			uniqueListFinished = append(uniqueListFinished, x)
		}

	}

	PrintToFile(fileToOpen+".cupp.txt", uniqueListFinished)
}

func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func indexOf(slice []string, item string) int {
	for i, v := range slice {
		if v == item {
			return i
		}
	}
	return -1
}
