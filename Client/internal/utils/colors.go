package utils

import (
	"fmt"

	"github.com/fatih/color"
)

var UseColor = true
var IsSilent = false
var IsVerbose = false

func Success(format string, a ...interface{}) string {
	if !UseColor {
		return fmt.Sprintf(format, a...)
	}
	return color.GreenString(format, a...)
}

func Error(format string, a ...interface{}) string {
	if !UseColor {
		return fmt.Sprintf(format, a...)
	}
	return color.RedString(format, a...)
}

func Warning(format string, a ...interface{}) string {
	if !UseColor {
		return fmt.Sprintf(format, a...)
	}
	return color.YellowString(format, a...)
}

func Info(format string, a ...interface{}) string {
	if !UseColor {
		return fmt.Sprintf(format, a...)
	}
	return color.BlueString(format, a...)
}

func Highlight(format string, a ...interface{}) string {
	if !UseColor {
		return fmt.Sprintf(format, a...)
	}
	return color.CyanString(format, a...)
}

func BoldSuccess(format string, a ...interface{}) string {
	boldGreen := color.New(color.FgGreen, color.Bold)
	return boldGreen.Sprintf(format, a...)
}

func BoldError(format string, a ...interface{}) string {
	boldRed := color.New(color.FgRed, color.Bold)
	return boldRed.Sprintf(format, a...)
}

func BoldWarning(format string, a ...interface{}) string {
	boldYellow := color.New(color.FgYellow, color.Bold)
	return boldYellow.Sprintf(format, a...)
}

func BoldInfo(format string, a ...interface{}) string {
	boldBlue := color.New(color.FgBlue, color.Bold)
	return boldBlue.Sprintf(format, a...)
}

func Progress(format string, a ...interface{}) string {
	return color.MagentaString(format, a...)
}

func Debug(format string, a ...interface{}) string {
	if !IsVerbose {
		return ""
	}
	return color.New(color.FgHiBlack).Sprintf(format, a...)
}

func Banner(format string, a ...interface{}) string {
	boldCyan := color.New(color.FgCyan, color.Bold)
	return boldCyan.Sprintf(format, a...)
}

func Title(format string, a ...interface{}) string {
	boldWhite := color.New(color.FgWhite, color.Bold)
	return boldWhite.Sprintf(format, a...)
}

func SuccessPrint(format string, a ...interface{}) {
	if IsSilent {
		return
	}
	color.Green(format+"\n", a...)
}

func ErrorPrint(format string, a ...interface{}) {
	color.Red(format+"\n", a...)
}

func WarningPrint(format string, a ...interface{}) {
	color.Yellow(format+"\n", a...)
}

func InfoPrint(format string, a ...interface{}) {
	if IsSilent {
		return
	}
	fmt.Printf(format+"\n", a...)
}

func Successf(format string, a ...interface{}) string {
	return Success(format, a...)
}

func Errorf(format string, a ...interface{}) string {
	return Error(format, a...)
}

func Warningf(format string, a ...interface{}) string {
	return Warning(format, a...)
}

func Infof(format string, a ...interface{}) string {
	return Info(format, a...)
}

func ProgressPrint(format string, a ...interface{}) {
	if IsSilent {
		return
	}
	color.Magenta(format+"\n", a...)
}

func BannerPrint(format string, a ...interface{}) {
	boldCyan := color.New(color.FgCyan, color.Bold)
	boldCyan.Printf(format+"\n", a...)
}

func TitlePrint(format string, a ...interface{}) {
	boldWhite := color.New(color.FgWhite, color.Bold)
	boldWhite.Printf(format+"\n", a...)
}

func ResultPrint(format string, a ...interface{}) {
	if IsSilent {
		return
	}
	boldCyan := color.New(color.FgCyan, color.Bold)
	boldCyan.Printf("[>] "+format+"\n", a...)
}

func ColorText(text string, colorCode string) string {
	return text
}

func ColorPrint(colorCode string, format string, a ...interface{}) {
	fmt.Printf("%s\n", fmt.Sprintf(format, a...))
}
