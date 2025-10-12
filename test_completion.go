package main
import (
	"fmt"
	"cipgram/pkg/cli"
)
func main() {
	app, _ := cli.NewApp()
	fmt.Println("=== ZSH SCRIPT ===")
	fmt.Println(app.GenerateCompletionScriptForShell("zsh"))
	fmt.Println("=== BASH SCRIPT ===") 
	fmt.Println(app.GenerateCompletionScriptForShell("bash"))
}
