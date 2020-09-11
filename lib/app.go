package checkawscloudwatchlogsinsights

import (
	"os"

	"github.com/mackerelio/checkers"
)

// Do the logic
func Do() {
	ckr := run(os.Args[1:])
	ckr.Name = "CloudWatch Logs Insights"
	ckr.Exit()
}

func run(args []string) *checkers.Checker {
	return checkers.Ok("This is a test checker")
}
