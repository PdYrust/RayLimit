package buildinfo

import "fmt"

const (
	ProductName        = "RayLimit"
	BinaryName         = "raylimit"
	CreatorName        = "YrustPd"
	RepositoryURL      = "https://github.com/PdYrust/RayLimit"
	TelegramChannelURL = "https://t.me/PdYrust"
	ProductTagline     = "Reconcile-aware traffic shaping for Xray runtimes."
)

// These values are intended to be overridden at build time for release artifacts.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

func Summary() string {
	return fmt.Sprintf("%s %s", ProductName, Version)
}

func Details() string {
	return fmt.Sprintf(
		"%s\n%s\n\nBuild:\n  version     %s\n  commit      %s\n  built       %s\n\nProject:\n  creator     %s\n  repository  %s\n  telegram    %s\n",
		ProductName,
		ProductTagline,
		Version,
		Commit,
		BuildTime,
		CreatorName,
		RepositoryURL,
		TelegramChannelURL,
	)
}
