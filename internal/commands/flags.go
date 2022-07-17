package commands

// General flags
var (
	// isQuiet if true, disable all console prints
	isQuiet          bool
	isQuietFlagName  = "quiet"
	isQuietShortFlag = "q"

	// outputFilePath if provided, output will be appended to a file
	outputFilePath          string
	outputFilePathFlagName  = "output-file"
	outputFilePathShortFlag = "o"

	// logFilePath if provided, logs will be appended to a file
	logFilePath          string
	logFilePathFlagName  = "log-file"
	logFilePathShortFlag = "l"

	// logFormat the format of the logs
	logFormat         string
	logFormatFlagName = "log-format"

	// number if flags determinds log level verbosiry (0 - info, 1 - debug, 2 - trace)
	verbosity          int
	verbosityFlagName  = "verbose"
	verbosityShortFlag = "v"

	// noColor disables output color
	noColor         bool
	noColorFlagName = "no-color"

	// configFilePath path to local configuration file
	configFilePath          string
	configFilePathFlagName  = "config-file"
	configFilePathShortFlag = "c"
)

// Scan flags
var (
	// repositoryUrl the path to the repository to scan
	repositoryUrl          string
	repositoryUrlFlagName  = "repository-url"
	repositoryUrlShortFlag = "r"

	// repositoryUrl the path to the repository to scan
	accessToken          string
	accessTokenFlagName  = "access-token"
	accessTokenShortFlag = "t"

	// branch the branch name to scan
	branch          string
	branchFlagName  = "branch"
	branchShortFlag = "b"
)
