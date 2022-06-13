package consts

import "errors"

// checks registration errors
var (
	ErrorNoCheckID     = errors.New("Missing Check ID")
	ErrorNoName        = errors.New("Missing Name")
	ErrorNoEntity      = errors.New("Missing Entity")
	ErrorNoType        = errors.New("Missing Type")
	ErrorNoDescription = errors.New("Missing Description")
	ErrorNoRemediation = errors.New("Missing Remediation")
	ErrorNoUrl         = errors.New("Missing Url")
	ErrorNoCheckAction = errors.New("Check action cannot be nil")
)
