package utils

func GetValue[T any](p *T) T {
	if p == nil {
		var v T
		return v
	}

	return *p
}

func GetPtr[T any](value T) *T {
	return &value
}

func GetBranchName(defaultBranch, branchName string) string {
	if branchName != "" {
		return branchName
	}

	return defaultBranch
}
