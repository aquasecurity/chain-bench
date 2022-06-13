package utils

func Contains[T comparable](slice []T, searchTerm T) bool {
	for _, t := range slice {
		if t == searchTerm {
			return true
		}
	}
	return false
}
