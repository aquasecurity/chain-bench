package generic.utils

ensure_pipelines_fetched {
	input.Pipelines != null
}

ensure_pipelines_exists {
	count(input.Pipelines) > 0
}
