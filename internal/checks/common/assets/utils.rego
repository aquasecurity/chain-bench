package generic.utils

is_pipelines_data_missing {
	input.Pipelines == null
}

is_pipelines_list_empty {
	count(input.Pipelines) == 0
}

is_organization_data_missing {
	input.Organization == null
}
