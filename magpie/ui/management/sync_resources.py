import threddsclient


def merge_db_and_remote_resources(current_resources, service_url, service_name):
    depth = 2  # replace with global parameter?

    external_resources = {}

    if service_name == "thredds":
        external_resources = thredds_get_references(service_url, depth)

    if external_resources:
        # don't compare the name of the service, only the resources
        service_name = list(current_resources)[0]
        external_service_name = list(external_resources)[0]
        external_resources[service_name] = external_resources[external_service_name]
        del external_resources[external_service_name]

        merged_resources = traverse_and_merge_ressources(current_resources, external_resources)

        return merged_resources

    return current_resources


def thredds_get_references(url, depth=0, **kwargs):
    cat = threddsclient.read_url(url, **kwargs)
    name = cat.name

    tree_item = {name: {'children': {}}}

    if depth > 0:
        for reference in cat.flat_references():
            tree_item[name]['children'].update(thredds_get_references(reference.url, depth - 1))

    return tree_item


def traverse_and_merge_ressources(current_resources, external_resources, remote_path=""):
    for resource_name, values in current_resources.items():
        matches_remote = resource_name in external_resources
        values["matches_remote"] = matches_remote

        external_resource_children = external_resources.get(resource_name, {}).get('children', {})
        new_path = "/".join([remote_path, resource_name])
        traverse_and_merge_ressources(values['children'], external_resource_children, new_path)

    for resource_name, values in external_resources.items():
        if not resource_name in current_resources:
            new_path = "/".join([remote_path, resource_name])
            new_resource = {'permission_names': [],
                            'children': {},
                            'id': new_path,
                            'remote_path': new_path,
                            'matches_remote': True}

            current_resources[resource_name] = new_resource
            traverse_and_merge_ressources(new_resource['children'], values['children'], new_path)

    return current_resources
