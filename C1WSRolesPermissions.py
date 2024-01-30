import requests
import csv
import re

def format_permission_string(s):
    formatted_string = re.sub(r'_(?=[A-Za-z])', ' -> ', s)
    formatted_string = re.sub(r'(?<!^)(?=[A-Z])', ' ', formatted_string)
    formatted_string = ' '.join(word.capitalize() for word in formatted_string.split())
    return formatted_string.replace('Anti Malware', 'AntiMalware')

def flatten_permissions(perm_dict, prefix=''):
    flat_perms = {}
    for key, value in perm_dict.items():
        if isinstance(value, dict):
            flat_perms.update(flatten_permissions(value, prefix + key + '_'))
        else:
            flat_perms[prefix + key] = value
    return flat_perms

def fetch_names(ids, endpoint):
    names = []
    for _id in ids:
        response = requests.get(f"{base_url}/{endpoint}/{_id}", headers=headers)
        if response.status_code == 200:
            names.append(response.json()['name'])
        else:
            names.append(f"ID {_id} not found")
    return ', '.join(names)

region = input("Please enter your region: ")
api_key = input("Please enter your API key: ")

base_url = f"https://workload.{region}.cloudone.trendmicro.com/api"
headers = {'Authorization': f'ApiKey {api_key}', 'api-version': 'v1'}

response = requests.get(f"{base_url}/roles", headers=headers)
data = response.json()

all_permissions = set()
roles_info = {}
roles_permissions = {}

for role in data['roles']:
    role_info = {
        'Description': role.get('description', ''),
        'Urn': role.get('urn', ''),
        'Immutable': role.get('immutable', ''),
        'Hidden': role.get('hidden', ''),
        'Predefined': role.get('predefined', ''),
        'CreatedFromV1': role.get('createdFromV1', ''),
        'ID': role.get('ID', ''),
        'Computer Groups Scopes': 'All' if role.get('allComputers', False) else fetch_names(role.get('computerGroupIDs', []), 'computergroups'),
        'Policies Scopes': 'All' if role.get('allPolicies', False) else fetch_names(role.get('policyIDs', []), 'policies'),
        'AntiMalware Configuration Scopes': 'All' if role.get('commonObjectScopes', {}).get('antiMalwareConfigurationScopes', {}).get('allMalwareConfigurations', False) else fetch_names(role.get('commonObjectScopes', {}).get('antiMalwareConfigurationScopes', {}).get('malwareConfigurationIDs', []), 'antimalwareconfigurations'),
        'File Lists Scopes': 'All' if role.get('commonObjectScopes', {}).get('fileListScopes', {}).get('allFileLists', False) else fetch_names(role.get('commonObjectScopes', {}).get('fileListScopes', {}).get('fileListIDs', []), 'filelists'),
        'Directory Lists Scopes': 'All' if role.get('commonObjectScopes', {}).get('directoryListScopes', {}).get('allDirectoryLists', False) else fetch_names(role.get('commonObjectScopes', {}).get('directoryListScopes', {}).get('directoryListIDs', []), 'directorylists'),
        'File Extension Lists Scopes': 'All' if role.get('commonObjectScopes', {}).get('fileExtensionListScopes', {}).get('allFileExtensionLists', False) else fetch_names(role.get('commonObjectScopes', {}).get('fileExtensionListScopes', {}).get('fileExtensionListIDs', []), 'fileextensionlists')
    }
    permissions = flatten_permissions(role['rights'])
    roles_permissions[role['name']] = permissions
    roles_info[role['name']] = role_info
    all_permissions.update(permissions.keys())

all_permissions = sorted(list(all_permissions))

with open('roles_permissions_details_updated.csv', 'w', newline='', encoding='utf-8') as csvfile:
    writer = csv.writer(csvfile)

    writer.writerow(['Permission'] + list(roles_permissions.keys()))

    additional_info_keys = ['Description', 'Urn', 'Immutable', 'Hidden', 'Predefined', 'CreatedFromV1', 'ID', 'Computer Groups Scopes', 'Policies Scopes', 'AntiMalware Configuration Scopes', 'File Lists Scopes', 'Directory Lists Scopes', 'File Extension Lists Scopes']
    for info_key in additional_info_keys:
        row = [info_key]
        for role in roles_info.values():
            row.append(role[info_key])
        writer.writerow(row)

    for perm in all_permissions:
        formatted_perm = format_permission_string(perm)
        row = [formatted_perm]
        for role in roles_permissions.values():
            row.append(role.get(perm, False))
        writer.writerow(row)
