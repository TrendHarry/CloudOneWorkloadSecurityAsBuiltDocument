import requests
import csv
from datetime import datetime

def get_role_access(service_role_urns, service_name):
    access_pattern = f"urn:cloudone:{service_name}:au-1:406000301716:role/"
    for urn in service_role_urns:
        if access_pattern in urn:
            return urn.split('/')[-1].replace('-', ' ').capitalize()
    return ""

def main():
    api_key = input("Please enter your API key: ")
    headers = {
        'Api-Version': 'v1',
        'Authorization': f'ApiKey {api_key}'
    }

    roles_url = "https://accounts.cloudone.trendmicro.com/api/roles"
    roles_response = requests.get(roles_url, headers=headers)
    roles_data = roles_response.json()['roles']

    permissions = [
        "Application Security", "Audit Log", "Billing and Subscriptions",
        "Cloud Provider Accounts", "Conformity", "Container Security",
        "Endpoint & Workload Security", "File Storage Security",
        "Identity and Account", "Network Security", "Outbound Integrations",
        "snyk", "Source Provider Accounts"
    ]

    service_names = [
        "", "audit", "billing", "cloudaccounts", "conformity", "",
        "workload", "", "identity", "network", "integrations", "snyk", "sourceaccounts"
    ]

    roles_info = {role['name']: role for role in roles_data}

    csv_data = []
    for perm, service_name in zip(permissions, service_names):
        row = {'Permissions': perm}
        for role_name, role in roles_info.items():
            access = role_name if perm == "Endpoint & Workload Security" else get_role_access(role['serviceRoleURNs'], service_name)
            row[role_name] = access
        csv_data.append(row)

    current_utc_time = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    file_name = f'RolePermissions_{current_utc_time}.csv'
    with open(file_name, 'w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=['Permissions'] + list(roles_info.keys()))
        writer.writeheader()
        writer.writerows(csv_data)

    print(f"CSV file '{file_name}' has been created.")

if __name__ == "__main__":
    main()
