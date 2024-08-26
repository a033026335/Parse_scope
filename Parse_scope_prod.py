#The purpose of this script is to help pen testers to easily import postman collections and IP addresses from remediation lead
#and have it export into csv file that can easily re-upload into Restart.
#This will help pen testers save a lot of time when there are large amount of API endpoints that are in scope. 

import json
from tkinter import Tk, filedialog
import socket 
import pandas as pd
# import inquirer
# import ipaddress
# import re
from urllib.parse import urlparse, quote, urlencode, parse_qs

# pip install pyfiglet
import pyfiglet

scope = []
endpoints = []
ip_addresses = []
range_ip_addresses = []
processed_ip_addresses = []
processed_range_ip_addresses = []
final_ip_addresses = []

#Defining parse_test_scope on gathering IP addresses.
def get_ip_addresses():
    print("Enter IP addresses (separate multiple address with spaces):")
    input_ips = input().split()
    for ip in input_ips:
        ip_addresses.append(ip)
    return ip_addresses

#Defining parse_test_scope on converting IP range to a list of IP addresses.
def get_ip_range():
    start_ip = input('Enter the starting IP address: ')
    end_ip = input('Enter the ending IP address: ')
    start_octetes = list(map(int, start_ip.split('.')))
    end_octets = list(map(int, end_ip.split('.')))

    while start_octetes <= end_octets:
        range_ip_addresses.append('.'.join(map(str,start_octetes)))
        start_octetes[-1] += 1
        for i in reversed(range(1,4)):
            if start_octetes[i] == 256:
                start_octetes[i] = 0
                start_octetes[i-1] +=1
    return range_ip_addresses

#Defining parse_test_scope on getting solution name from postman collection.
def sort_by_solution(item):
    #Docstring distriptions.
    return item.get('Solution')

#Defining parse_test_scope on converting IP address to DNS name utilizing socket.
def get_dns_name(ip):
    try:
        dns_name=socket.gethostbyaddr(ip)[0]
        return dns_name
    except socket.herror:
        return ""

#Defining parse_test_scope on expoerting data to csv using dataframe. 
def export_csv(data, output_file):

    # Create a pandas DataFrame
    df = pd.DataFrame(data)

    # Export DataFrame to csv
    df.to_csv(output_file, index=False)

#Defining parse_test_scope on processing main menu selection
def get_user_input():

    print('Select an option:')
    print('1. Import REST API endpoints to export formatted scope in .csv and http requests in .txt')
    print('2. Import IP addresses')
    print('q. Quit')
    choice = input('Enter your choice (1 or 2): ')
    if choice not in ['1', '2', 'q']:
        print('Invalid selection.')
    return choice

#Defining convert_to_http_requests to convert Postmam and Insomnia collections to http requests.
def convert_to_http_requests(collection_data, collection_type='postman'):
    http_requests = []
    if collection_type == 'postman':
        for item in collection_data['item']:
            if item.get('request'):
                method = item['request']['method']
                url_details = item['request']['url']
                # Constructing the first line with method and path
                path = url_details['path']
                path_str = '/' + '/'.join(path) if path else ''
                query = '&'.join([f'{q["key"]}={q["value"]}' for q in url_details.get('query', [])])
                path_with_query = f'{path_str}?{query}' if query else path_str
                first_line = f'{method} {path_with_query} HTTP/1.1\n'
                # Constructing the headers, including Host and potentially authorization.
                host = url_details['host']
                host_str = '.'.join(host) if host else ''
                headers = item['request'].get('header', [])
                headers.append({'key': 'Host', 'value': host_str})  # Add Host header
                #Adding scanning for Content-Type header as part of header to make sure it has required Content-Type parameter.
                content_type_present = any(header.get('key','') == 'Content-Type' for header in headers)
                if not content_type_present:
                    headers.append({'key':'Content-Type', 'value': 'application/json'})
                # Check for auth object and append auth header accordingly and add it into header.
                auth = item['request'].get('auth')
                if auth:
                    if auth['type'] == 'basic':
                        import base64
                        user_pass = f"{auth['basic'][0]['value']}:{auth['basic'][1]['value']}"
                        encoded_credentials = base64.b64encode(user_pass.encode()).decode()
                        headers.append({'key': 'Authorization', 'value': f'Basic {encoded_credentials}'})
                    elif auth['type'] == 'bearer':
                        token = auth['bearer'][0]['value']
                        headers.append({'key': 'Authorization', 'value': f'Bearer {token}'})
                    # Add other auth types here as needed
                headers_line = '\n'.join([f'{header["key"]}: {header["value"]}' for header in headers]) + '\n\n'
                # Constructing the body from the 'raw' parameter
                body = item['request'].get('body', {})
                body_line = body.get('raw', '') + '\n\n' if body.get('mode') == 'raw' else ''
                http_requests.append(first_line + headers_line + body_line)

    elif collection_type == 'insomnia':
        for item in collection_data.get('resources', []):
            if item.get('_type') == 'request':
                method = item.get('method')
                url = item.get('url')
                parsed_url = urlparse(url)
                # Handle merging existing and new query parameters
                existing_query = parse_qs(parsed_url.query)
                params = item.get('parameters', [])
                param_dict = {param['name']: param['value'] for param in params if 'name' in param and 'value' in param}
                all_params = {**existing_query, **param_dict}
                full_query = urlencode(all_params, doseq=True)
                path_with_query = parsed_url.path
                if full_query:
                    path_with_query += f'?{full_query}'
                first_line = f'{method} {path_with_query} HTTP/1.1\n'
                headers = item.get('headers', [])
                headers.append({'name': 'Host', 'value': parsed_url.netloc})
                #Adding scanning for Content-Type header as part of header to make sure it has required Content-Type parameter.
                content_type_present = any(header.get('name','') == 'Content-Type' for header in headers)
                if not content_type_present:
                    headers.append({'name':'Content-Type', 'value': 'application/json'})
                auth = item.get('authentication', {})
                auth_type = auth.get('type')
                if auth_type == 'basic':
                    import base64
                    user_pass = f"{auth.get('username')}:{auth.get('password')}"
                    encoded_credentials = base64.b64encode(user_pass.encode()).decode()
                    headers.append({'name': 'Authorization', 'value': f'Basic {encoded_credentials}'})
                elif auth_type == 'bearer':
                    token = auth.get('token')
                    headers.append({'name': 'Authorization', 'value': f'Bearer {token}'})
                headers_line = '\n'.join(f'{header["name"]}: {header["value"]}' for header in headers) + '\n\n'
                body = item.get('body', {})
                body_type = body.get('mimeType')
                body_content = body.get('text', '')
                body_line = body_content + '\n\n'  # Default fallback
                if body_content and body_type == 'application/json':
                    try:
                        json_object = json.loads(body_content)
                        body_line = json.dumps(json_object, indent=2) + '\n\n'
                    except json.JSONDecodeError:
                        print("Error decoding JSON: Invalid content")  # Logging the error
                        body_line = 'Invalid JSON content.\n\n'
                elif body_type == 'application/x-www-form-urlencoded':
                    try:
                        body_line = urlencode(json.loads(body_content)) + '\n\n'
                    except json.JSONDecodeError:
                        print("Error decoding form-urlencoded data: Invalid content")
                        body_line = 'Invalid form data.\n\n'
                http_requests.append(first_line + headers_line + body_line)
    return http_requests

# New function to export data to a .txt file
def export_to_txt(data, output_file):
    with open(output_file, "w") as file:
        for line in data:
            file.write(line + "\n")

#Defining parse_test_scope of postman datas.
def process_postman(collection_data, info_name = None):

    #Extracting solution name. We wamt to make sure that we use () instead of [], so when the loop sees no solution name, it doens't cause error, but print out none. 

    if not info_name:
        process_postman_info_name= collection_data.get('info').get('name')

        # Extract endpoint names and URLs. 
        # 
        # First, it scans the object that name iten and get into the object.
            
    for item in collection_data['item']:

        #It then look for an object that is request. That means it has endpoint. Then, it will gather information about the endpoint and append into appropriate format.
        #It also determine if the endpoint is internal or external proxy and appropriate labels to name.
        if item.get('request'):
            endpoint_name = item['name']
            endpoint_url = item['request']['url']['raw']
            url_validation=endpoint_url.split('//')[1].lstrip().split('/')[0]
            print(f'if was captured: {endpoint_url}')

            if ("proxy" or "gateway") in endpoint_url:
                endpoint_name = f'External - {endpoint_name}'
            else:
                endpoint_name = f'Internal - {endpoint_name}'

            endpoints.append({ 'Id': '', 'Solution': process_postman_info_name, 'Request': process_postman_info_name, 'RequestScopeType': 'Web Application', 'Name': endpoint_name, 'Description': '',
            'CloudProvider': '', 'ResourceParent': '', 'ResourceCollection': '', 'ResourceName': '', 'Region': '', 'Market' :'',
            'Network':'', 'NetworkLocation': '', 'Country': '', 'HostnameOrIPAddress': '', 'NetworkPath': '', 'DnsName': '', 'Port':'',
            'Protocol': '', 'SiteNumber': '', 'StartIP': '', 'EndIP': '', 'ApmId': '', 'SrcrOrSspId': '', 'IsInternallyDeveloped': '',
            'IsSourceCodeAvailableForTheApplication': '', 'ApplicationPath': endpoint_url, 'SourceRepositoryUrl': '', 'DeviceName': '',
            'DevicePath': '', 'OperatingSystem': '', 'Manufacturer': '', 'Model': '', 'IsPhysicallyAccessible': '',
            'IsItPossibleToShipTheDevice': '', 'IsRemoteSupportAvailable': '', 'IsWirelessDevice': '', 'IsExternallyAccessible': '',
            'IsInPCIScope': '', 'IsCreditCardInformationAccepted': '', 'IsDeployedInASecureEnvironment': '', 'IsDocumentationAvailable': '',
            'DocumentationUrl': '', 'IsAuthenticationRequired': '', 'IsAccountLockoutEnabled': '', 'IsAuthenticationDocumentationAvailable': '',
            'AuthenticationDocumentationUrl': '', 'CreatedBy': '', 'CreatedOn': ''})
            
        #Otherwise, if it sees a folder instead of an endpoint, it get into the folder and retrave endpoints and returns it. Besides the folder that name "not in scope"
        elif item.get('name'):
            folder_name= item['name']

            if folder_name == 'not in scope':

                continue
            else:
                process_postman(item,info_name)

    #It returns endpoint outside of the if statement
    return endpoints

#Defining parse_test_scope of Insomnia datas.
def process_Insomnia(collection_data):

    #Extracting solution name. We wamt to make sure that we use () instead of [], so when the loop sees no solution name, it doens't cause error, but print out none. 

    process_Insomnia_info_name = input("Enter solution name:")


        # Extract endpoint names and URLs. 
        # 
        # First, it scans the object that name iten and get into the object.
            
    for item in collection_data.get('resources', []):

        #It then look for an object that is request. That means it has endpoint. Then, it will gather information about the endpoint and append into appropriate format.
        #It also determine if the endpoint is internal or external proxy and appropriate labels to name.
        if item.get('_type')== 'request':
            endpoint_name = item.get('name')
            endpoint_url = item.get('url')
            #url_validation=endpoint_url.split('//')[1].lstrip().split('/')[0]
            
            if ("proxy" or "gateway") in endpoint_url:
                endpoint_name = f'External - {endpoint_name}'
            else:
                endpoint_name = f'Internal - {endpoint_name}'

            endpoints.append({ 'Id': '', 'Solution': process_Insomnia_info_name, 'Request': process_Insomnia_info_name, 'RequestScopeType': 'Web Application', 'Name': endpoint_name, 'Description': '',
            'CloudProvider': '', 'ResourceParent': '', 'ResourceCollection': '', 'ResourceName': '', 'Region': '', 'Market' :'',
            'Network':'', 'NetworkLocation': '', 'Country': '', 'HostnameOrIPAddress': '', 'NetworkPath': '', 'DnsName': '', 'Port':'',
            'Protocol': '', 'SiteNumber': '', 'StartIP': '', 'EndIP': '', 'ApmId': '', 'SrcrOrSspId': '', 'IsInternallyDeveloped': '',
            'IsSourceCodeAvailableForTheApplication': '', 'ApplicationPath': endpoint_url, 'SourceRepositoryUrl': '', 'DeviceName': '',
            'DevicePath': '', 'OperatingSystem': '', 'Manufacturer': '', 'Model': '', 'IsPhysicallyAccessible': '',
            'IsItPossibleToShipTheDevice': '', 'IsRemoteSupportAvailable': '', 'IsWirelessDevice': '', 'IsExternallyAccessible': '',
            'IsInPCIScope': '', 'IsCreditCardInformationAccepted': '', 'IsDeployedInASecureEnvironment': '', 'IsDocumentationAvailable': '',
            'DocumentationUrl': '', 'IsAuthenticationRequired': '', 'IsAccountLockoutEnabled': '', 'IsAuthenticationDocumentationAvailable': '',
            'AuthenticationDocumentationUrl': '', 'CreatedBy': '', 'CreatedOn': ''})

        #Otherwise, if it sees a folder instead of an endpoint, it get into the folder and retrave endpoints and returns it. Besides the folder that name "not in scope"
        elif collection_data.get('_type')== 'request_group':
            folder_name= collection_data.get('name')

            if folder_name == 'not in scope':

                continue
            else:
                process_Insomnia(item)

    #It returns endpoint outside of the if statement
    return endpoints

#Defining parse_test_scope of IPs.
def process_ip(ip_addresses):

    #Extracting solution name. We wamt to make sure that we use () instead of [], so when the loop sees no solution name, it doens't cause error, but print out none. 

    process_ip_info_name = input("Enter solution name:")
        # Extract endpoint names and URLs. 
        # 
        # First, it scans the object that name iten and get into the object.

    
    for ip in ip_addresses:
        dns_name= get_dns_name(ip)
        application_path = 'https://'+ip+'/'
        #It then look for an object that is request. That means it has endpoint. Then, it will gather information about the endpoint and append into appropriate format.
        #It also determine if the endpoint is internal or external proxy and appropriate labels to name.

        processed_ip_addresses.append({ 'Id': '', 'Solution': process_ip_info_name, 'Request': process_ip_info_name, 'RequestScopeType': 'Networking & Infrastructure', 'Name': ip, 'Description': '',
        'CloudProvider': '', 'ResourceParent': '', 'ResourceCollection': '', 'ResourceName': '', 'Region': '', 'Market' :'',
        'Network':'', 'NetworkLocation': '', 'Country': '', 'HostnameOrIPAddress': ip, 'NetworkPath': '', 'DnsName': dns_name, 'Port':'',
        'Protocol': '', 'SiteNumber': '', 'StartIP': '', 'EndIP': '', 'ApmId': '', 'SrcrOrSspId': '', 'IsInternallyDeveloped': '',
        'IsSourceCodeAvailableForTheApplication': '', 'ApplicationPath': '', 'SourceRepositoryUrl': '', 'DeviceName': '',
        'DevicePath': '', 'OperatingSystem': '', 'Manufacturer': '', 'Model': '', 'IsPhysicallyAccessible': '',
        'IsItPossibleToShipTheDevice': '', 'IsRemoteSupportAvailable': '', 'IsWirelessDevice': '', 'IsExternallyAccessible': '',
        'IsInPCIScope': '', 'IsCreditCardInformationAccepted': '', 'IsDeployedInASecureEnvironment': '', 'IsDocumentationAvailable': '',
        'DocumentationUrl': '', 'IsAuthenticationRequired': '', 'IsAccountLockoutEnabled': '', 'IsAuthenticationDocumentationAvailable': '',
        'AuthenticationDocumentationUrl': '', 'CreatedBy': '', 'CreatedOn': ''})

    return processed_ip_addresses

#Defining parse_test_scope of IPs.
def process_range_ip(range_ip_addresses):

    #Extracting solution name. We wamt to make sure that we use () instead of [], so when the loop sees no solution name, it doens't cause error, but print out none. 

    process_range_ip_info_name = input("Enter solution name:")
        # Extract endpoint names and URLs. 
        # 
        # First, it scans the object that name iten and get into the object.

    
    for ip in range_ip_addresses:
        dns_name= get_dns_name(ip)
        start_ip= range_ip_addresses [0]
        end_ip = range_ip_addresses [-1]
        application_path = 'https://'+ip+'/'
        #It then look for an object that is request. That means it has endpoint. Then, it will gather information about the endpoint and append into appropriate format.
        #It also determine if the endpoint is internal or external proxy and appropriate labels to name.

        processed_ip_addresses.append({ 'Id': '', 'Solution': process_range_ip_info_name, 'Request': process_range_ip_info_name, 'RequestScopeType': 'Networking & Infrastructure', 'Name': ip, 'Description': '',
        'CloudProvider': '', 'ResourceParent': '', 'ResourceCollection': '', 'ResourceName': '', 'Region': '', 'Market' :'',
        'Network':'', 'NetworkLocation': '', 'Country': '', 'HostnameOrIPAddress': ip, 'NetworkPath': '', 'DnsName': dns_name, 'Port':'',
        'Protocol': '', 'SiteNumber': '', 'StartIP': start_ip, 'EndIP': end_ip, 'ApmId': '', 'SrcrOrSspId': '', 'IsInternallyDeveloped': '',
        'IsSourceCodeAvailableForTheApplication': '', 'ApplicationPath': '', 'SourceRepositoryUrl': '', 'DeviceName': '',
        'DevicePath': '', 'OperatingSystem': '', 'Manufacturer': '', 'Model': '', 'IsPhysicallyAccessible': '',
        'IsItPossibleToShipTheDevice': '', 'IsRemoteSupportAvailable': '', 'IsWirelessDevice': '', 'IsExternallyAccessible': '',
        'IsInPCIScope': '', 'IsCreditCardInformationAccepted': '', 'IsDeployedInASecureEnvironment': '', 'IsDocumentationAvailable': '',
        'DocumentationUrl': '', 'IsAuthenticationRequired': '', 'IsAccountLockoutEnabled': '', 'IsAuthenticationDocumentationAvailable': '',
        'AuthenticationDocumentationUrl': '', 'CreatedBy': '', 'CreatedOn': ''})

    return processed_range_ip_addresses

#Defining parse_test_scope of unify menu response on yes or no.
def process_yes_no_menu_prompt(prompt):
    while True:
        user_input =input(f"{prompt} (yes/no): ").strip().lower()

        if user_input == 'yes':
            return True
        elif user_input == 'no':
            return False
        else:
            print('Invalid input. Please enter yes or no')

#Defining parse_test_scope of unify menu response on numeric options.
def process_numeric_menu_prompt(prompt):
    while True:
        try:
            user_input =input(f"{prompt} (1, 2 or q): ")

            if user_input == '1' or user_input == '2' or user_input == 'q':
                return user_input
            else:
                print('Invalid input. Please enter 1, 2 or q.')
        except ValueError:
            print('Invalid input. Please enter a valid number.')

#Defining parse_test_scope of reseting ip addresses in global variable.
def reset_global_varialbe_ip():
    global ip_addresses, range_ip_addresses, processed_ip_addresses, processed_range_ip_addresses, final_ip_addresses
    del ip_addresses[:], range_ip_addresses[:], processed_ip_addresses[:], processed_range_ip_addresses[:], final_ip_addresses[:]

#Defining parse_test_scope of resetting API in global variable.
def reset_global_varialbe_API():
    global endpoints
    del endpoints[:]

#API's sub menu
def choice_one():
    while True:
        print("Choose one option:")
        print("1. Upload Postman collection")
        print("2. Upload Insomnia collection")
        print('q. Quit')
        prompt_text = "Enter your choice. "
        selected_option = process_numeric_menu_prompt(prompt_text)
        http_requests = []  # List to store HTTP requests
        if selected_option == '1':
            window = Tk()
            window.withdraw()
            while True:
                print("Select your Postman Collection(s): ")
                file_paths = filedialog.askopenfilenames(filetypes=[("Postman Collection", "*.json")])
                for file_path in file_paths:
                    if not file_path:
                        print("Error: No file selected.")
                        continue
                    with open(file_path, 'r') as file:
                        data = json.load(file)
                        try:
                            process_postman(data)
                        except IndexError or AttributeError:
                            print('Invalid Postman collection. Please ensure all parameters within the collection are complete.')
                        http_requests.extend(convert_to_http_requests(data, 'postman'))
                prompt_text = "Do you have more Postman collections?"
                decision = process_yes_no_menu_prompt(prompt_text)
                if not decision:
                    break
        elif selected_option == '2':
            window = Tk()
            window.withdraw()
            while True:
                print("Select your Insomnia Collection(s): ")
                file_paths = filedialog.askopenfilenames(filetypes=[("Insomnia Collection", "*.json")])
                for file_path in file_paths:
                    if not file_path:
                        print("Error: No file selected.")
                        continue
                    with open(file_path, 'r') as file:
                        data = json.load(file)
                        try:
                            process_Insomnia(data)
                        except IndexError or AttributeError:
                            print('Invalid Insomnia collection. Please ensure all parameters within the collection are complete.')
                        http_requests.extend(convert_to_http_requests(data, 'insomnia'))
                prompt_text = "Do you have more Insomnia collections?"
                decision = process_yes_no_menu_prompt(prompt_text)
                if not decision:
                    break
        elif selected_option == 'q':
            main()
        else:
            print("Invalid choice, please enter 1 or 2. \n")
            continue
        # Open file dialog to select output file base name
        base_output_file = filedialog.asksaveasfilename(defaultextension='', filetypes=[("All Files", "*.*")])
        if base_output_file:
            # Export to CSV and TXT
            export_csv(endpoints, base_output_file + '.csv')
            export_to_txt(http_requests, base_output_file + '.txt')
            print("Export successful!")
            break
        else:
            print("No output file selected.")

#IP's sub menu
def choice_two():
    ip_addresses = []
    range_ip_addresses = []

    while True:
        print("Choose one option:")
        print("1. Enter individual IP addresses")
        print("2. Enter an IP address range")
        print('q. Quit')
        ip_option = input('Enter your choice (1, 2 or q: ')

        if ip_option == '1':
            ip_addresses = get_ip_addresses()
            # Create the main window
            prompt_text = "Do you have more IP addrsses?"
            decision = process_yes_no_menu_prompt(prompt_text)

            if decision == False:
                break

        elif ip_option == '2':
            range_ip_addresses = get_ip_range()
            prompt_text = "Do you have more IP addrsses?"
            decision = process_yes_no_menu_prompt(prompt_text)
            if decision == False:
                break

        elif ip_option == 'q':
            main()
        else:
            print('Invalid input. Please enter 1 or 2.')

    window = Tk()
    window.withdraw()
    output_file = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[("csv file", "*.csv")])

    while True:
        if output_file:
            # Export the ip_addresses to CSV
            processed_ip_addresses=process_ip(ip_addresses)
            processed_range_ip_addresses = process_range_ip(range_ip_addresses)
            final_ip_addresses = processed_ip_addresses + processed_range_ip_addresses
            export_csv(final_ip_addresses, output_file)
            print("Export successful!")
            del ip_addresses
            
            break
        else:
            print("Error exporting")

#Main
def main():
    while True:
        reset_global_varialbe_ip()
        reset_global_varialbe_API()
        ascii_banner = pyfiglet.figlet_format("Howdy from Tech Review!!")
        print(ascii_banner)
        choice = get_user_input()
        if choice == '1':
            choice_one()

        elif choice == '2':
            choice_two()

        elif choice == 'q':
            break
        else:
            print('Invalid choice. Please enter either 1 or 2')
        
if __name__ == "__main__":
    main()
