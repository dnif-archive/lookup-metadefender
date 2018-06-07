import requests
import pprint
import os
import yaml

path = os.environ["WORKDIR"]
with open(path + "/lookup_plugins/metadefender/dnifconfig.yml", 'r') as ymlfile:
with open("dnifconfig.yml") as ymlfile:
    cfg = yaml.load(ymlfile)


def get_cve_products(inward_array, var_array):
    # https://onlinehelp.opswat.com/mdcloud/6.2_CVE_Information_Lookup.html
    for i in inward_array:

        if var_array[0] in i:
            headers = {
                'authorization': 'apikey ' + str(cfg['lookup_plugin']['MD_API_KEY']),
                "Accept-Encoding": "gzip, deflate",
                "User-Agent": "gzip,  My Python requests library example client or username"
            }

        url = 'https://api.metadefender.com/v3/cve/:cve/products'
        url = url.replace(':cve', i[var_array[0]])

        try:
            response = requests.get(url, headers=headers)
        except Exception as e:
            return "Error in API" + str(e)

        json_response = response.json()

        try:
            i['$MDSuccess'] = json_response['success']
        except Exception:
            pass

        data = json_response['data']

        try:
            i['$MDCVE'] = data['cve']
        except Exception:
            pass

        try:
            i['$MDDescription'] = data['description']
        except Exception:
            pass

        try:
            i['$MDCWE'] = data['cwe']
        except Exception:
            pass

        try:
            for key, value in data['cvss_2_0'].items():
                i['$MDCVSS2' + key.replace('_', '')] = value
        except Exception:
            pass

        try:
            for key, value in data['cvss_3_0'].items():
                if key == 'opswat_temporal_score':
                    for key1, value1 in data['cvss_3_0']['opswat_temporal_score'].items():
                        if 'epoch' in key1:
                            continue
                        else:
                            i['$MDCVSS3OPSWAT' + key1.replace('_', '')] = value1
                else:
                    i['$MDCVSS3' + key.replace('_', '')] = value
        except Exception:
            pass

        try:
            higher_version = []
            product_id = []
            product_name = []
            for dic in data['resolution']:
                higher_version.append(dic['higher_than_version'])
                product_id.append(dic['product_id'])
                product_name.append(dic['product_name'])
            if higher_version:
                i['$MDProductResolutionVersion'] = higher_version
            if product_id:
                i['$MDProductResolutionID'] = product_id
            if product_name:
                i['$MDProductResolutionName'] = product_name
        except Exception:
            pass

        try:
            product_id = []
            product_name = []
            vul_start = []
            vul_end = []
            vendor_id = []
            vendor_name = []
            for dic in data['opswat_product_info']:
                product_id.append(dic['product']['id'])
                product_name.append(dic['product']['name'])
                for dic_nested in dic['ranges']:
                    vul_start.append(dic_nested['start'])
                    vul_end.append(dic_nested['limit'])
                vendor_id.append(dic['vendor']['id'])
                vendor_name.append(dic['vendor']['name'])
            if product_id:
                i['$MDOPSWATProductID'] = product_id
            if product_name:
                i['$MDOPSWATProductName'] = product_name
            if vul_start:
                i['$MDOPSWATVulnerableRangeStart'] = vul_start
            if vul_end:
                i['$MDOPSWATVulnerableRangeLimit'] = vul_end
            if vendor_id:
                i['$MDOPSWATVendorID'] = vendor_id
            if vendor_name:
                i['$MDOPSWATVendorName'] = vendor_name
        except Exception:
            pass

        try:
            references = []
            for dic in data['references']:
                temp = [dic['url']]
                references.append(temp)
            if references:
                i['$MDReferences'] = references
        except Exception:
            pass

        try:
            i['$MDSeverity'] = data['severity']
        except Exception:
            pass

        try:
            i['$MDSeverityIndex'] = data['severity_index']
        except Exception:
            pass

        try:
            i['$MDVulnerableSoftware'] = data['vulnerable_software_list']
        except Exception:
            pass

    return inward_array


def get_cve_vendors(inward_array, var_array):
    # https://onlinehelp.opswat.com/mdcloud/6.2_CVE_Information_Lookup.html
    for i in inward_array:

        if var_array[0] in i:
            headers = {
                'authorization': 'apikey ' + str(cfg['lookup_plugin']['MD_API_KEY']),
                "Accept-Encoding": "gzip, deflate",
                "User-Agent": "gzip,  My Python requests library example client or username"
            }

        url = 'https://api.metadefender.com/v3/cve/:cve/vendors'
        url = url.replace(':cve', i[var_array[0]])

        try:
            response = requests.get(url, headers=headers)
        except Exception as e:
            return "Error in API" + str(e)

        json_response = response.json()

        try:
            i['$MDSuccess'] = json_response['success']
        except Exception:
            pass

        data = json_response['data']

        try:
            i['$MDCVE'] = data['cve']
        except Exception:
            pass

        try:
            i['$MDDescription'] = data['description']
        except Exception:
            pass

        try:
            i['$MDCWE'] = data['cwe']
        except Exception:
            pass

        try:
            for key, value in data['cvss_2_0'].items():
                i['$MDCVSS2' + key.replace('_', '')] = value
        except Exception:
            pass

        try:
            for key, value in data['cvss_3_0'].items():
                if key == 'opswat_temporal_score':
                    for key1, value1 in data['cvss_3_0']['opswat_temporal_score'].items():
                        if 'epoch' in key1:
                            continue
                        else:
                            i['$MDCVSS3OPSWAT' + key1.replace('_', '')] = value1
                else:
                    i['$MDCVSS3' + key.replace('_', '')] = value
        except Exception:
            pass

        try:
            higher_version = []
            product_id = []
            product_name = []
            for dic in data['resolution']:
                higher_version.append(dic['higher_than_version'])
                product_id.append(dic['product_id'])
                product_name.append(dic['product_name'])
            if higher_version:
                i['$MDProductResolutionVersion'] = higher_version
            if product_id:
                i['$MDProductResolutionID'] = product_id
            if product_name:
                i['$MDProductResolutionName'] = product_name
        except Exception:
            pass

        try:
            product_id = []
            product_name = []
            vul_start = []
            vul_end = []
            vendor_id = []
            vendor_name = []
            for dic in data['opswat_product_info']:
                product_id.append(dic['product']['id'])
                product_name.append(dic['product']['name'])
                for dic_nested in dic['ranges']:
                    vul_start.append(dic_nested['start'])
                    vul_end.append(dic_nested['limit'])
                vendor_id.append(dic['vendor']['id'])
                vendor_name.append(dic['vendor']['name'])
            if product_id:
                i['$MDOPSWATProductID'] = product_id
            if product_name:
                i['$MDOPSWATProductName'] = product_name
            if vul_start:
                i['$MDOPSWATVulnerableRangeStart'] = vul_start
            if vul_end:
                i['$MDOPSWATVulnerableRangeLimit'] = vul_end
            if vendor_id:
                i['$MDOPSWATVendorID'] = vendor_id
            if vendor_name:
                i['$MDOPSWATVendorName'] = vendor_name
        except Exception:
            pass

        try:
            references = []
            for dic in data['references']:
                temp = [dic['url']]
                references.append(temp)
            if references:
                i['$MDReferences'] = references
        except Exception:
            pass

        try:
            i['$MDSeverity'] = data['severity']
        except Exception:
            pass

        try:
            i['$MDSeverityIndex'] = data['severity_index']
        except Exception:
            pass

        try:
            i['$MDVulnerableSoftware'] = data['vulnerable_software_list']
        except Exception:
            pass

    return inward_array


def get_cve_hashes(inward_array, var_array):
    # https://onlinehelp.opswat.com/mdcloud/6.2_CVE_Information_Lookup.html
    for i in inward_array:

        if var_array[0] in i:
            headers = {
                'authorization': 'apikey ' + str(cfg['lookup_plugin']['MD_API_KEY']),
                "Accept-Encoding": "gzip, deflate",
                "User-Agent": "gzip,  My Python requests library example client or username"
            }

        url = 'https://api.metadefender.com/v3/cve/:cve/hashes'
        url = url.replace(':cve', i[var_array[0]])

        try:
            response = requests.get(url, headers=headers)
        except Exception as e:
            return "Error in API" + str(e)

        json_response = response.json()

        try:
            i['$MDSuccess'] = json_response['success']
        except Exception:
            pass

        data = json_response['data']

        try:
            i['$MDCVE'] = data['cve']
        except Exception:
            pass

        try:
            i['$MDCWE'] = data['cwe']
        except Exception:
            pass


        try:
            for key, value in data['cvss_2_0'].items():
                i['$MDCVSS2' + key.replace('_', '')] = value
        except Exception:
            pass

        try:
            for key, value in data['cvss_3_0'].items():
                if key == 'opswat_temporal_score':
                    for key1, value1 in data['cvss_3_0']['opswat_temporal_score'].items():
                        if 'epoch' in key1:
                            continue
                        else:
                            i['$MDCVSS3OPSWAT' + key1.replace('_', '')] = value1
                else:
                    i['$MDCVSS3' + key.replace('_', '')] = value
        except Exception:
            pass

        try:
            i['$MDDescription'] = data['description']
        except Exception:
            pass

        try:
            i['$MDHashesCount'] = data['hashes_count']
        except Exception:
            pass

        try:
            higher_version = []
            product_id = []
            product_name = []
            for dic in data['resolution']:
                higher_version.append(dic['higher_than_version'])
                product_id.append(dic['product_id'])
                product_name.append(dic['product_name'])
            if higher_version:
                i['$MDProductResolutionVersion'] = higher_version
            if product_id:
                i['$MDProductResolutionID'] = product_id
            if product_name:
                i['$MDProductResolutionName'] = product_name
        except Exception:
            pass

        try:
            references = []
            for dic in data['references']:
                temp = [dic['url']]
                references.append(temp)
            if references:
                i['$MDReferences'] = references
        except Exception:
            pass

        try:
            i['$MDSeverity'] = data['severity']
        except Exception:
            pass

        try:
            i['$MDSeverityIndex'] = data['severity_index']
        except Exception:
            pass

        try:
            hash_sha1 = set()
            for hashes in data['sha1']:
                hash_sha1.add(hashes)
            i['$MDSHA1'] = list(hash_sha1)
        except Exception:
            pass

        try:
            hash_md5 = set()
            for hashes in data['md5']:
                hash_md5.add(hashes)
            i['$MDMD5'] = list(hash_md5)
        except Exception:
            pass

        try:
            hash_sha256 = set()
            for hashes in data['sha256']:
                hash_sha256.add(hashes)
            i['$MDSHA256'] = list(hash_sha256)
        except Exception:
            pass

        try:
            i['$MDVulnerableSoftware'] = data['vulnerable_software_list']
        except Exception:
            pass

    return inward_array


def get_cve(inward_array, var_array):
    # https://onlinehelp.opswat.com/mdcloud/6.2_CVE_Information_Lookup.html
    for i in inward_array:

        if var_array[0] in i:
            headers = {
                'authorization': 'apikey ' + str(cfg['lookup_plugin']['MD_API_KEY']),
                "Accept-Encoding": "gzip, deflate",
                "User-Agent": "gzip,  My Python requests library example client or username"
            }

        url = 'https://api.metadefender.com/v3/cve/'
        url += i[var_array[0]]

        try:
            response = requests.get(url, headers=headers)
        except Exception as e:
            return "Error in API" + str(e)

        json_response = response.json()

        try:
            i['$MDSuccess'] = json_response['success']
        except Exception:
            pass

        data = json_response['data']

        try:
            i['$MDCVE'] = data['cve']
        except Exception:
            pass

        try:
            i['$MDCWE'] = data['cwe']
        except Exception:
            pass

        try:
            for key, value in data['cvss_2_0'].items():
                i['$MDCVSS2' + key.replace('_', '')] = value
        except Exception:
            pass

        try:
            for key, value in data['cvss_3_0'].items():
                if key == 'opswat_temporal_score':
                    for key1, value1 in data['cvss_3_0']['opswat_temporal_score'].items():
                        if 'epoch' in key1:
                            continue
                        else:
                            i['$MDCVSS3OPSWAT' + key1.replace('_', '')] = value1
                else:
                    i['$MDCVSS3' + key.replace('_', '')] = value
        except Exception:
            pass

        try:
            i['$MDDescription'] = data['description']
        except Exception:
            pass

        try:
            i['$MDHashesCount'] = data['hashes_count']
        except Exception:
            pass

        try:
            references = []
            for dic in data['references']:
                temp = [dic['url']]
                references.append(temp)
            if references:
                i['$MDReferences'] = references
        except Exception:
            pass

        try:
            higher_version = []
            product_id = []
            product_name = []
            for dic in data['resolution']:
                higher_version.append(dic['higher_than_version'])
                product_id.append(dic['product_id'])
                product_name.append(dic['product_name'])
            if higher_version:
                i['$MDProductResolutionVersion'] = higher_version
            if product_id:
                i['$MDProductResolutionID'] = product_id
            if product_name:
                i['$MDProductResolutionName'] = product_name
        except Exception:
            pass

        try:
            product_id = []
            product_name = []
            vul_start = []
            vul_end = []
            vendor_id = []
            vendor_name = []
            for dic in data['opswat_product_info']:
                product_id.append(dic['product']['id'])
                product_name.append(dic['product']['name'])
                for dic_nested in dic['ranges']:
                    vul_start.append(dic_nested['start'])
                    vul_end.append(dic_nested['limit'])
                vendor_id.append(dic['vendor']['id'])
                vendor_name.append(dic['vendor']['name'])
            if product_id:
                i['$MDOPSWATProductID'] = product_id
            if product_name:
                i['$MDOPSWATProductName'] = product_name
            if vul_start:
                i['$MDOPSWATVulnerableRangeStart'] = vul_start
            if vul_end:
                i['$MDOPSWATVulnerableRangeLimit'] = vul_end
            if vendor_id:
                i['$MDOPSWATVendorID'] = vendor_id
            if vendor_name:
                i['$MDOPSWATVendorName'] = vendor_name
        except Exception:
            pass

        try:
            hash_sha1 = set()
            for hashes in data['sha1']:
                hash_sha1.add(hashes)
            i['$MDSHA1'] = list(hash_sha1)
        except Exception:
            pass

        try:
            hash_md5 = set()
            for hashes in data['md5']:
                hash_md5.add(hashes)
            i['$MDMD5'] = list(hash_md5)
        except Exception:
            pass

        try:
            hash_sha256 = set()
            for hashes in data['sha256']:
                hash_sha256.add(hashes)
            i['$MDSHA256'] = list(hash_sha256)
        except Exception:
            pass

        try:
            i['$MDSeverity'] = data['severity']
        except Exception:
            pass

        try:
            i['$MDSeverityIndex'] = data['severity_index']
        except Exception:
            pass

        try:
            i['$MDVulnerableSoftware'] = data['vulnerable_software_list']
        except Exception:
            pass

    return inward_array


def get_vulnerability(inward_array, var_array):
    # https://onlinehelp.opswat.com/mdcloud/Vulnerability_Data_Lookup.html
    for i in inward_array:

        if var_array[0] in i:
            headers = {
                'authorization': 'apikey ' + str(cfg['lookup_plugin']['MD_API_KEY']),
                "Accept-Encoding": "gzip, deflate",
                "User-Agent": "gzip,  My Python requests library example client or username"
            }

        url = 'https://api.metadefender.com/v3/vulnerability/'
        url += i[var_array[0]]

        try:
            response = requests.get(url, headers=headers)
        except Exception as e:
            return "Error in API" + str(e)

        json_response = response.json()

        try:
            i['$MDSuccess'] = json_response['success']
        except Exception:
            pass

        cve_list = []
        for dic in json_response['data']:
            cve_list.append(dic['cve'])
        if cve_list:
            i['$MDCVE'] = cve_list
    return inward_array


def get_ip_report(inward_array, var_array):
    # https://onlinehelp.opswat.com/mdcloud/3.1_IP_Reputatio.html
    for i in inward_array:

        if var_array[0] in i:
            headers = {
                'authorization': 'apikey ' + str(cfg['lookup_plugin']['MD_API_KEY']),
                "Accept-Encoding": "gzip, deflate",
                "User-Agent": "gzip,  My Python requests library example client or username"
            }

        url = 'https://api.metadefender.com/v3/ip/'
        url += i[var_array[0]]

        try:
            response = requests.get(url, headers=headers)
        except Exception as e:
            return "Error in API" + str(e)

        json_response = response.json()

        try:
            i['$MDSuccess'] = json_response['success']
        except Exception:
            pass

        try:
            i['$MDContinent'] = json_response['data']['geo_info']['continent']['names']['en']
        except Exception:
            pass

        try:
            i['$MDDetections'] = json_response['data']['detected_by']
        except Exception:
            pass

        try:
            i['$MDLocation'] = json_response['data']['location']
        except Exception:
            pass

        try:
            i['$MDCountry'] = json_response['data']['geo_info']['country']['names']['en']
            i['$MDRegisteredGeonameID'] = json_response['data']['geo_info']['registered_country']['geoname_id']
            i['$MDRegisteredISOCode'] = json_response['data']['geo_info']['registered_country']['iso_code']
        except Exception:
            pass

        try:
            positive_detection = []
            negative_detection = []
            for dic in json_response['data']['scan_results']:
                if dic['results'][0]['assessment'] != '':
                    positive_detection.append(dic['source'])
                    if dic['source'].split('.')[0] != 'www':
                        key = '$MD' + (dic['source'].split('.')[0])
                    else:
                        key = '$MD' + (dic['source'].split('.')[1])
                    value = dic['results'][0]['assessment']
                    i[key] = value
                    i[key + 'confidence'] = dic['results'][0]['confident']
                else:
                    negative_detection.append(dic['source'])
            if positive_detection:
                i['$MDPositiveDetection'] = positive_detection
            if negative_detection:
                i['$MDNegativeDetection'] = negative_detection
        except Exception:
            pass

    return inward_array


def get_hash_report(inward_array, var_array):
    # https://onlinehelp.opswat.com/mdcloud/2.1_Retrieving_scan_reports_using_a_data_hash.html
    for i in inward_array:

        if var_array[0] in i:
            headers = {
                'apikey': str(cfg['lookup_plugin']['MD_API_KEY']),
                "Accept-Encoding": "gzip, deflate",
                "User-Agent": "gzip,  My Python requests library example client or username"
            }

        url = 'https://api.metadefender.com/v2/hash/'
        url += i[var_array[0]]

        try:
            response = requests.get(url, headers=headers)
        except Exception as e:
            return "Error in API" + str(e)

        json_response = response.json()

        try:
            i['$MDFileID'] = json_response['file_id']
        except Exception:
            pass

        try:
            i['$MDFileName'] = json_response['file_info']['display_name']
            i['$MDFileType'] = json_response['file_info']['file_type_extension']
            i['$MDFileSize'] = json_response['file_info']['file_size']
            i['$MDFileCategory'] = json_response['file_info']['file_type_category']
            i['$MDDescription'] = json_response['file_info']['file_type_description']
            hashes = [('MD5:' + json_response['file_info']['md5']), ('SHA1:' + json_response['file_info']['sha1']),
                      ('SHA256:' + json_response['file_info']['sha256'])]
            i['$MDHashCodes'] = hashes
            i['$MDUploadTimestamp'] = json_response['file_info']['upload_timestamp']
        except Exception:
            pass

        try:
            i['$MDBlockReason'] = json_response['process_info']['blocked_reason']
            i['$MDProcessResult'] = json_response['process_info']['result']
        except Exception:
            pass

        try:
            safe_reports = []
            infected_reports = []
            suspicious_reports = []
            failed_scan_reports = []
            cleaned_reports = []
            unknown_reports = []
            skip_infected = []
            encrypted_results = []
            exceeded_size_results = []
            pass_protected_results = []
            potential_vul_results = []
            detections = set()
            for keys, values in json_response['scan_results']['scan_details'].items():
                if values['scan_result_i'] == 0:
                    safe_reports.append(keys)
                elif values['scan_result_i'] == 1:
                    infected_reports.append(keys)
                    detections.add(values['threat_found'])
                elif values['scan_result_i'] == 2:
                    suspicious_reports.append(keys)
                elif values['scan_result_i'] == 3:
                    failed_scan_reports.append(keys)
                elif values['scan_result_i'] == 4:
                    cleaned_reports.append(keys)
                elif values['scan_result_i'] == 5:
                    unknown_reports.append(keys)
                elif values['scan_result_i'] == 8:
                    skip_infected.append(keys)
                elif values['scan_result_i'] == 12:
                    encrypted_results.append(keys)
                elif values['scan_result_i'] == 13:
                    exceeded_size_results.append(keys)
                elif values['scan_result_i'] == 15:
                    pass_protected_results.append(keys)
                elif values['scan_result_i'] == 18:
                    potential_vul_results.append(keys)
            if safe_reports:
                i['$MDSafeDetection'] = safe_reports
            if infected_reports:
                i['$MDInfectedDetection'] = infected_reports
            if suspicious_reports:
                i['$MDSuspiciousDetection'] = suspicious_reports
            if failed_scan_reports:
                i['$MDFailedScan'] = failed_scan_reports
            if cleaned_reports:
                i['$MDCleanedFileDetection'] = cleaned_reports
            if unknown_reports:
                i['$MDUnknownFileDetection'] = unknown_reports
            if skip_infected:
                i['$MDSkippedInfectedDetection'] = skip_infected
            if encrypted_results:
                i['$MDEncryptedFileDetection'] = encrypted_results
            if exceeded_size_results:
                i['$MDExceededSize'] = exceeded_size_results
            if pass_protected_results:
                i['$MDPasswordProtectedDetection'] = pass_protected_results
            if potential_vul_results:
                i['$MDPotentialVulnerableDetection'] = potential_vul_results
            i['$MDDetectionTypes'] = list(detections)
            i['$MDFinalResult'] = json_response['scan_results']['scan_all_result_a']
            i['$MDFinalResultCode'] = json_response['scan_results']['scan_all_result_i']
        except Exception:
            pass

        try:
            i['$MDTotalAVs'] = json_response['scan_results']['total_avs']
            i['$MDTotalDetectedAVs'] = json_response['scan_results']['total_detected_avs']
        except Exception:
            pass

    return inward_array
