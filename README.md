## MetaDefender

https://metadefender.opswat.com/#!/

### Overview
OPSWAT's Threat Intelligence Feeds provide a host of the most prevailing and widespread threats. OPSWAT offers the ability to leverage data collected from the MetaDefender Cloud community of users and customers. The goal is to make organizations more secure, and to give developers, IT administrators, and users alike the information and tools to make that possible.

Organizations can easily integrate MetaDefender threat intelligence data into their site, product, or solution. Feeds are updated daily with newly detected threats to provide actionable and timely threat intelligence to users.

The Commercial version of MetaDefender threat intelligence feeds provides Access to hundreds of thousands of unique threats every day. The commercial version can be easily integrated into your existing DNIF Platform. 

#### Lookups integrated with MetaDefender

##### Retrieve File Scan reports by MD5/SHA1/SHA256 Hash

Report on scan results of MD5/SHA-1/SHA-256 hash provided
- input : a md5/sha1/sha256 hash will retrieve the most recent report on a given sample

The Lookup call returns output in the following structure for available data

|   Field                         |                                                                    Description                                                                                                                            |
|---------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| $MDFileID                       | Unique identifier of the file in MetaDefender's system                                                                                                                                                    |
| $MDFileName                     | Name of the file associated with the hash                                                                                                                                                                 |
| $MDFileType                     | Extension of the file                                                                                                                                                                                     |
| $MDFileSize                     | Size of the file                                                                                                                                                                                          |
| $MDFileCategory                 | Category for file type.<br>Possible values:<br>E - executables<br>D - documents<br>A - archives<br>G - graphical format<br>T - text<br>P - pdf format<br>M - audio or video format<br>N - Android apk file |
| $MDDescription                  | Description of the file scanned                                                                                                                                                                           |
| $MDHashCodes                    | Provides the MD5, SHA1 and SHA256 hash codes of the file                                                                                                                                                  |
| $MDUploadTimestamp              | The time the file was first uploaded.                                                                                                                                                                     |
| $MDBlockReason                  | The particular reason for blocking the file                                                                                                                                                               |
| $MDProcessResult                | The final result of the scan carried out                                                                                                                                                                  |
| $MDSafeDetection                | Anti-virus providers which reported that no threat was detected or the file is empty.                                                                                                                     |
| $MDInfectedDetection            | Anti-virus providers which reported that a threat is found.                                                                                                                                               |
| $MDSuspiciousDetection          | Anti-virus providers which reported that the file is classified as a possible threat but not identified as specific threat.                                                                               |
| $MDFailedScan                   | Anti-virus providers which reported that scanning is not fully performed (for example, invalid file or no read permission).                                                                               |
| $MDCleanedFileDetection         | Anti-virus providers which reported that threat is found and file is cleaned.                                                                                                                             |
| $MDUnknownFileDetection         | Anti-virus providers which reported Unknown Signature.                                                                                                                                                    |
| $MDSkippedInfectedDetection     | Anti-virus providers which reported that scan is skipped because this file type is in black-list.                                                                                                         |
| $MDEncryptedFileDetection       | Anti-virus providers which reported that file/buffer is not scanned because the file type is detected as encrypted (password-protected)                                                                   |
| $MDExceededSize                 | Anti-virus providers which reported that the extracted archive is too large to scan.                                                                                                                      |
| $MDPasswordProtectedDetection   | Anti-virus providers which reported that document is protected by a password                                                                                                                              |
| $MDPotentialVulnerableDetection | Anti-virus providers which reported that possible vulnerability detected for applied file.                                                                                                                |
| $MDDetectionTypes               | The detected types of malware                                                                                                                                                                             |
| $MDFinalResult                  | A text description of the scan results                                                                                                                                                                    |
| $MDFinalResultCode              | The final code returned by the scan.                                                                                                                                                                      |
| $MDTotalAVs                     | Total number of Anti-Virus scanners used for the scanning of the file                                                                                                                                     |
| $MDTotalDetectedAVs             | Total number of Anti-Virus scanners which detected a threat                                                                                                                                               |

##### Retrive IP Reputation reports by IP Address

Report on the reputation of the IP Adress 
- input : an IPv4/IPv6 address

The Lookup call returns output in the following structure for available data

| Field                           | Description                                                                  |
|---------------------------------|------------------------------------------------------------------------------|
| $MDSuccess                      | Boolean value representing whether request was successfully resolved or not. |
| $MDContinent                    | The name of the continent (en) where the IP address originates               |
| $MDDetections                   | Number of blacklisted sources.                                               |
| $MDLocation                     | The latitude, longitude and timezone information of the IP address           |
| $MDCountry                      | The country name (en) from where the IP address originates                   |
| $MDRegisteredGeonameID          | The geoname ID of the of the registered country                              |
| $MDRegisteredISOCode            | The ISO code of the registered country                                       |
| $MDPositiveDetection            | List of providers who have flagged the IP address                            |
| $MDNegativeDetection            | List of providers who have marked the IP address as safe                     |

The report also includes variable fields depending on the positive detections. For example, a report contining zeusnet detections would have the following fields

| Field                           | Description                                                           |
|---------------------------------|-----------------------------------------------------------------------|
| $MDzeustracker                  | The detected threats responsible for flagging of the IP address       |
| $MDzeustrackerconfidence        | The confidence level rating of the provider (varies between 0 to 100) |

##### Retrieve Vulnerabilities by Hashcode of an Application

Report on the CVEs present for an application
- input : SHA1 hash of the application

The Lookup call returns output in the following structure for available data

| Field                           | Description                                                                  |
|---------------------------------|------------------------------------------------------------------------------|
| $MDSuccess                      | Boolean value representing whether request was successfully resolved or not. |
| $MDCVE                          | List of all the CVEs present for the application                             |

##### Retrieve CVE information

Report on the particulars of the provided CVE
- input : CVE identifier

The Lookup call returns output in the following structure for available data

| Field                           | Description                                                                                                                 |
|---------------------------------|-----------------------------------------------------------------------------------------------------------------------------|
| $MDSuccess                      | Boolean value representing wheter request was succesfully resolved or not.                                                  |
| $MDCVE                          | CVE vulnerability identifier                                                                                                |
| $MDCWE                          | CWE identifier number/name of the weakness type                                                                             |
| $MDCVSS2accesscomplexity        | Describes how easy or difficult it is to exploit the discovered vulnerability                                               |
| $MDCVSS2accessvector            | Shows how a vulnerability may be exploited                                                                                  |
| $MDCVSS2authentication          | Describes the number of times that an attacker must authenticate to a target to exploit it                                  |
| $MDCVSS2availabilityimpact      | Describes the impact on the availability of the targeted system                                                             |
| $MDCVSS2confidentialityimpact   | Describes the impact on the confidentiality of data processed by the system                                                 |
| $MDCVSS2exploitabilityscore     | Describes a score assigned on the basis of the exploitability                                                               |
| $MDCVSS2impactscore             | Describes a score assigned on the basis of the impact                                                                       |
| $MDCVSS2integrityimpact         | Describes the impact on the integrity of the exploited system                                                               |
| $MDCVSS2score                   | Numerical score                                                                                                             |
| $MDCVSS2source                  | The source of the known vulnerability                                                                                       |
| $MDCVSS3OPSWATexploitability    | OPSWAT assigned exploitability level                                                                                        |
| $MDCVSS3OPSWATremediationlevel  | OPSWAT assigned remediation level                                                                                           |
| $MDCVSS3OPSWATreportconfidence  | OPSWAT assigned confidence level                                                                                            |
| $MDCVSS3OPSWATtemporalscore     | OPSWAT assigned temporal score                                                                                              |
| $MDCVSS3attackcomplexity        | Level of complexity of the attack                                                                                           |
| $MDCVSS3attackvector            | Attack vector of the vulnerability                                                                                          |
| $MDCVSS3availabilityimpact      | Describe impact on availability of resources                                                                                |
| $MDCVSS3basescore               | Describe a numerical score based on the remoteness of the attacker to the vulnerable component                              |
| $MDCVSS3baseseverity            | Describes the severity level                                                                                                |
| $MDCVSS3confidentialityimpact   | Describes the impact on the confidentiality of data processed by the system                                                 |
| $MDCVSS3exploitabilityscore     | Describes a score assigned on the basis of the exploitability                                                               |
| $MDCVSS3impactscore             | Describes a score assigned on the basis of the impact                                                                       |
| $MDCVSS3integrityimpact         | Describes the impact on the integrity of the exploited system                                                               |
| $MDCVSS3privilegesrequired      | Describes the the level of access required for a successful attack                                                          |
| $MDCVSS3scope                   | The collection of privileges defined and managed by an authorization authority when granting access to computing resources. |
| $MDCVSS3userinteraction         | Describes the access required by the attacker with another user                                                             |
| $MDCVSS3vectorstring            | Specifically formatted text string that contains each value assigned to each metric                                         |
| $MDDescription                  | Provides a description of the vulnerability                                                                                 |
| $MDHashesCount                  | The total nuber of hashes in the database                                                                                   |
| $MDMD5                          | Array of MD5 hashes associated with the CVE. (Limit of 100 with the free API key)                                           |
| $MDOPSWATProductID              | OPSWAT product ID                                                                                                           |
| $MDOPSWATProductName            | OPSWAT product name                                                                                                         |
| $MDOPSWATVendorID               | OPSWAT vendor ID                                                                                                            |
| $MDOPSWATVendorName             | OPSWAT vendor name                                                                                                          |
| $MDOPSWATVulnerableRangeLimit   | The last version in the affected versions range                                                                             |
| $MDOPSWATVulnerableRangeStart   | The first version in the affected versions range                                                                            |
| $MDProductResolutionID          | The ID in the database of the software containing the resolution                                                            |
| $MDProductResolutionName        | Name of the resolved product                                                                                                |
| $MDProductResolutionVersion     | The version at which the vulnerability was resolved                                                                         |
| $MDReferences                   | Array of CVE references                                                                                                     |
| $MDSHA1                         | Array of SHA1 hashes associated with the CVE. (Limit of 100 with the free API key)                                          |
| $MDSHA256                       | Array of SHA256 hashes associated with the CVE. (Limit of 100 with the free API key)                                        |
| $MDSeverity                     | Level of importance of this known vulnerability (text)                                                                      |
| $MDSeverityIndex                | Level of importance of this known vulnerability (index)                                                                     |
| $MDVulnerableSoftware           | Array of all the vulnerable softwares                                                                                       |

##### Retrieve CVE hashes

Report the hashes associated with the CVE
- input : CVE identifier

The Lookup call returns output in the following structure for available data

| Field                           | Description                                                                                                                 |
|---------------------------------|-----------------------------------------------------------------------------------------------------------------------------|
| $MDSuccess                      | Boolean value representing wheter request was succesfully resolved or not.                                                  |
| $MDCVE                          | CVE vulnerability identifier                                                                                                |
| $MDCWE                          | CWE identifier number/name of the weakness type                                                                             |
| $MDCVSS2accesscomplexity        | Describes how easy or difficult it is to exploit the discovered vulnerability                                               |
| $MDCVSS2accessvector            | Shows how a vulnerability may be exploited                                                                                  |
| $MDCVSS2authentication          | Describes the number of times that an attacker must authenticate to a target to exploit it                                  |
| $MDCVSS2availabilityimpact      | Describes the impact on the availability of the targeted system                                                             |
| $MDCVSS2confidentialityimpact   | Describes the impact on the confidentiality of data processed by the system                                                 |
| $MDCVSS2exploitabilityscore     | Describes a score assigned on the basis of the exploitability                                                               |
| $MDCVSS2impactscore             | Describes a score assigned on the basis of the impact                                                                       |
| $MDCVSS2integrityimpact         | Describes the impact on the integrity of the exploited system                                                               |
| $MDCVSS2score                   | Numerical score                                                                                                             |
| $MDCVSS2source                  | The source of the known vulnerability                                                                                       |
| $MDCVSS3OPSWATexploitability    | OPSWAT assigned exploitability level                                                                                        |
| $MDCVSS3OPSWATremediationlevel  | OPSWAT assigned remediation level                                                                                           |
| $MDCVSS3OPSWATreportconfidence  | OPSWAT assigned confidence level                                                                                            |
| $MDCVSS3OPSWATtemporalscore     | OPSWAT assigned temporal score                                                                                              |
| $MDCVSS3attackcomplexity        | Level of complexity of the attack                                                                                           |
| $MDCVSS3attackvector            | Attack vector of the vulnerability                                                                                          |
| $MDCVSS3availabilityimpact      | Describe impact on availability of resources                                                                                |
| $MDCVSS3basescore               | Describe a numerical score based on the remoteness of the attacker to the vulnerable component                              |
| $MDCVSS3baseseverity            | Describes the severity level                                                                                                |
| $MDCVSS3confidentialityimpact   | Describes the impact on the confidentiality of data processed by the system                                                 |
| $MDCVSS3exploitabilityscore     | Describes a score assigned on the basis of the exploitability                                                               |
| $MDCVSS3impactscore             | Describes a score assigned on the basis of the impact                                                                       |
| $MDCVSS3integrityimpact         | Describes the impact on the integrity of the exploited system                                                               |
| $MDCVSS3privilegesrequired      | Describes the the level of access required for a successful attack                                                          |
| $MDCVSS3scope                   | The collection of privileges defined and managed by an authorization authority when granting access to computing resources. |
| $MDCVSS3userinteraction         | Describes the access required by the attacker with another user                                                             |
| $MDCVSS3vectorstring            | Specifically formatted text string that contains each value assigned to each metric                                         |
| $MDDescription                  | Provides a description of the vulnerability                                                                                 |
| $MDHashesCount                  | The total nuber of hashes in the database                                                                                   |
| $MDMD5                          | Array of MD5 hashes associated with the CVE. (Limit of 100 with the free API key)                                           |
| $MDProductResolutionID          | The ID in the database of the software containing the resolution                                                            |
| $MDProductResolutionName        | Name of the resolved product                                                                                                |
| $MDProductResolutionVersion     | The version at which the vulnerability was resolved                                                                         |
| $MDReferences                   | Array of CVE references                                                                                                     |
| $MDSHA1                         | Array of SHA1 hashes associated with the CVE. (Limit of 100 with the free API key)                                          |
| $MDSHA256                       | Array of SHA256 hashes associated with the CVE. (Limit of 100 with the free API key)                                        |
| $MDSeverity                     | Level of importance of this known vulnerability (text)                                                                      |
| $MDSeverityIndex                | Level of importance of this known vulnerability (index)                                                                     |
| $MDVulnerableSoftware           | Array of all the vulnerable softwares                                                                                       |

##### Retrieve CVE Vendor details

Report on the vendor details of the softwares affected by the CVE
- input : CVE identifier

The Lookup call returns output in the following structure for available data

| Field                           | Description                                                                                                                 |
|---------------------------------|-----------------------------------------------------------------------------------------------------------------------------|
| $MDSuccess                      | Boolean value representing wheter request was succesfully resolved or not.                                                  |
| $MDCVE                          | CVE vulnerability identifier                                                                                                |
| $MDCWE                          | CWE identifier number/name of the weakness type                                                                             |
| $MDCVSS2accesscomplexity        | Describes how easy or difficult it is to exploit the discovered vulnerability                                               |
| $MDCVSS2accessvector            | Shows how a vulnerability may be exploited                                                                                  |
| $MDCVSS2authentication          | Describes the number of times that an attacker must authenticate to a target to exploit it                                  |
| $MDCVSS2availabilityimpact      | Describes the impact on the availability of the targeted system                                                             |
| $MDCVSS2confidentialityimpact   | Describes the impact on the confidentiality of data processed by the system                                                 |
| $MDCVSS2exploitabilityscore     | Describes a score assigned on the basis of the exploitability                                                               |
| $MDCVSS2impactscore             | Describes a score assigned on the basis of the impact                                                                       |
| $MDCVSS2integrityimpact         | Describes the impact on the integrity of the exploited system                                                               |
| $MDCVSS2score                   | Numerical score                                                                                                             |
| $MDCVSS2source                  | The source of the known vulnerability                                                                                       |
| $MDCVSS3OPSWATexploitability    | OPSWAT assigned exploitability level                                                                                        |
| $MDCVSS3OPSWATremediationlevel  | OPSWAT assigned remediation level                                                                                           |
| $MDCVSS3OPSWATreportconfidence  | OPSWAT assigned confidence level                                                                                            |
| $MDCVSS3OPSWATtemporalscore     | OPSWAT assigned temporal score                                                                                              |
| $MDCVSS3attackcomplexity        | Level of complexity of the attack                                                                                           |
| $MDCVSS3attackvector            | Attack vector of the vulnerability                                                                                          |
| $MDCVSS3availabilityimpact      | Describe impact on availability of resources                                                                                |
| $MDCVSS3basescore               | Describe a numerical score based on the remoteness of the attacker to the vulnerable component                              |
| $MDCVSS3baseseverity            | Describes the severity level                                                                                                |
| $MDCVSS3confidentialityimpact   | Describes the impact on the confidentiality of data processed by the system                                                 |
| $MDCVSS3exploitabilityscore     | Describes a score assigned on the basis of the exploitability                                                               |
| $MDCVSS3impactscore             | Describes a score assigned on the basis of the impact                                                                       |
| $MDCVSS3integrityimpact         | Describes the impact on the integrity of the exploited system                                                               |
| $MDCVSS3privilegesrequired      | Describes the the level of access required for a successful attack                                                          |
| $MDCVSS3scope                   | The collection of privileges defined and managed by an authorization authority when granting access to computing resources. |
| $MDCVSS3userinteraction         | Describes the access required by the attacker with another user                                                             |
| $MDCVSS3vectorstring            | Specifically formatted text string that contains each value assigned to each metric                                         |
| $MDDescription                  | Provides a description of the vulnerability                                                                                 |
| $MDOPSWATProductID              | OPSWAT product ID                                                                                                           |
| $MDOPSWATProductName            | OPSWAT product name                                                                                                         |
| $MDOPSWATVendorID               | OPSWAT vendor ID                                                                                                            |
| $MDOPSWATVendorName             | OPSWAT vendor name                                                                                                          |
| $MDOPSWATVulnerableRangeLimit   | The last version in the affected versions range                                                                             |
| $MDOPSWATVulnerableRangeStart   | The first version in the affected versions range                                                                            |
| $MDProductResolutionID          | The ID in the database of the software containing the resolution                                                            |
| $MDProductResolutionName        | Name of the resolved product                                                                                                |
| $MDProductResolutionVersion     | The version at which the vulnerability was resolved                                                                         |
| $MDReferences                   | Array of CVE references                                                                                                     |
| $MDSeverity                     | Level of importance of this known vulnerability (text)                                                                      |
| $MDSeverityIndex                | Level of importance of this known vulnerability (index)                                                                     |
| $MDVulnerableSoftware           | Array of all the vulnerable softwares                                                                                       |

##### Retrieve CVE Product details

Report on the products affected by the CVE
- input : CVE identifier

The Lookup call returns output in the following structure for available data

| Field                           | Description                                                                                                                 |
|---------------------------------|-----------------------------------------------------------------------------------------------------------------------------|
| $MDSuccess                      | Boolean value representing wheter request was succesfully resolved or not.                                                  |
| $MDCVE                          | CVE vulnerability identifier                                                                                                |
| $MDCWE                          | CWE identifier number/name of the weakness type                                                                             |
| $MDCVSS2accesscomplexity        | Describes how easy or difficult it is to exploit the discovered vulnerability                                               |
| $MDCVSS2accessvector            | Shows how a vulnerability may be exploited                                                                                  |
| $MDCVSS2authentication          | Describes the number of times that an attacker must authenticate to a target to exploit it                                  |
| $MDCVSS2availabilityimpact      | Describes the impact on the availability of the targeted system                                                             |
| $MDCVSS2confidentialityimpact   | Describes the impact on the confidentiality of data processed by the system                                                 |
| $MDCVSS2exploitabilityscore     | Describes a score assigned on the basis of the exploitability                                                               |
| $MDCVSS2impactscore             | Describes a score assigned on the basis of the impact                                                                       |
| $MDCVSS2integrityimpact         | Describes the impact on the integrity of the exploited system                                                               |
| $MDCVSS2score                   | Numerical score                                                                                                             |
| $MDCVSS2source                  | The source of the known vulnerability                                                                                       |
| $MDCVSS3OPSWATexploitability    | OPSWAT assigned exploitability level                                                                                        |
| $MDCVSS3OPSWATremediationlevel  | OPSWAT assigned remediation level                                                                                           |
| $MDCVSS3OPSWATreportconfidence  | OPSWAT assigned confidence level                                                                                            |
| $MDCVSS3OPSWATtemporalscore     | OPSWAT assigned temporal score                                                                                              |
| $MDCVSS3attackcomplexity        | Level of complexity of the attack                                                                                           |
| $MDCVSS3attackvector            | Attack vector of the vulnerability                                                                                          |
| $MDCVSS3availabilityimpact      | Describe impact on availability of resources                                                                                |
| $MDCVSS3basescore               | Describe a numerical score based on the remoteness of the attacker to the vulnerable component                              |
| $MDCVSS3baseseverity            | Describes the severity level                                                                                                |
| $MDCVSS3confidentialityimpact   | Describes the impact on the confidentiality of data processed by the system                                                 |
| $MDCVSS3exploitabilityscore     | Describes a score assigned on the basis of the exploitability                                                               |
| $MDCVSS3impactscore             | Describes a score assigned on the basis of the impact                                                                       |
| $MDCVSS3integrityimpact         | Describes the impact on the integrity of the exploited system                                                               |
| $MDCVSS3privilegesrequired      | Describes the the level of access required for a successful attack                                                          |
| $MDCVSS3scope                   | The collection of privileges defined and managed by an authorization authority when granting access to computing resources. |
| $MDCVSS3userinteraction         | Describes the access required by the attacker with another user                                                             |
| $MDCVSS3vectorstring            | Specifically formatted text string that contains each value assigned to each metric                                         |
| $MDDescription                  | Provides a description of the vulnerability                                                                                 |
| $MDOPSWATProductID              | OPSWAT product ID                                                                                                           |
| $MDOPSWATProductName            | OPSWAT product name                                                                                                         |
| $MDOPSWATVendorID               | OPSWAT vendor ID                                                                                                            |
| $MDOPSWATVendorName             | OPSWAT vendor name                                                                                                          |
| $MDOPSWATVulnerableRangeLimit   | The last version in the affected versions range                                                                             |
| $MDOPSWATVulnerableRangeStart   | The first version in the affected versions range                                                                            |
| $MDProductResolutionID          | The ID in the database of the software containing the resolution                                                            |
| $MDProductResolutionName        | Name of the resolved product                                                                                                |
| $MDProductResolutionVersion     | The version at which the vulnerability was resolved                                                                         |
| $MDReferences                   | Array of CVE references                                                                                                     |
| $MDSeverity                     | Level of importance of this known vulnerability (text)                                                                      |
| $MDSeverityIndex                | Level of importance of this known vulnerability (index)                                                                     |
| $MDVulnerableSoftware           | Array of all the vulnerable softwares                                                                                       |

### Using the MetaDefender API and DNIF  
The MetaDefender API is found on github at 

  https://github.com/dnif/lookup-metadefender

#### Getting started with MetaDefender API and DNIF

1. #####    Login to your Data Store, Correlator, and A10 containers.  
   [ACCESS DNIF CONTAINER VIA SSH](https://dnif.it/docs/guides/tutorials/access-dnif-container-via-ssh.html)
2. #####    Move to the ‘/dnif/<Deployment-key>/lookup_plugins’ folder path.
```
$cd /dnif/CnxxxxxxxxxxxxV8/lookup_plugins/
```
3. #####   Clone using the following command  
```  
git clone https://github.com/dnif/lookup-metadefender.git metadefender
```
4. #####   Move to the ‘/dnif/<Deployment-key>/lookup_plugins/metadefender/’ folder path and open dnifconfig.yml configuration file     
    
   Replace the tag: <Add_your_api_key_here> with your MetaDefender api key
```
lookup_plugin:
  MD_API_KEY: <Add_your_api_key_here>

```