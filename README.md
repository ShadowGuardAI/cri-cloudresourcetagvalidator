# CRI-CloudResourceTagValidator
Validates cloud resource tags against predefined policies (e.g., naming conventions, mandatory tags). Uses boto3 to scan resources and reports violations in a user-friendly format. - Focused on Inspects cloud resource configurations (AWS, Azure, GCP) for security misconfigurations and compliance violations. Detects insecure settings, open ports, overly permissive IAM roles, and other common cloud security risks. Generates reports highlighting deviations from security best practices. Leverages cloud provider SDKs to query resource configurations.

## Install
`git clone https://github.com/ShadowGuardAI/cri-cloudresourcetagvalidator`

## Usage
`./cri-cloudresourcetagvalidator [params]`

## Parameters
- `-h`: Show help message and exit

## License
Copyright (c) ShadowGuardAI
