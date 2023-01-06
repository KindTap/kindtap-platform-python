## KindTap Platform Library for Python 3.9+

#### This library currently supports generating a signed authorization header which is required to make requests to KindTap Platform APIs.

### Installation

`pip install git+https://github.com/KindTap/kindtap-platform-python.git#0.0.1`

### Example using requests

#### Important Notes

* the `host` and `x-kt-date` headers are required
* request body must be a string that matches exactly the body of the HTTP request

```Python
import json
from datetime import datetime, timezone

import requests
from kindtap_platform_python.signature_v1 import (
    generate_signed_auth_header,
    stringify_date,
)


host = 'kindtap-platform-host'
path = '/path/to/api/endpoint/'
query = { 'key1': 'value1': 'key2': 1 }
date = datetime.now(tz=timezone.utc)

method = 'post'

body = json.dumps({
    'someKey': 'someValue',
})

headers = {
    'Content-Type': 'application/json',
    'Host': host,
    'X-KT-Date': stringify_date(date),
    # other headers as necessary
}

headers['Authorization'] = generate_signed_auth_header(
    'kindtap-platform-service-name',
    'kindtap-client-key',
    'kindtap-client-secret',
    method,
    path,
    date,
    headers,
    body,
    query,
)

response = getattr(requests, method)(f'https://{host}{path}', data=body, params=query, headers=headers)

response.raise_for_status()

print(response.json())
```

### Valid signature will allow request

### Invalid signature will block request

```Python
requests.exceptions.HTTPError: 401 Client Error: Unauthorized for url
```
