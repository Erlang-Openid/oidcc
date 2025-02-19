<!--
SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
SPDX-License-Identifier: Apache-2.0
-->

# Regenerating `jwk_cert.pem`

``` bash
openssl x509 -signkey jwk.pem -in jwk.csr -req -days 3650 -out jwk_cert.pem
```

