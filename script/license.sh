#!/usr/bin/env bash

YEAR=$(date +%Y)

LICENSE_HEADER="// Copyright $YEAR rogg Authors
//
// Licensed under the Apache License, Version 2.0 (the \"License\");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an \"AS IS\" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
"

find . -name "*.rs" -type f | while read file; do
    if ! grep -q "Apache License" "$file"; then
        echo "Adding license to: $file"
        echo "$LICENSE_HEADER" | cat - "$file" > "$file.tmp" && mv "$file.tmp" "$file"
    fi
done
