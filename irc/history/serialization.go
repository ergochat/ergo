// Copyright (c) 2020 Shivaram Lingamneni
// released under the MIT license

package history

import (
	"encoding/json"
)

// 123 / '{' is the magic number that means JSON;
// if we want to do a binary encoding later, we just have to add different magic version numbers

func MarshalItem(item *Item) (result []byte, err error) {
	return json.Marshal(item)
}

func UnmarshalItem(data []byte, result *Item) (err error) {
	return json.Unmarshal(data, result)
}
