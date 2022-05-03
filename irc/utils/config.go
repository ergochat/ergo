// Copyright (c) 2022 Shivaram Lingamneni
// released under the MIT license

package utils

import (
	"sync/atomic"
	"unsafe"
)

/*
This can be used to implement the following pattern:

1. Load and munge a config (this can be arbitrarily expensive)
2. Use Set() to install the config
3. Use Get() to access the config
4. As long as any individual config is not modified (by any goroutine)
   after the initial call to Set(), this is free of data races, and Get()
   is extremely cheap (on amd64 it compiles down to plain MOV instructions).
*/

type ConfigStore[T any] struct {
	ptr unsafe.Pointer
}

func (c *ConfigStore[T]) Get() *T {
	return (*T)(atomic.LoadPointer(&c.ptr))
}

func (c *ConfigStore[T]) Set(ptr *T) {
	atomic.StorePointer(&c.ptr, unsafe.Pointer(ptr))
}
