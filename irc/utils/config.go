// Copyright (c) 2022 Shivaram Lingamneni
// released under the MIT license

package utils

import (
	"sync/atomic"
	"unsafe"
)

/*
This can be used to implement the following pattern:

1. Prepare a config object (this can be arbitrarily expensive)
2. Take a pointer to the config object and use Set() to install it
3. Use Get() to access the config from any goroutine
4. To update the config, call Set() again with a new prepared config object
5. As long as any individual config object is not modified (by any goroutine)
   after it is installed with Set(), this is free of data races, and Get()
   is extremely cheap (on amd64 it compiles down to plain MOV instructions).
*/

type ConfigStore[Config any] struct {
	ptr unsafe.Pointer
}

func (c *ConfigStore[Config]) Get() *Config {
	return (*Config)(atomic.LoadPointer(&c.ptr))
}

func (c *ConfigStore[Config]) Set(ptr *Config) {
	atomic.StorePointer(&c.ptr, unsafe.Pointer(ptr))
}
