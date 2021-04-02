# btree

[![GoDoc](https://godoc.org/github.com/tidwall/btree?status.svg)](https://godoc.org/github.com/tidwall/btree)

An [efficient](#performance) [B-tree](https://en.wikipedia.org/wiki/B-tree) implementation in Go. 

## Features

- `Copy()` method with copy-on-write support.
- Fast bulk loading for pre-ordered data using the `Load()` method.
- All operations are thread-safe.
- Path hinting optimization for operations with nearby keys.

## Installing

To start using btree, install Go and run `go get`:

```sh
$ go get -u github.com/tidwall/btree
```

## Usage

```go
package main

import (
	"fmt"

	"github.com/tidwall/btree"
)

type Item struct {
	Key, Val string
}

// byKeys is a comparison function that compares item keys and returns true
// when a is less than b.
func byKeys(a, b interface{}) bool {
	i1, i2 := a.(*Item), b.(*Item)
	return i1.Key < i2.Key
}

// byVals is a comparison function that compares item values and returns true
// when a is less than b.
func byVals(a, b interface{}) bool {
	i1, i2 := a.(*Item), b.(*Item)
	if i1.Val < i2.Val {
		return true
	}
	if i1.Val > i2.Val {
		return false
	}
	// Both vals are equal so we should fall though
	// and let the key comparison take over.
	return byKeys(a, b)
}

func main() {
	// Create a tree for keys and a tree for values.
	// The "keys" tree will be sorted on the Keys field.
	// The "values" tree will be sorted on the Values field.
	keys := btree.New(byKeys)
	vals := btree.New(byVals)

	// Create some items.
	users := []*Item{
		&Item{Key: "user:1", Val: "Jane"},
		&Item{Key: "user:2", Val: "Andy"},
		&Item{Key: "user:3", Val: "Steve"},
		&Item{Key: "user:4", Val: "Andrea"},
		&Item{Key: "user:5", Val: "Janet"},
		&Item{Key: "user:6", Val: "Andy"},
	}

	// Insert each user into both trees
	for _, user := range users {
		keys.Set(user)
		vals.Set(user)
	}

	// Iterate over each user in the key tree
	keys.Ascend(nil, func(item interface{}) bool {
		kvi := item.(*Item)
		fmt.Printf("%s %s\n", kvi.Key, kvi.Val)
		return true
	})

	fmt.Printf("\n")
	// Iterate over each user in the val tree
	vals.Ascend(nil, func(item interface{}) bool {
		kvi := item.(*Item)
		fmt.Printf("%s %s\n", kvi.Key, kvi.Val)
		return true
	})

	// Output:
	// user:1 Jane
	// user:2 Andy
	// user:3 Steve
	// user:4 Andrea
	// user:5 Janet
	// user:6 Andy
	//
	// user:4 Andrea
	// user:2 Andy
	// user:6 Andy
	// user:1 Jane
	// user:5 Janet
	// user:3 Steve
}
```

## Operations

### Basic

```
Len()                   # return the number of items in the btree
Set(item)               # insert or replace an existing item
Get(item)               # get an existing item
Delete(item)            # delete an item
```

### Iteration

```
Ascend(pivot, iter)     # scan items in ascending order starting at pivot.
Descend(pivot, iter)    # scan items in descending order starting at pivot.
```

### Queues

```
Min()                   # return the first item in the btree
Max()                   # return the last item in the btree
PopMin()                # remove and return the first item in the btree
PopMax()                # remove and return the last item in the btree
```
### Bulk loading

```
Load(item)              # load presorted items into tree
```

### Path hints

```
SetHint(item, *hint)    # insert or replace an existing item
GetHint(item, *hint)    # get an existing item
DeleteHint(item, *hint) # delete an item
```

## Performance

This implementation was designed with performance in mind. 

The following benchmarks were run on my 2019 Macbook Pro (2.4 GHz 8-Core Intel Core i9) using Go 1.15.3. The items are simple 8-byte ints. 

- `google`: The [google/btree](https://github.com/google/btree) package
- `tidwall`: The [tidwall/btree](https://github.com/tidwall/btree) package
- `go-arr`: Just a simple Go array

```
** sequential set **
google:  set-seq        1,000,000 ops in 160ms, 6,262,097/sec, 159 ns/op, 31.0 MB, 32 bytes/op
tidwall: set-seq        1,000,000 ops in 142ms, 7,020,721/sec, 142 ns/op, 36.6 MB, 38 bytes/op
tidwall: set-seq-hint   1,000,000 ops in 87ms, 11,503,315/sec, 86 ns/op, 36.6 MB, 38 bytes/op
tidwall: load-seq       1,000,000 ops in 37ms, 27,177,242/sec, 36 ns/op, 36.6 MB, 38 bytes/op
go-arr:  append         1,000,000 ops in 49ms, 20,574,760/sec, 48 ns/op

** random set **
google:  set-rand       1,000,000 ops in 606ms, 1,649,921/sec, 606 ns/op, 21.5 MB, 22 bytes/op
tidwall: set-rand       1,000,000 ops in 543ms, 1,841,590/sec, 543 ns/op, 26.7 MB, 27 bytes/op
tidwall: set-rand-hint  1,000,000 ops in 573ms, 1,745,624/sec, 572 ns/op, 26.4 MB, 27 bytes/op
tidwall: set-again      1,000,000 ops in 452ms, 2,212,581/sec, 451 ns/op, 27.1 MB, 28 bytes/op
tidwall: set-after-copy 1,000,000 ops in 472ms, 2,117,457/sec, 472 ns/op, 27.9 MB, 29 bytes/op
tidwall: load-rand      1,000,000 ops in 551ms, 1,816,498/sec, 550 ns/op, 26.1 MB, 27 bytes/op

** sequential get **
google:  get-seq        1,000,000 ops in 133ms, 7,497,604/sec, 133 ns/op
tidwall: get-seq        1,000,000 ops in 110ms, 9,082,972/sec, 110 ns/op
tidwall: get-seq-hint   1,000,000 ops in 55ms, 18,289,945/sec, 54 ns/op

** random get **
google:  get-rand       1,000,000 ops in 149ms, 6,704,337/sec, 149 ns/op
tidwall: get-rand       1,000,000 ops in 131ms, 7,616,296/sec, 131 ns/op
tidwall: get-rand-hint  1,000,000 ops in 216ms, 4,632,532/sec, 215 ns/op
```

*You can find the benchmark utility at [tidwall/btree-benchmark](https://github.com/tidwall/btree-benchmark)*

## Contact

Josh Baker [@tidwall](http://twitter.com/tidwall)

## License

Source code is available under the MIT [License](/LICENSE).
