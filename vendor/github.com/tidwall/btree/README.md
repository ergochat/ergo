# btree

[![GoDoc](https://godoc.org/github.com/tidwall/btree?status.svg)](https://godoc.org/github.com/tidwall/btree)

An [efficient](#performance) [B-tree](https://en.wikipedia.org/wiki/B-tree) implementation in Go. 

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

- `tidwall`: The [tidwall/btree](https://github.com/tidwall/btree) package
- `google`: The [google/btree](https://github.com/google/btree) package
- `go-arr`: Just a simple Go array

```
** sequential set **
tidwall: set-seq       1,000,000 ops in 143ms, 6,996,275/sec, 142 ns/op, 30.9 MB, 32 bytes/op
tidwall: set-seq-hint  1,000,000 ops in 65ms, 15,441,082/sec, 64 ns/op, 30.9 MB, 32 bytes/op
tidwall: load-seq      1,000,000 ops in 19ms, 53,242,398/sec, 18 ns/op, 30.9 MB, 32 bytes/op
google:  set-seq       1,000,000 ops in 175ms, 5,700,922/sec, 175 ns/op, 33.1 MB, 34 bytes/op
go-arr:  append        1,000,000 ops in 52ms, 19,153,714/sec, 52 ns/op, 41.3 MB, 43 bytes/op

** random set **
tidwall: set-rand      1,000,000 ops in 589ms, 1,697,471/sec, 589 ns/op, 22.5 MB, 23 bytes/op
tidwall: set-rand-hint 1,000,000 ops in 592ms, 1,688,184/sec, 592 ns/op, 22.2 MB, 23 bytes/op
tidwall: load-rand     1,000,000 ops in 578ms, 1,728,932/sec, 578 ns/op, 22.3 MB, 23 bytes/op
google:  set-rand      1,000,000 ops in 662ms, 1,509,924/sec, 662 ns/op, 32.1 MB, 33 bytes/op

** sequential get **
tidwall: get-seq       1,000,000 ops in 111ms, 8,995,090/sec, 111 ns/op
tidwall: get-seq-hint  1,000,000 ops in 56ms, 18,017,397/sec, 55 ns/op
google:  get-seq       1,000,000 ops in 135ms, 7,414,046/sec, 134 ns/op

** random get **
tidwall: get-rand      1,000,000 ops in 139ms, 7,214,017/sec, 138 ns/op
tidwall: get-rand-hint 1,000,000 ops in 191ms, 5,243,833/sec, 190 ns/op
google:  get-rand      1,000,000 ops in 161ms, 6,199,818/sec, 161 ns/op
```

*You can find the benchmark utility at [tidwall/btree-benchmark](https://github.com/tidwall/btree-benchmark)*

## Contact

Josh Baker [@tidwall](http://twitter.com/tidwall)

## License

Source code is available under the MIT [License](/LICENSE).
