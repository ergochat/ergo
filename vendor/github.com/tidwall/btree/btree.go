// Copyright 2020 Joshua J Baker. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package btree

import (
	"sync"
)

const maxItems = 255 // max items per node. max children is +1
const minItems = maxItems * 40 / 100

type cow struct {
	_ int // it cannot be an empty struct
}

type node struct {
	cow      *cow
	leaf     bool
	numItems int16
	count    int
	items    [maxItems]interface{}
	children *[maxItems + 1]*node
}

// BTree is an ordered set items
type BTree struct {
	mu    *sync.RWMutex
	cow   *cow
	root  *node
	count int
	less  func(a, b interface{}) bool
	locks bool
}

func (tr *BTree) newNode(leaf bool) *node {
	n := &node{leaf: leaf}
	if !leaf {
		n.children = new([maxItems + 1]*node)
	}
	n.cow = tr.cow
	return n
}

// PathHint is a utility type used with the *Hint() functions. Hints provide
// faster operations for clustered keys.
type PathHint struct {
	used [8]bool
	path [8]uint8
}

// New returns a new BTree
func New(less func(a, b interface{}) bool) *BTree {
	return newBTree(less, true)
}

// NewNonConcurrent returns a new BTree which is not safe for concurrent
// write operations by multiple goroutines.
//
// This is useful for when you do not need the BTree to manage the locking,
// but would rather do it yourself.
func NewNonConcurrent(less func(a, b interface{}) bool) *BTree {
	return newBTree(less, false)
}

func newBTree(less func(a, b interface{}) bool, locks bool) *BTree {
	if less == nil {
		panic("nil less")
	}
	tr := new(BTree)
	tr.mu = new(sync.RWMutex)
	tr.less = less
	tr.locks = locks
	return tr
}

// Less is a convenience function that performs a comparison of two items
// using the same "less" function provided to New.
func (tr *BTree) Less(a, b interface{}) bool {
	return tr.less(a, b)
}

func (n *node) find(key interface{}, less func(a, b interface{}) bool,
	hint *PathHint, depth int,
) (index int16, found bool) {
	low := int16(0)
	high := n.numItems - 1
	if hint != nil && depth < 8 && hint.used[depth] {
		index = int16(hint.path[depth])
		if index >= n.numItems {
			// tail item
			if less(n.items[n.numItems-1], key) {
				if less(key, n.items[n.numItems-1]) {
					index = n.numItems - 1
					found = true
					goto path_match
				} else {
					index = n.numItems
					goto path_match
				}
			}
			index = n.numItems - 1
		}
		if less(key, n.items[index]) {
			if index == 0 || less(n.items[index-1], key) {
				goto path_match
			}
			high = index - 1
		} else if less(n.items[index], key) {
			low = index + 1
		} else {
			found = true
			goto path_match
		}
	}
	for low <= high {
		mid := low + ((high+1)-low)/2
		if !less(key, n.items[mid]) {
			low = mid + 1
		} else {
			high = mid - 1
		}
	}
	if low > 0 && !less(n.items[low-1], key) {
		index = low - 1
		found = true
	} else {
		index = low
		found = false
	}
	if hint == nil || depth >= 8 {
		return index, found
	}

path_match:
	hint.used[depth] = true
	if n.leaf && found {
		hint.path[depth] = byte(index + 1)
	} else {
		hint.path[depth] = byte(index)
	}
	return index, found
}

// SetHint sets or replace a value for a key using a path hint
func (tr *BTree) SetHint(item interface{}, hint *PathHint) (prev interface{}) {
	if item == nil {
		panic("nil item")
	}
	if tr.lock() {
		defer tr.unlock()
	}
	return tr.setHint(item, hint)
}

func (tr *BTree) setHint(item interface{}, hint *PathHint) (prev interface{}) {
	if tr.root == nil {
		tr.root = tr.newNode(true)
		tr.root.items[0] = item
		tr.root.numItems = 1
		tr.root.count = 1
		tr.count = 1
		return
	}
	prev = tr.nodeSet(&tr.root, item, tr.less, hint, 0)
	if prev != nil {
		return prev
	}
	if tr.root.numItems == maxItems {
		n := tr.cowLoad(&tr.root)
		right, median := tr.nodeSplit(n)
		tr.root = tr.newNode(false)
		tr.root.children[0] = n
		tr.root.items[0] = median
		tr.root.children[1] = right
		tr.root.numItems = 1
		tr.root.count = n.count + 1 + right.count
	}
	tr.count++
	return prev
}

// Set or replace a value for a key
func (tr *BTree) Set(item interface{}) (prev interface{}) {
	return tr.SetHint(item, nil)
}

func (tr *BTree) nodeSplit(n *node) (right *node, median interface{}) {
	right = tr.newNode(n.leaf)
	median = n.items[maxItems/2]
	copy(right.items[:maxItems/2], n.items[maxItems/2+1:])
	if !n.leaf {
		copy(right.children[:maxItems/2+1], n.children[maxItems/2+1:])
	}
	right.numItems = maxItems / 2
	if !n.leaf {
		for i := maxItems/2 + 1; i < maxItems+1; i++ {
			n.children[i] = nil
		}
	}
	for i := maxItems / 2; i < maxItems; i++ {
		n.items[i] = nil
	}
	n.numItems = maxItems / 2
	// update counts
	n.updateCount()
	right.updateCount()
	return right, median
}

func (n *node) updateCount() {
	n.count = int(n.numItems)
	if !n.leaf {
		for i := 0; i <= int(n.numItems); i++ {
			n.count += n.children[i].count
		}
	}
}

// This operation should not be inlined because it's expensive and rarely
// called outside of heavy copy-on-write situations. Marking it "noinline"
// allows for the parent cowLoad to be inlined.
// go:noinline
func (tr *BTree) copy(n *node) *node {
	n2 := *n
	n2.cow = tr.cow
	copy(n2.items[:], n.items[:])
	if n.children != nil {
		n2.children = new([maxItems + 1]*node)
		copy(n2.children[:], n.children[:])
	}
	return &n2
}

// cowLoad loads the provide node and, if needed, performs a copy-on-write.
func (tr *BTree) cowLoad(cn **node) *node {
	if (*cn).cow != tr.cow {
		*cn = tr.copy(*cn)
	}
	return *cn
}

func (tr *BTree) nodeSet(cn **node, item interface{},
	less func(a, b interface{}) bool, hint *PathHint, depth int,
) (prev interface{}) {
	n := tr.cowLoad(cn)
	i, found := n.find(item, less, hint, depth)
	if found {
		prev = n.items[i]
		n.items[i] = item
		return prev
	}
	if n.leaf {
		copy(n.items[i+1:n.numItems+1], n.items[i:n.numItems])
		n.items[i] = item
		n.numItems++
		n.count++
		return nil
	}
	prev = tr.nodeSet(&n.children[i], item, less, hint, depth+1)
	if prev != nil {
		return prev
	}
	if n.children[i].numItems == maxItems {
		right, median := tr.nodeSplit(n.children[i])
		copy(n.children[i+1:], n.children[i:])
		copy(n.items[i+1:], n.items[i:])
		n.items[i] = median
		n.children[i+1] = right
		n.numItems++
	}
	n.count++
	return nil
}

func (n *node) scan(iter func(item interface{}) bool) bool {
	if n.leaf {
		for i := int16(0); i < n.numItems; i++ {
			if !iter(n.items[i]) {
				return false
			}
		}
		return true
	}
	for i := int16(0); i < n.numItems; i++ {
		if !n.children[i].scan(iter) {
			return false
		}
		if !iter(n.items[i]) {
			return false
		}
	}
	return n.children[n.numItems].scan(iter)
}

// Get a value for key
func (tr *BTree) Get(key interface{}) interface{} {
	// This operation is basically the same as calling:
	//     return tr.GetHint(key, nil)
	// But here we inline the bsearch to avoid the hint logic and extra
	// function call.
	if tr.rlock() {
		defer tr.runlock()
	}
	if tr.root == nil || key == nil {
		return nil
	}
	depth := 0
	n := tr.root
	for {
		low := int16(0)
		high := n.numItems - 1
		for low <= high {
			mid := low + ((high+1)-low)/2
			if !tr.less(key, n.items[mid]) {
				low = mid + 1
			} else {
				high = mid - 1
			}
		}
		if low > 0 && !tr.less(n.items[low-1], key) {
			return n.items[low-1]
		}
		if n.leaf {
			return nil
		}
		n = n.children[low]
		depth++
	}
}

// GetHint gets a value for key using a path hint
func (tr *BTree) GetHint(key interface{}, hint *PathHint) interface{} {
	if tr.rlock() {
		defer tr.runlock()
	}
	if tr.root == nil || key == nil {
		return nil
	}
	depth := 0
	n := tr.root
	for {
		index, found := n.find(key, tr.less, hint, depth)
		if found {
			return n.items[index]
		}
		if n.leaf {
			return nil
		}
		n = n.children[index]
		depth++
	}
}

// Len returns the number of items in the tree
func (tr *BTree) Len() int {
	return tr.count
}

// Delete a value for a key
func (tr *BTree) Delete(key interface{}) interface{} {
	return tr.DeleteHint(key, nil)
}

// DeleteHint deletes a value for a key using a path hint
func (tr *BTree) DeleteHint(key interface{}, hint *PathHint) interface{} {
	if tr.lock() {
		defer tr.unlock()
	}
	return tr.deleteHint(key, hint)
}

func (tr *BTree) deleteHint(key interface{}, hint *PathHint) interface{} {
	if tr.root == nil || key == nil {
		return nil
	}
	prev := tr.delete(&tr.root, false, key, tr.less, hint, 0)
	if prev == nil {
		return nil
	}
	if tr.root.numItems == 0 && !tr.root.leaf {
		tr.root = tr.root.children[0]
	}
	tr.count--
	if tr.count == 0 {
		tr.root = nil
	}
	return prev
}

func (tr *BTree) delete(cn **node, max bool, key interface{},
	less func(a, b interface{}) bool, hint *PathHint, depth int,
) interface{} {
	n := tr.cowLoad(cn)
	var i int16
	var found bool
	if max {
		i, found = n.numItems-1, true
	} else {
		i, found = n.find(key, less, hint, depth)
	}
	if n.leaf {
		if found {
			prev := n.items[i]
			// found the items at the leaf, remove it and return.
			copy(n.items[i:], n.items[i+1:n.numItems])
			n.items[n.numItems-1] = nil
			n.numItems--
			n.count--
			return prev
		}
		return nil
	}

	var prev interface{}
	if found {
		if max {
			i++
			prev = tr.delete(&n.children[i], true, "", less, nil, 0)
		} else {
			prev = n.items[i]
			maxItem := tr.delete(&n.children[i], true, "", less, nil, 0)
			n.items[i] = maxItem
		}
	} else {
		prev = tr.delete(&n.children[i], max, key, less, hint, depth+1)
	}
	if prev == nil {
		return nil
	}
	n.count--
	if n.children[i].numItems >= minItems {
		return prev
	}

	// merge / rebalance nodes
	if i == n.numItems {
		i--
	}
	n.children[i] = tr.cowLoad(&n.children[i])
	n.children[i+1] = tr.cowLoad(&n.children[i+1])
	if n.children[i].numItems+n.children[i+1].numItems+1 < maxItems {
		// merge left + item + right
		n.children[i].items[n.children[i].numItems] = n.items[i]
		copy(n.children[i].items[n.children[i].numItems+1:],
			n.children[i+1].items[:n.children[i+1].numItems])
		if !n.children[0].leaf {
			copy(n.children[i].children[n.children[i].numItems+1:],
				n.children[i+1].children[:n.children[i+1].numItems+1])
		}
		n.children[i].numItems += n.children[i+1].numItems + 1
		n.children[i].count += n.children[i+1].count + 1
		copy(n.items[i:], n.items[i+1:n.numItems])
		copy(n.children[i+1:], n.children[i+2:n.numItems+1])
		n.items[n.numItems-1] = nil
		n.children[n.numItems] = nil
		n.numItems--
	} else if n.children[i].numItems > n.children[i+1].numItems {
		// move left -> right
		copy(n.children[i+1].items[1:],
			n.children[i+1].items[:n.children[i+1].numItems])
		if !n.children[0].leaf {
			copy(n.children[i+1].children[1:],
				n.children[i+1].children[:n.children[i+1].numItems+1])
		}
		n.children[i+1].items[0] = n.items[i]
		if !n.children[0].leaf {
			n.children[i+1].children[0] =
				n.children[i].children[n.children[i].numItems]
			n.children[i+1].count += n.children[i+1].children[0].count
		}
		n.children[i+1].numItems++
		n.children[i+1].count++
		n.items[i] = n.children[i].items[n.children[i].numItems-1]
		n.children[i].items[n.children[i].numItems-1] = nil
		if !n.children[0].leaf {
			n.children[i].children[n.children[i].numItems] = nil
			n.children[i].count -= n.children[i+1].children[0].count
		}
		n.children[i].numItems--
		n.children[i].count--
	} else {
		// move left <- right
		n.children[i].items[n.children[i].numItems] = n.items[i]
		if !n.children[0].leaf {
			n.children[i].children[n.children[i].numItems+1] =
				n.children[i+1].children[0]
			n.children[i].count +=
				n.children[i].children[n.children[i].numItems+1].count
		}
		n.children[i].numItems++
		n.children[i].count++
		n.items[i] = n.children[i+1].items[0]
		copy(n.children[i+1].items[:],
			n.children[i+1].items[1:n.children[i+1].numItems])
		n.children[i+1].items[n.children[i+1].numItems-1] = nil
		if !n.children[0].leaf {
			copy(n.children[i+1].children[:],
				n.children[i+1].children[1:n.children[i+1].numItems+1])
			n.children[i+1].children[n.children[i+1].numItems] = nil
			n.children[i+1].count -=
				n.children[i].children[n.children[i].numItems].count
		}
		n.children[i+1].numItems--
		n.children[i+1].count--
	}
	return prev
}

// Ascend the tree within the range [pivot, last]
// Pass nil for pivot to scan all item in ascending order
// Return false to stop iterating
func (tr *BTree) Ascend(pivot interface{}, iter func(item interface{}) bool) {
	if tr.rlock() {
		defer tr.runlock()
	}
	if tr.root == nil {
		return
	}
	if pivot == nil {
		tr.root.scan(iter)
	} else if tr.root != nil {
		tr.root.ascend(pivot, tr.less, nil, 0, iter)
	}
}

func (n *node) ascend(pivot interface{}, less func(a, b interface{}) bool,
	hint *PathHint, depth int, iter func(item interface{}) bool,
) bool {
	i, found := n.find(pivot, less, hint, depth)
	if !found {
		if !n.leaf {
			if !n.children[i].ascend(pivot, less, hint, depth+1, iter) {
				return false
			}
		}
	}
	for ; i < n.numItems; i++ {
		if !iter(n.items[i]) {
			return false
		}
		if !n.leaf {
			if !n.children[i+1].scan(iter) {
				return false
			}
		}
	}
	return true
}

func (n *node) reverse(iter func(item interface{}) bool) bool {
	if n.leaf {
		for i := n.numItems - 1; i >= 0; i-- {
			if !iter(n.items[i]) {
				return false
			}
		}
		return true
	}
	if !n.children[n.numItems].reverse(iter) {
		return false
	}
	for i := n.numItems - 1; i >= 0; i-- {
		if !iter(n.items[i]) {
			return false
		}
		if !n.children[i].reverse(iter) {
			return false
		}
	}
	return true
}

// Descend the tree within the range [pivot, first]
// Pass nil for pivot to scan all item in descending order
// Return false to stop iterating
func (tr *BTree) Descend(pivot interface{}, iter func(item interface{}) bool) {
	if tr.rlock() {
		defer tr.runlock()
	}
	if tr.root == nil {
		return
	}
	if pivot == nil {
		tr.root.reverse(iter)
	} else if tr.root != nil {
		tr.root.descend(pivot, tr.less, nil, 0, iter)
	}
}

func (n *node) descend(pivot interface{}, less func(a, b interface{}) bool,
	hint *PathHint, depth int, iter func(item interface{}) bool,
) bool {
	i, found := n.find(pivot, less, hint, depth)
	if !found {
		if !n.leaf {
			if !n.children[i].descend(pivot, less, hint, depth+1, iter) {
				return false
			}
		}
		i--
	}
	for ; i >= 0; i-- {
		if !iter(n.items[i]) {
			return false
		}
		if !n.leaf {
			if !n.children[i].reverse(iter) {
				return false
			}
		}
	}
	return true
}

// Load is for bulk loading pre-sorted items
func (tr *BTree) Load(item interface{}) interface{} {
	if item == nil {
		panic("nil item")
	}
	if tr.lock() {
		defer tr.unlock()
	}
	if tr.root == nil {
		return tr.setHint(item, nil)
	}
	n := tr.cowLoad(&tr.root)
	for {
		n.count++ // optimistically update counts
		if n.leaf {
			if n.numItems < maxItems-2 {
				if tr.less(n.items[n.numItems-1], item) {
					n.items[n.numItems] = item
					n.numItems++
					tr.count++
					return nil
				}
			}
			break
		}
		n = tr.cowLoad(&n.children[n.numItems])
	}
	// revert the counts
	n = tr.root
	for {
		n.count--
		if n.leaf {
			break
		}
		n = n.children[n.numItems]
	}
	return tr.setHint(item, nil)
}

// Min returns the minimum item in tree.
// Returns nil if the tree has no items.
func (tr *BTree) Min() interface{} {
	if tr.rlock() {
		defer tr.runlock()
	}
	if tr.root == nil {
		return nil
	}
	n := tr.root
	for {
		if n.leaf {
			return n.items[0]
		}
		n = n.children[0]
	}
}

// Max returns the maximum item in tree.
// Returns nil if the tree has no items.
func (tr *BTree) Max() interface{} {
	if tr.rlock() {
		defer tr.runlock()
	}
	if tr.root == nil {
		return nil
	}
	n := tr.root
	for {
		if n.leaf {
			return n.items[n.numItems-1]
		}
		n = n.children[n.numItems]
	}
}

// PopMin removes the minimum item in tree and returns it.
// Returns nil if the tree has no items.
func (tr *BTree) PopMin() interface{} {
	if tr.lock() {
		defer tr.unlock()
	}
	if tr.root == nil {
		return nil
	}
	n := tr.cowLoad(&tr.root)
	var item interface{}
	for {
		n.count-- // optimistically update counts
		if n.leaf {
			item = n.items[0]
			if n.numItems == minItems {
				break
			}
			copy(n.items[:], n.items[1:])
			n.items[n.numItems-1] = nil
			n.numItems--
			tr.count--
			if tr.count == 0 {
				tr.root = nil
			}
			return item
		}
		n = tr.cowLoad(&n.children[0])
	}
	// revert the counts
	n = tr.root
	for {
		n.count++
		if n.leaf {
			break
		}
		n = n.children[0]
	}
	return tr.deleteHint(item, nil)
}

// PopMax removes the minimum item in tree and returns it.
// Returns nil if the tree has no items.
func (tr *BTree) PopMax() interface{} {
	if tr.lock() {
		defer tr.unlock()
	}
	if tr.root == nil {
		return nil
	}
	n := tr.cowLoad(&tr.root)
	var item interface{}
	for {
		n.count-- // optimistically update counts
		if n.leaf {
			item = n.items[n.numItems-1]
			if n.numItems == minItems {
				break
			}
			n.items[n.numItems-1] = nil
			n.numItems--
			tr.count--
			if tr.count == 0 {
				tr.root = nil
			}
			return item
		}
		n = tr.cowLoad(&n.children[n.numItems])
	}
	// revert the counts
	n = tr.root
	for {
		n.count++
		if n.leaf {
			break
		}
		n = n.children[n.numItems]
	}
	return tr.deleteHint(item, nil)
}

// GetAt returns the value at index.
// Return nil if the tree is empty or the index is out of bounds.
func (tr *BTree) GetAt(index int) interface{} {
	if tr.rlock() {
		defer tr.runlock()
	}
	if tr.root == nil || index < 0 || index >= tr.count {
		return nil
	}
	n := tr.root
	for {
		if n.leaf {
			return n.items[index]
		}
		i := 0
		for ; i < int(n.numItems); i++ {
			if index < n.children[i].count {
				break
			} else if index == n.children[i].count {
				return n.items[i]
			}
			index -= n.children[i].count + 1
		}
		n = n.children[i]
	}
}

// DeleteAt deletes the item at index.
// Return nil if the tree is empty or the index is out of bounds.
func (tr *BTree) DeleteAt(index int) interface{} {
	if tr.lock() {
		defer tr.unlock()
	}
	if tr.root == nil || index < 0 || index >= tr.count {
		return nil
	}
	var pathbuf [8]uint8 // track the path
	path := pathbuf[:0]
	var item interface{}
	n := tr.cowLoad(&tr.root)
outer:
	for {
		n.count-- // optimistically update counts
		if n.leaf {
			// the index is the item position
			item = n.items[index]
			if n.numItems == minItems {
				path = append(path, uint8(index))
				break outer
			}
			copy(n.items[index:], n.items[index+1:n.numItems])
			n.items[n.numItems-1] = nil
			n.numItems--
			tr.count--
			if tr.count == 0 {
				tr.root = nil
			}
			return item
		}
		i := 0
		for ; i < int(n.numItems); i++ {
			if index < n.children[i].count {
				break
			} else if index == n.children[i].count {
				item = n.items[i]
				path = append(path, uint8(i))
				break outer
			}
			index -= n.children[i].count + 1
		}
		path = append(path, uint8(i))
		n = tr.cowLoad(&n.children[i])
	}
	// revert the counts
	var hint PathHint
	n = tr.root
	for i := 0; i < len(path); i++ {
		if i < len(hint.path) {
			hint.path[i] = path[i]
			hint.used[i] = true
		}
		n.count++
		if !n.leaf {
			n = n.children[uint8(path[i])]
		}
	}
	return tr.deleteHint(item, &hint)
}

// Height returns the height of the tree.
// Returns zero if tree has no items.
func (tr *BTree) Height() int {
	if tr.rlock() {
		defer tr.runlock()
	}
	var height int
	if tr.root != nil {
		n := tr.root
		for {
			height++
			if n.leaf {
				break
			}
			n = n.children[n.numItems]
		}
	}
	return height
}

// Walk iterates over all items in tree, in order.
// The items param will contain one or more items.
func (tr *BTree) Walk(iter func(item []interface{})) {
	if tr.rlock() {
		defer tr.runlock()
	}
	if tr.root != nil {
		tr.root.walk(iter)
	}
}

func (n *node) walk(iter func(item []interface{})) {
	if n.leaf {
		iter(n.items[:n.numItems])
	} else {
		for i := int16(0); i < n.numItems; i++ {
			n.children[i].walk(iter)
			iter(n.items[i : i+1])
		}
		n.children[n.numItems].walk(iter)
	}
}

// Copy the tree. This operation is very fast because it only performs a
// shadowed copy.
func (tr *BTree) Copy() *BTree {
	if tr.lock() {
		defer tr.unlock()
	}
	tr.cow = new(cow)
	tr2 := *tr
	tr2.mu = new(sync.RWMutex)
	tr2.cow = new(cow)
	return &tr2
}

func (tr *BTree) lock() bool {
	if tr.locks {
		tr.mu.Lock()
	}
	return tr.locks
}

func (tr *BTree) unlock() {
	tr.mu.Unlock()
}

func (tr *BTree) rlock() bool {
	if tr.locks {
		tr.mu.RLock()
	}
	return tr.locks
}

func (tr *BTree) runlock() {
	tr.mu.RUnlock()
}
