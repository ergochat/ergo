package enfa

import "fmt"

type transitionInput struct {
	srcState int
	input    string
}

type destState map[int]bool

type ENFA struct {
	initState    int
	currentState map[int]bool
	totalStates  []int
	finalStates  []int
	transition   map[transitionInput]destState
	inputMap     map[string]bool
}

//New a new NFA
func NewENFA(initState int, isFinal bool) *ENFA {

	retNFA := &ENFA{
		transition: make(map[transitionInput]destState),
		inputMap:   make(map[string]bool),
		initState:  initState}

	retNFA.currentState = make(map[int]bool)
	retNFA.currentState[initState] = true
	retNFA.AddState(initState, isFinal)
	return retNFA
}

//Add new state in this NFA
func (d *ENFA) AddState(state int, isFinal bool) {
	if state == -1 {
		fmt.Println("Cannot add state as -1, it is dead state")
		return
	}

	d.totalStates = append(d.totalStates, state)
	if isFinal {
		d.finalStates = append(d.finalStates, state)
	}
}

//Add new transition function into NFA
func (d *ENFA) AddTransition(srcState int, input string, dstStateList ...int) {
	find := false

	//find input if exist in NFA input List
	if _, ok := d.inputMap[input]; !ok {
		//not exist, new input in this NFA
		d.inputMap[input] = true
	}

	for _, v := range d.totalStates {
		if v == srcState {
			find = true
		}
	}

	if !find {
		fmt.Println("No such state:", srcState, " in current NFA")
		return
	}

	dstMap := make(map[int]bool)
	for _, destState := range dstStateList {
		dstMap[destState] = true
	}

	targetTrans := transitionInput{srcState: srcState, input: input}
	d.transition[targetTrans] = dstMap
}

func (d *ENFA) CheckPathExist(src int, input string, dst int) bool {
	retMap, _ := d.transition[transitionInput{srcState: src, input: input}]
	if _, ok := retMap[dst]; ok {
		return true
	}
	return false
}

func (d *ENFA) Input(testInput string) []int {
	updateCurrentState := make(map[int]bool)
	for current, _ := range d.currentState {
		for _, realTestInput := range []string{testInput, "*", "?"} {
			intputTrans := transitionInput{srcState: current, input: realTestInput}
			valMap, ok := d.transition[intputTrans]
			if ok {
				for dst, _ := range valMap {
					updateCurrentState[dst] = true

					//Update epsilon input way... if exist
					epsilonTrans := transitionInput{srcState: dst}
					if eMap, ok := d.transition[epsilonTrans]; ok {
						for eDst, _ := range eMap {
							updateCurrentState[eDst] = true
						}
					}
				}
			} else {
				//dead state, remove in current state
				//do nothing.
			}
		}
	}

	//update curret state
	d.currentState = updateCurrentState

	//return result
	var ret []int
	for state, _ := range updateCurrentState {
		ret = append(ret, state)
	}
	return ret
}

//To verify current state if it is final state
func (d *ENFA) Verify() bool {
	for _, val := range d.finalStates {
		for cState, _ := range d.currentState {
			if val == cState {
				return true
			}
		}
	}
	return false
}

//Reset NFA state to initilize state, but all state and transition function will remain
func (d *ENFA) Reset() {
	initState := make(map[int]bool)
	initState[d.initState] = true
	d.currentState = initState
}

//Verify if list of input could be accept by NFA or not
func (d *ENFA) VerifyInputs(inputs []string) bool {
	for _, v := range inputs {
		d.Input(v)
	}
	return d.Verify()
}

//To print detail transition table contain of current NFA
func (d *ENFA) PrintTransitionTable() {
	fmt.Println("===================================================")
	//list all inputs
	var inputList []string
	for key, _ := range d.inputMap {
		if key == "" {
			fmt.Printf("\tε|")
		} else {
			fmt.Printf("\t%s|", key)
		}
		inputList = append(inputList, key)
	}

	fmt.Printf("\n")
	fmt.Println("---------------------------------------------------")

	for _, state := range d.totalStates {
		fmt.Printf("%d |", state)
		for _, key := range inputList {
			checkInput := transitionInput{srcState: state, input: key}
			if dstState, ok := d.transition[checkInput]; ok {
				fmt.Printf("\t")
				for val, _ := range dstState {
					fmt.Printf("%d,", val)
				}
				fmt.Printf("|")
			} else {
				fmt.Printf("\tNA|")
			}
		}
		fmt.Printf("\n")
	}

	fmt.Println("---------------------------------------------------")
	fmt.Println("===================================================")
}
