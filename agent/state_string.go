// Code generated by "stringer -type=state"; DO NOT EDIT.

package agent

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[idle-0]
	_ = x[receivingManifest-1]
	_ = x[receivingAlgorithm-2]
	_ = x[receivingData-3]
	_ = x[running-4]
	_ = x[results-5]
	_ = x[complete-6]
	_ = x[failed-7]
}

const _state_name = "idlereceivingManifestreceivingAlgorithmreceivingDatarunningresultscompletefailed"

var _state_index = [...]uint8{0, 4, 21, 39, 52, 59, 66, 74, 80}

func (i state) String() string {
	if i >= state(len(_state_index)-1) {
		return "state(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _state_name[_state_index[i]:_state_index[i+1]]
}
