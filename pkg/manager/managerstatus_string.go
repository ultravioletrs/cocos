// Code generated by "stringer -type=ManagerStatus"; DO NOT EDIT.

package manager

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[Starting-0]
	_ = x[Stopped-1]
	_ = x[Error-2]
	_ = x[Disconnected-3]
}

const _ManagerStatus_name = "StartingStoppedErrorDisconnected"

var _ManagerStatus_index = [...]uint8{0, 8, 15, 20, 32}

func (i ManagerStatus) String() string {
	if i >= ManagerStatus(len(_ManagerStatus_index)-1) {
		return "ManagerStatus(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _ManagerStatus_name[_ManagerStatus_index[i]:_ManagerStatus_index[i+1]]
}