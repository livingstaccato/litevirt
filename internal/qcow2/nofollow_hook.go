package qcow2

// layerOpenedHook runs after a layer of a chain is opened and before its header
// is judged (tests: swap the name for another file there).
var layerOpenedHook func(path string)
