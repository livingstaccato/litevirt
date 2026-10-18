package automation

import (
	"bytes"
	"errors"
	"io"

	"gopkg.in/yaml.v3"
)

// These parser safety limits are independent of the aggregate admission budget.
const (
	bootstrapMetadataMaxBytes = 256 * 1024
	bootstrapMetadataMaxDepth = 64
	bootstrapMetadataMaxNodes = 16384
)

// NormalizeBootstrap prepares metadata for an already assigned resource UID and
// admitted name. The caller supplies any admitted network rendering. Supplied
// user data and all network data remain opaque, including nonnil empty slices.
// Nil user data gets the existing minimal cloud-config default once; callers
// retain original input presence separately for intent equality. All returned
// data is owned by the caller independently of the input slices.
//
// Complete metadata retains its original bytes. Otherwise only absent identity
// and hostname keys are filled; callers must retain the resulting effective
// files for recovery rather than normalize them again from mutable inputs.
func NormalizeBootstrap(uid, name string, userData, metadata, networkConfig []byte) (user, meta, network []byte, err error) {
	if uid == "" || name == "" {
		return nil, nil, nil, errors.New("missing admitted bootstrap identity")
	}
	if userData == nil {
		userData = []byte("#cloud-config\n{}\n")
	}
	invalid := errors.New("invalid bootstrap metadata")
	if len(metadata) > bootstrapMetadataMaxBytes {
		return nil, nil, nil, invalid
	}
	var doc yaml.Node
	if metadata == nil {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	} else {
		decoder := yaml.NewDecoder(bytes.NewReader(metadata))
		if decoder.Decode(&doc) != nil || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
			return nil, nil, nil, invalid
		}
		var extra yaml.Node
		if decoder.Decode(&extra) != io.EOF {
			return nil, nil, nil, invalid
		}
	}
	nodes := 0
	if !validBootstrapMetadata(&doc, 0, &nodes) {
		return nil, nil, nil, invalid
	}
	mapping := doc.Content[0]
	var instanceID, hostname *yaml.Node
	for i := 0; i < len(mapping.Content); i += 2 {
		switch mapping.Content[i].Value {
		case "instance-id":
			instanceID = mapping.Content[i+1]
		case "local-hostname":
			hostname = mapping.Content[i+1]
		}
	}
	if instanceID != nil && (instanceID.Kind != yaml.ScalarNode || instanceID.ShortTag() != "!!str" || instanceID.Value != uid) {
		return nil, nil, nil, invalid
	}
	if hostname != nil && (hostname.Kind != yaml.ScalarNode || hostname.ShortTag() != "!!str" || hostname.Value == "") {
		return nil, nil, nil, invalid
	}
	if instanceID != nil && hostname != nil {
		return bytes.Clone(userData), bytes.Clone(metadata), bytes.Clone(networkConfig), nil
	}
	for _, field := range []struct {
		key, value string
		present    bool
	}{
		{"instance-id", uid, instanceID != nil},
		{"local-hostname", name, hostname != nil},
	} {
		if !field.present {
			mapping.Content = append(mapping.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: field.key}, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: field.value})
		}
	}
	nodes = 0
	if !validBootstrapMetadata(&doc, 0, &nodes) {
		return nil, nil, nil, invalid
	}
	meta, err = yaml.Marshal(&doc)
	if err != nil || len(meta) > bootstrapMetadataMaxBytes {
		return nil, nil, nil, invalid
	}
	return bytes.Clone(userData), meta, bytes.Clone(networkConfig), nil
}

// Validate the node graph before encoding it or interpreting identity fields.
// Node decoding alone does not reject duplicate keys or prevent YAML aliases.
func validBootstrapMetadata(node *yaml.Node, depth int, nodes *int) bool {
	*nodes += 1
	if depth > bootstrapMetadataMaxDepth || *nodes > bootstrapMetadataMaxNodes || node.Kind == yaml.AliasNode || node.ShortTag() == "!!merge" {
		return false
	}
	if node.Kind == yaml.MappingNode {
		keys := make(map[string]struct{}, len(node.Content)/2)
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" {
				return false
			}
			if _, exists := keys[key.Value]; exists {
				return false
			}
			keys[key.Value] = struct{}{}
		}
	}
	for _, child := range node.Content {
		if !validBootstrapMetadata(child, depth+1, nodes) {
			return false
		}
	}
	return true
}
