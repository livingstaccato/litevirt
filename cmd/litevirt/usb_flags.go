package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// usbFlags are the USB passthrough flags `lv run` and `lv update` share.
type usbFlags struct {
	ids      []string // --usb vendor:product
	ports    []string // --usb-port bus-port
	mappings []string // --usb-mapping name
}

func (u *usbFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringArrayVar(&u.ids, "usb", nil,
		"Pass through the host USB device <vendor>:<product> (e.g. 046d:c52b; repeatable). A raw device binds the VM to its host: pin it with --host")
	cmd.Flags().StringArrayVar(&u.ports, "usb-port", nil,
		"Pass through the host USB device plugged into <bus>-<port>[.<port>...] (e.g. 1-2; repeatable). Binds the VM to its host")
	cmd.Flags().StringArrayVar(&u.mappings, "usb-mapping", nil,
		"Pass through the USB device a resource mapping names on whichever host runs the VM (repeatable; see lv mapping add-device)")
}

// changed reports whether any USB flag was given.
func (u *usbFlags) changed(cmd *cobra.Command) bool {
	f := cmd.Flags()
	return f.Changed("usb") || f.Changed("usb-port") || f.Changed("usb-mapping")
}

// devices builds the USB device list the flags describe.
func (u *usbFlags) devices() ([]*pb.USBDeviceSpec, error) {
	var out []*pb.USBDeviceSpec
	for _, id := range u.ids {
		v, p, ok := strings.Cut(id, ":")
		if !ok || v == "" || p == "" {
			return nil, fmt.Errorf("--usb %q: want <vendor>:<product>, e.g. 046d:c52b", id)
		}
		out = append(out, &pb.USBDeviceSpec{Vendor: v, Product: p})
	}
	for _, port := range u.ports {
		out = append(out, &pb.USBDeviceSpec{BusPort: port})
	}
	for _, m := range u.mappings {
		out = append(out, &pb.USBDeviceSpec{Mapping: m})
	}
	return out, nil
}
