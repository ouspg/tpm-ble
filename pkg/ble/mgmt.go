package ble

import (
	"github.com/muka/go-bluetooth/hw"
	"github.com/muka/go-bluetooth/hw/linux/btmgmt"
	"github.com/muka/go-bluetooth/hw/linux/cmd"
	"os"
)

/**
Todo: Use dbus bluetooth management API instead of the btmgmt cli tool (requires CAP_NET_ADMIN)
 */

func EnableSecureLE(adapterID string) {
	btmgmt := hw.NewBtMgmt(adapterID)
	if len(os.Getenv("DOCKER")) > 0 {
		btmgmt.BinPath = "./bin/docker-btmgmt"
	}

	// set LE mode
	btmgmt.SetPowered(false)
	btmgmt.SetLe(true)
	btmgmt.SetBondable(true)
	btmgmt.SetLinkLevelSecurity(true)
	btmgmt.SetSsp(true)
	btmgmt.SetBredr(false)
	btmgmt.SetPowered(true)
}

// NewBtMgmt init a new BtMgmt command
func NewBtMgmt(adapterID string) *BtMgmt {
	return &BtMgmt{adapterID, btmgmt.DefaultBinPath}
}

// BtMgmt btmgmt command wrapper
type BtMgmt struct {
	adapterID string
	// BinPath configure the CLI path to btmgmt
	BinPath string
}

// btmgmt cmd wrapper
func (h *BtMgmt) cmd(args ...string) error {
	cmdArgs := []string{h.BinPath, "--index", h.adapterID}
	cmdArgs = append(cmdArgs, args...)
	_, err := cmd.Exec(cmdArgs...)
	if err != nil {
		return err
	}
	return nil
}


func (h *BtMgmt) GetBREDROOBData(adapterID string) {
	btmgmt := NewBtMgmt(adapterID)
	if len(os.Getenv("DOCKER")) > 0 {
		btmgmt.BinPath = "./bin/docker-btmgmt"
	}

	h.cmd()
}