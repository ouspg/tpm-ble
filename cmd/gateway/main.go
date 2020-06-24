package main

import (
	"fmt"
	"os"

	"github.com/muka/go-bluetooth/hw"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func Run(adapterID string, mode string, hwaddr string) error {

	log.SetLevel(log.TraceLevel)

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


	/*if mode == "client" {
		return client(adapterID, hwaddr)
	} else {
		return serve(adapterID)
	}*/

	return serve(adapterID)
}

func failArg(arg string) {
	failArgs([]string{arg})
}

func failArgs(args []string) {
	fail(fmt.Errorf("Missing arguments: %s", args))
}

func fail(err error) {
	if err != nil {
		log.Errorf("Error: %s", err)
		os.Exit(1)
	}
	os.Exit(0)
}

var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "A service / client example",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {

		adapterID, err := cmd.Flags().GetString("adapterID")
		if err != nil {
			fail(err)
		}

		if len(args) < 1 {
			failArgs([]string{"mode [server|client]"})
		}

		if args[0] == "client" {
			if len(args) < 2 {
				failArgs([]string{
					"please specify the adapter HW address that expose the service (eg. using hciconfig)",
				})
			}
		} else {
			args = append(args, "")
		}

		fail(Run(adapterID, args[0], args[1]))
	},
}

func main() {
	serviceCmd.Flags().String("adapterID", "", "Specify adapter id")

	serviceCmd.Execute()
}
