package cmd

import (
	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago/server/requestorserver"
	"github.com/spf13/cobra"
	"os"
	"os/signal"
	"syscall"
)

var TypeCommand = &cobra.Command{
	Use:   "vc",
	Short: "Starts a server to return type or issuer information",
	Long:  `irma server vc`,
	Run: func(command *cobra.Command, args []string) {
		if err := configure(command); err != nil {
			die(errors.WrapPrefix(err, "Failed to read configuration from file, args, or env vars", 0))
		}

		// Hack: temporarily disable scheme updating to prevent verifyConfiguration() from immediately updating schemes
		enabled := conf.DisableSchemesUpdate
		conf.DisableSchemesUpdate = true

		if _, err := requestorserver.New(conf); err != nil {
			die(errors.WrapPrefix(err, "Invalid configuration", 0))
		}

		conf.DisableSchemesUpdate = enabled // restore previous value before printing configuration

		// here the server needs to be started
		conf.Logger.Debug("TEST type")

		serv, err := requestorserver.New(conf)
		if err != nil {
			die(errors.WrapPrefix(err, "Failed to configure server", 0))
		}

		stopped := make(chan struct{})
		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

		go func() {
			if err := serv.Start(conf, true); err != nil {
				die(errors.WrapPrefix(err, "Failed to start server", 0))
			}
			conf.Logger.Debug("Server stopped")
			stopped <- struct{}{}
		}()

		for {
			select {
			case <-interrupt:
				conf.Logger.Debug("Caught interrupt")
				serv.Stop() // causes serv.Start() above to return
				conf.Logger.Debug("Sent stop signal to server")
			case <-stopped:
				conf.Logger.Info("Exiting")
				close(stopped)
				close(interrupt)
				return
			}
		}
	},
}

func init() {
	RootCommand.AddCommand(TypeCommand)

	if err := setFlags(TypeCommand, productionMode()); err != nil {
		die(errors.WrapPrefix(err, "Failed to attach flags to "+TypeCommand.Name()+" command", 0))
	}
}
