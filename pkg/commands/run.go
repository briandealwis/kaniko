/*
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package commands

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	kConfig "github.com/GoogleContainerTools/kaniko/pkg/config"
	"github.com/GoogleContainerTools/kaniko/pkg/constants"
	"github.com/GoogleContainerTools/kaniko/pkg/dockerfile"
	"github.com/GoogleContainerTools/kaniko/pkg/util"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	shell "github.com/kballard/go-shellquote"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type RunCommand struct {
	BaseCommand
	cmd *instructions.RunCommand
}

// for testing
var (
	userLookup   = user.Lookup
	userLookupID = user.LookupId
)

func (r *RunCommand) ExecuteCommand(config *v1.Config, buildArgs *dockerfile.BuildArgs) error {
	return runCommandInExec(config, buildArgs, r.cmd)
}

func runCommandInExec(config *v1.Config, buildArgs *dockerfile.BuildArgs, cmdRun *instructions.RunCommand) error {
	cmdLine := binfmtPatch(cmdRun.CmdLine, config)

	var newCommand []string
	if cmdRun.PrependShell {
		// This is the default shell on Linux
		var shell []string
		if len(config.Shell) > 0 {
			shell = config.Shell
		} else {
			shell = append(shell, "/bin/sh", "-c")
		}
		newCommand = append(shell, strings.Join(cmdLine, " "))
	} else {
		newCommand = cmdRun.CmdLine
		path, err := lookPath(newCommand[0], config)
		if err == nil {
			newCommand[0] = path
		}
	}

	logrus.Infof("cmd: %s", newCommand[0])
	logrus.Infof("args: %s", newCommand[1:])

	cmd := exec.Command(newCommand[0], newCommand[1:]...)

	cmd.Dir = setWorkDirIfExists(config.WorkingDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	replacementEnvs := buildArgs.ReplacementEnvs(config.Env)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	u := config.User
	userAndGroup := strings.Split(u, ":")
	userStr, err := util.ResolveEnvironmentReplacement(userAndGroup[0], replacementEnvs, false)
	if err != nil {
		return errors.Wrapf(err, "resolving user %s", userAndGroup[0])
	}

	// If specified, run the command as a specific user
	if userStr != "" {
		cmd.SysProcAttr.Credential, err = util.SyscallCredentials(userStr)
		if err != nil {
			return errors.Wrap(err, "credentials")
		}
	}

	env, err := addDefaultHOME(userStr, replacementEnvs)
	if err != nil {
		return errors.Wrap(err, "adding default HOME variable")
	}

	cmd.Env = env

	logrus.Infof("Running: %s", cmd.Args)
	if err := cmd.Start(); err != nil {
		return errors.Wrap(err, "starting command")
	}

	pgid, err := syscall.Getpgid(cmd.Process.Pid)
	if err != nil {
		return errors.Wrap(err, "getting group id for process")
	}
	if err := cmd.Wait(); err != nil {
		return errors.Wrap(err, "waiting for process to exit")
	}

	//it's not an error if there are no grandchildren
	if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil && err.Error() != "no such process" {
		return err
	}
	return nil
}

// addDefaultHOME adds the default value for HOME if it isn't already set
func addDefaultHOME(u string, envs []string) ([]string, error) {
	for _, env := range envs {
		split := strings.SplitN(env, "=", 2)
		if split[0] == constants.HOME {
			return envs, nil
		}
	}

	// If user isn't set, set default value of HOME
	if u == "" || u == constants.RootUser {
		return append(envs, fmt.Sprintf("%s=%s", constants.HOME, constants.DefaultHOMEValue)), nil
	}

	// If user is set to username, set value of HOME to /home/${user}
	// Otherwise the user is set to uid and HOME is /
	userObj, err := userLookup(u)
	if err != nil {
		if uo, e := userLookupID(u); e == nil {
			userObj = uo
		} else {
			return nil, err
		}
	}

	return append(envs, fmt.Sprintf("%s=%s", constants.HOME, userObj.HomeDir)), nil
}

// String returns some information about the command for the image config
func (r *RunCommand) String() string {
	return r.cmd.String()
}

func (r *RunCommand) FilesToSnapshot() []string {
	return nil
}

func (r *RunCommand) ProvidesFilesToSnapshot() bool {
	return false
}

// CacheCommand returns true since this command should be cached
func (r *RunCommand) CacheCommand(img v1.Image) DockerCommand {

	return &CachingRunCommand{
		img:       img,
		cmd:       r.cmd,
		extractFn: util.ExtractFile,
	}
}

func (r *RunCommand) MetadataOnly() bool {
	return false
}

func (r *RunCommand) RequiresUnpackedFS() bool {
	return true
}

func (r *RunCommand) ShouldCacheOutput() bool {
	return true
}

type CachingRunCommand struct {
	BaseCommand
	caching
	img            v1.Image
	extractedFiles []string
	cmd            *instructions.RunCommand
	extractFn      util.ExtractFunction
}

func (cr *CachingRunCommand) ExecuteCommand(config *v1.Config, buildArgs *dockerfile.BuildArgs) error {
	logrus.Infof("Found cached layer, extracting to filesystem")
	var err error

	if cr.img == nil {
		return errors.New(fmt.Sprintf("command image is nil %v", cr.String()))
	}

	layers, err := cr.img.Layers()
	if err != nil {
		return errors.Wrap(err, "retrieving image layers")
	}

	if len(layers) != 1 {
		return errors.New(fmt.Sprintf("expected %d layers but got %d", 1, len(layers)))
	}

	cr.layer = layers[0]

	cr.extractedFiles, err = util.GetFSFromLayers(
		kConfig.RootDir,
		layers,
		util.ExtractFunc(cr.extractFn),
		util.IncludeWhiteout(),
	)
	if err != nil {
		return errors.Wrap(err, "extracting fs from image")
	}

	return nil
}

func (cr *CachingRunCommand) FilesToSnapshot() []string {
	f := cr.extractedFiles
	logrus.Debugf("%d files extracted by caching run command", len(f))
	logrus.Tracef("Extracted files: %s", f)

	return f
}

func (cr *CachingRunCommand) String() string {
	if cr.cmd == nil {
		return "nil command"
	}
	return cr.cmd.String()
}

func (cr *CachingRunCommand) MetadataOnly() bool {
	return false
}

func setWorkDirIfExists(workdir string) string {
	if _, err := os.Lstat(workdir); err == nil {
		return workdir
	}
	return ""
}

// Poor Man's implementation of linux binfmt_misc https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html
type binfmtMagic struct {
	os     string
	arch   string
	magic  []byte
	mask   []byte
	offset int
}

var (
	elves []binfmtMagic = []binfmtMagic{
		{
			os:     "linux",
			arch:   "arm",
			magic:  []byte{0x7f, 'E', 'L', 'F', 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x28, 0x00},
			mask:   []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff},
			offset: 0,
		},
		{
			os:     "linux",
			arch:   "arm64",
			magic:  []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0xb7, 0x00},
			mask:   []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff},
			offset: 0,
		},
		{
			os:     "linux",
			arch:   "amd64",
			magic:  []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x3e, 0x00},
			mask:   []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xfe, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff},
			offset: 0,
		},
	}
)

func hasMagic(filepath string) *binfmtMagic {
	max := 0
	for _, elf := range elves {
		c := elf.offset + len(elf.magic)
		if c > max {
			max = c
		}
	}

	header, err := readHeader(filepath, max)
	if err != nil {
		logrus.Warnf("unable to read file header for %q: %v", filepath, err)
		return nil
	}
	for _, elf := range elves {
		matched := true
		for i := 0; matched && i < len(elf.magic); i++ {
			if (header[elf.offset+i]^elf.magic[i])&elf.mask[i] != 0 {
				matched = false
			}
		}
		if matched {
			logrus.Debugfof("File %q is executable from %s/%s", filepath, elf.os, elf.arch)
			return &elf
		}
	}
	return nil
}

func readHeader(filepath string, n int) ([]byte, error) {
	var header []byte = make([]byte, n)
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if _, err := io.ReadFull(file, header); err != nil {
		return nil, err
	}
	return header, nil
}

// binfmtPatch rewrites a command-line to invoke foreign executables using the corresponding
// qemu-user-static loader.  This function assumes the qemu loaders are named /kaniko/qemu-GOARCH.
func binfmtPatch(cmdLine []string, config *v1.Config) []string {
	rejoin := false
	if len(cmdLine) == 1 && strings.Contains(cmdLine[0], " ") {
		if cl, err := shell.Split(cmdLine[0]); err == nil {
			logrus.Tracef("binfmtPatch: reparsed cmdline: %v", cmdLine)
			cmdLine = cl
			rejoin = true
		}
	}
	var modified []string
	for i, arg := range cmdLine {
		logrus.Tracef("binfmtPatch: examining %d: %q relative to %q", i, arg, config.WorkingDir)

		if fp, err := lookPath(arg, config); err != nil {
			logrus.Tracef("could not resolve %q as binary: %v", arg, err)
		} else if isExecutable(fp) {
			logrus.Debugf("binfmtPatch: resolved %q to executable %q", arg, fp)

			if elf := hasMagic(fp); elf != nil {
				if runtime.GOOS != elf.os || runtime.GOARCH != elf.arch {
					logrus.Infof("binfmtPatch: %q is an executable file of type %s/%s", fp, elf.os, elf.arch)
					modified = append(modified, fmt.Sprintf("/kaniko/qemu-%s", elf.arch))
					arg = fp // replace with fully-resolved path
				}
			} else {
				logrus.Debugf("bifmtPatch: %q is an unknown executable", fp)
			}
		}
		modified = append(modified, arg)
	}
	logrus.Debugf("binfmtPatch: modified cmdline: %v", modified)
	if rejoin {
		return []string{shell.Join(modified...)}
	}
	return modified
}

// lookPath tries to resolve the given command in the image configuration's PATH.
func lookPath(cmd string, config *v1.Config) (string, error) {
	if filepath.IsAbs(cmd) && isExecutable(cmd) {
		return cmd, nil
	}
	if p := filepath.Join(config.WorkingDir, cmd); isExecutable(p) {
		return p, nil
	}
	for _, v := range config.Env {
		entry := strings.SplitN(v, "=", 2)
		if entry[0] != "PATH" {
			continue
		}
		for _, d := range strings.Split(entry[1], string(os.PathListSeparator)) {
			if p := filepath.Join(d, cmd); isExecutable(p) {
				return p, nil
			}
		}
	}
	return cmd, errors.New("not found")
}

func isExecutable(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fi.Mode().IsRegular() && (fi.Mode().Perm()&0111) != 0
}
