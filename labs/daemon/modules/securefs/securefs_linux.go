//go:build linux

package securefs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

var (
	fuseServer *fuse.Server
)

type MemFile struct {
	fs.Inode
	mu   sync.RWMutex
	data []byte
	mode uint32
}

// Implement NodeGetattrer
func (f *MemFile) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out.Size = uint64(len(f.data))
	out.Mode = f.mode
	return 0
}

// Implement NodeReader
func (f *MemFile) Read(ctx context.Context, fh fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if off >= int64(len(f.data)) {
		return fs.ReadResultData(nil), 0
	}
	end := off + int64(len(dest))
	if end > int64(len(f.data)) {
		end = int64(len(f.data))
	}
	return fs.ReadResultData(f.data[off:end]), 0
}

// Implement NodeWriter
func (f *MemFile) Write(ctx context.Context, fh fs.FileHandle, data []byte, off int64) (uint32, syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()
	end := off + int64(len(data))
	if end > int64(len(f.data)) {
		newData := make([]byte, end)
		copy(newData, f.data)
		f.data = newData
	}
	copy(f.data[off:end], data)
	return uint32(len(data)), 0
}

// Implement NodeSetattrer
func (f *MemFile) Setattr(ctx context.Context, fh fs.FileHandle, in *fuse.AttrIn, out *fuse.AttrOut) syscall.Errno {
	f.mu.Lock()
	defer f.mu.Unlock()
	if size, ok := in.GetSize(); ok {
		if int64(size) < int64(len(f.data)) {
			f.data = f.data[:size]
		} else if int64(size) > int64(len(f.data)) {
			newData := make([]byte, size)
			copy(newData, f.data)
			f.data = newData
		}
	}
	if mode, ok := in.GetMode(); ok {
		f.mode = mode
	}
	out.Size = uint64(len(f.data))
	out.Mode = f.mode
	return 0
}

type MemDir struct {
	fs.Inode
}

// Implement NodeCreater to allow file creation
func (d *MemDir) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	memFile := &MemFile{
		mode: mode,
	}
	child := d.NewPersistentInode(ctx, memFile, fs.StableAttr{Mode: syscall.S_IFREG})
	d.AddChild(name, child, true)
	return child, nil, 0, 0
}

// Implement NodeUnlinker to allow file deletion
func (d *MemDir) Unlink(ctx context.Context, name string) syscall.Errno {
	d.RmChild(name)
	return 0
}

func initSecureFS() error {
	if fuseServer != nil || secureDir != "" {
		return nil
	}
	dir, err := os.MkdirTemp("", "luminet-secure-*")
	if err != nil {
		return err
	}

	root := &MemDir{}
	server, errNo := fs.Mount(dir, root, &fs.Options{})
	if errNo != 0 {
		_ = os.RemoveAll(dir)
		return fmt.Errorf("failed to mount FUSE: %v", errNo)
	}

	secureDir = dir
	fuseServer = server
	return nil
}

func writeFile(filename string, data []byte, perm os.FileMode) (string, error) {
	if secureDir == "" {
		return "", fmt.Errorf("secure filesystem not initialized")
	}
	filePath := filepath.Join(secureDir, filename)
	err := os.WriteFile(filePath, data, perm)
	if err != nil {
		return "", err
	}
	return filePath, nil
}

func readFile(filename string) ([]byte, error) {
	if secureDir == "" {
		return nil, fmt.Errorf("secure filesystem not initialized")
	}
	filePath := filepath.Join(secureDir, filename)
	return os.ReadFile(filePath)
}

func cleanupSecureFS() {
	if fuseServer != nil {
		_ = fuseServer.Unmount()
		fuseServer = nil
	}
	if secureDir != "" {
		_ = os.RemoveAll(secureDir)
		secureDir = ""
	}
}
