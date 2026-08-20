package quarantine

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/mihanistudio/mihanisecurity/pkg/winapi"
)

var magicHeader = []byte("MHSQ1\x00")

const (
	chunkSize  = 64 << 10
	nonceSize  = 12
	tagSize    = 16
	headerSize = 6
)

func randomKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

func protectKey(key []byte) ([]byte, error) {
	return winapi.ProtectData(key)
}

func unprotectKey(blob []byte) ([]byte, error) {
	return winapi.UnprotectData(blob)
}

type encWriter struct {
	aead cipher.AEAD
	out  io.Writer
	hash io.Writer
}

func newEncWriter(out, hash io.Writer, key []byte) (*encWriter, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	w := &encWriter{aead: aead, out: out, hash: hash}
	if _, err := w.out.Write(magicHeader); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *encWriter) Write(p []byte) (int, error) {
	orig := len(p)
	if _, err := w.hash.Write(p); err != nil {
		return 0, err
	}
	for len(p) > 0 {
		n := len(p)
		if n > chunkSize {
			n = chunkSize
		}
		nonce := make([]byte, nonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return 0, err
		}
		ct := w.aead.Seal(nil, nonce, p[:n], nil)
		var hdr [4 + nonceSize]byte
		binary.LittleEndian.PutUint32(hdr[:4], uint32(len(ct)))
		copy(hdr[4:], nonce)
		if _, err := w.out.Write(hdr[:]); err != nil {
			return 0, err
		}
		if _, err := w.out.Write(ct); err != nil {
			return 0, err
		}
		p = p[n:]
	}
	return orig, nil
}

type decReader struct {
	aead cipher.AEAD
	in   io.Reader
	left []byte
	done bool
}

func newDecReader(r io.Reader, key []byte) (*decReader, error) {
	hdr := make([]byte, headerSize)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	if string(hdr) != string(magicHeader) {
		return nil, errors.New("quarantine: not an encrypted store file")
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return &decReader{aead: aead, in: r}, nil
}

func (d *decReader) Read(p []byte) (int, error) {
	if len(d.left) > 0 {
		n := copy(p, d.left)
		d.left = d.left[n:]
		return n, nil
	}
	if d.done {
		return 0, io.EOF
	}
	var hdr [4 + nonceSize]byte
	if _, err := io.ReadFull(d.in, hdr[:]); err != nil {
		if errors.Is(err, io.EOF) {
			d.done = true
			return 0, io.EOF
		}
		return 0, err
	}
	ctLen := int(binary.LittleEndian.Uint32(hdr[:4]))
	if ctLen < tagSize || ctLen > chunkSize+tagSize {
		return 0, errors.New("quarantine: corrupt encrypted chunk length")
	}
	ct := make([]byte, ctLen)
	if _, err := io.ReadFull(d.in, ct); err != nil {
		return 0, err
	}
	pt, err := d.aead.Open(nil, hdr[4:], ct, nil)
	if err != nil {
		return 0, err
	}
	n := copy(p, pt)
	if n < len(pt) {
		d.left = pt[n:]
	}
	return n, nil
}

func (s *Store) encryptFile(in io.Reader, out io.Writer, hash io.Writer) (int64, error) {
	ew, err := newEncWriter(out, hash, s.key)
	if err != nil {
		return 0, err
	}
	return io.Copy(ew, in)
}

func (s *Store) decryptFile(in io.Reader, out io.Writer) error {
	dr, err := newDecReader(in, s.key)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, dr)
	return err
}

func (s *Store) loadKey() error {
	if !s.encrypt {
		return nil
	}
	kp := filepath.Join(s.dir, "key.bin")
	b, err := os.ReadFile(kp)
	if err == nil {
		key, uerr := unprotectKey(b)
		if uerr == nil {
			s.key = key
			return nil
		}
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	key, kerr := randomKey()
	if kerr != nil {
		return kerr
	}
	prot, perr := protectKey(key)
	if perr != nil {
		return perr
	}
	if werr := os.WriteFile(kp, prot, 0o600); werr != nil {
		return werr
	}
	s.key = key
	return nil
}

func (s *Store) decryptStored(in io.Reader, out io.Writer) error {
	if s.encrypt {
		return s.decryptFile(in, out)
	}
	_, err := io.Copy(out, in)
	return err
}
