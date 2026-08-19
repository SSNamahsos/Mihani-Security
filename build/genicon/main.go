// Command genicon converts icon.png into a standard multi-size Windows ICO
// (build/windows/icon.ico) using PNG-compressed frames, which Windows 7+
// renders natively. Wails embeds this file into the GUI executable, and the
// Inno Setup script uses it for the installer icon.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/draw"
	"image/png"
	"os"
	"path/filepath"

	xdraw "golang.org/x/image/draw"
)

var sizes = []int{256, 128, 64, 48, 32, 24, 16}

func main() {
	root := "."
	src := filepath.Join(root, "icon.png")
	dst := filepath.Join(root, "build", "windows", "icon.ico")

	f, err := os.Open(src)
	if err != nil {
		fatal("open %s: %v", src, err)
	}
	img, err := png.Decode(f)
	f.Close()
	if err != nil {
		fatal("decode %s: %v", src, err)
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		fatal("mkdir: %v", err)
	}

	type frame struct {
		w, h, size	int
		data		[]byte
	}
	var frames []frame
	var offset = 6 + 16*len(sizes)
	for _, s := range sizes {
		var bmp image.Image = img
		if img.Bounds().Dx() != s || img.Bounds().Dy() != s {
			bmp = scale(img, s)
		}
		var buf bytes.Buffer
		if err := png.Encode(&buf, bmp); err != nil {
			fatal("encode %dpx: %v", s, err)
		}
		frames = append(frames, frame{s, s, buf.Len(), buf.Bytes()})
	}

	var out bytes.Buffer
	b := make([]byte, 6)

	binary.LittleEndian.PutUint16(b[0:2], 0)
	binary.LittleEndian.PutUint16(b[2:4], 1)
	binary.LittleEndian.PutUint16(b[4:6], uint16(len(frames)))
	out.Write(b)

	for _, fr := range frames {
		e := make([]byte, 16)
		if fr.w >= 256 {
			e[0], e[1] = 0, 0
		} else {
			e[0], e[1] = byte(fr.w), byte(fr.h)
		}
		binary.LittleEndian.PutUint16(e[4:6], 0)
		binary.LittleEndian.PutUint16(e[6:8], 32)
		binary.LittleEndian.PutUint32(e[8:12], uint32(fr.size))
		binary.LittleEndian.PutUint32(e[12:16], uint32(offset))
		out.Write(e)
		offset += fr.size
	}
	for _, fr := range frames {
		out.Write(fr.data)
	}

	if err := os.WriteFile(dst, out.Bytes(), 0o644); err != nil {
		fatal("write %s: %v", dst, err)
	}
	fmt.Printf("wrote %s (%d bytes, %d frames from %s)\n", dst, out.Len(), len(frames), src)
}

func scale(img image.Image, s int) image.Image {
	dst := image.NewRGBA(image.Rect(0, 0, s, s))
	xdraw.CatmullRom.Scale(dst, dst.Bounds(), img, img.Bounds(), draw.Over, nil)
	return dst
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "genicon: "+format+"\n", args...)
	os.Exit(1)
}
