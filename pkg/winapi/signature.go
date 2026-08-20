package winapi

import (
	"errors"
	"syscall"
	"unsafe"
)

var (
	procWinVerifyTrust             = wintrust.NewProc("WinVerifyTrust")
	procCryptQueryObject           = crypt32.NewProc("CryptQueryObject")
	procCertFindCertificateInStore = crypt32.NewProc("CertFindCertificateInStore")
	procCertGetNameStringW         = crypt32.NewProc("CertGetNameStringW")
	procCertCloseStore             = crypt32.NewProc("CertCloseStore")
	wintrust                       = syscall.NewLazyDLL("wintrust.dll")
)

const (
	wtUIChoiceNone        = 2
	wtRevocationCheckNone = 0
	wtChoiceFile          = 1
	wtStateActionVerify   = 1
	wtStateActionClose    = 2

	certQueryObjectFile        = 1
	certQueryContentFlagAll    = 0x0000FFFF
	certQueryFormatFlagAll     = 0x0000FFFF
	certFindAny                = 0
	certNameSimpleDisplayName  = 4
	certCloseStoreCheckFlag    = 0x00000001
	certSystemStoreCurrentUser = 0x00010000

	x509AsnEncoding  = 0x00000001
	pkcs7AsnEncoding = 0x00010000
)

var winTrustActionGenericVerifyV2 = [16]byte{
	0x6B, 0xC5, 0xAA, 0x00, 0x44, 0xCD, 0xD0, 0x11,
	0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE,
}

type winTrustFileInfo struct {
	CbStruct       uint32
	PcwszFilePath  *uint16
	HFile          uintptr
	PgKnownSubject uintptr
}

type winTrustData struct {
	CbStruct            uint32
	PPolicyCallbackData uintptr
	PSIPClientData      uintptr
	DwUIChoice          uint32
	FdwRevocationChecks uint32
	DwUnionChoice       uint32
	PFile               *winTrustFileInfo
	DwStateAction       uint32
	HWVTStateData       uintptr
	PwszURLReference    uintptr
	DwProvFlags         uint32
	DwUIContext         uint32
	PSignatureSettings  uintptr
}

func VerifySignedFile(path string) error {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	info := winTrustFileInfo{CbStruct: uint32(unsafe.Sizeof(winTrustFileInfo{})), PcwszFilePath: pathPtr, HFile: ^uintptr(0)}
	data := winTrustData{
		CbStruct:      uint32(unsafe.Sizeof(winTrustData{})),
		DwUIChoice:    wtUIChoiceNone,
		DwUnionChoice: wtChoiceFile,
		PFile:         &info,
		DwStateAction: wtStateActionVerify,
	}
	r, _, _ := procWinVerifyTrust.Call(0, uintptr(unsafe.Pointer(&winTrustActionGenericVerifyV2[0])), uintptr(unsafe.Pointer(&data)))
	data.DwStateAction = wtStateActionClose
	procWinVerifyTrust.Call(0, uintptr(unsafe.Pointer(&winTrustActionGenericVerifyV2[0])), uintptr(unsafe.Pointer(&data)))
	if r != 0 {
		return errors.New("signature verification failed")
	}
	return nil
}

func SignedPublisher(path string) (string, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	var store uintptr
	var msg uintptr
	var ctx uintptr
	var encType uint32
	var contentType uint32
	var formatType uint32
	r, _, e := procCryptQueryObject.Call(
		certQueryObjectFile,
		uintptr(unsafe.Pointer(pathPtr)),
		certQueryContentFlagAll,
		certQueryFormatFlagAll,
		0,
		uintptr(unsafe.Pointer(&encType)),
		uintptr(unsafe.Pointer(&contentType)),
		uintptr(unsafe.Pointer(&formatType)),
		uintptr(unsafe.Pointer(&store)),
		uintptr(unsafe.Pointer(&msg)),
		uintptr(unsafe.Pointer(&ctx)),
	)
	if r == 0 {
		return "", e
	}
	if store == 0 {
		return "", errors.New("no certificate store in signed file")
	}
	defer procCertCloseStore.Call(store, certCloseStoreCheckFlag)

	certR, _, _ := procCertFindCertificateInStore.Call(
		store,
		x509AsnEncoding|pkcs7AsnEncoding,
		0,
		certFindAny,
		0,
		0,
	)
	if certR == 0 {
		return "", errors.New("no signer certificate found")
	}
	buf := make([]uint16, 256)
	n, _, _ := procCertGetNameStringW.Call(certR, certNameSimpleDisplayName, 0, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 {
		return "", errors.New("signer display name unavailable")
	}
	return syscall.UTF16ToString(buf[:n-1]), nil
}
