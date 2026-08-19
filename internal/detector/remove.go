package detector

import "os"

func removeFileOS(path string) error { return os.Remove(path) }
