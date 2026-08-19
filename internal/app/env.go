package app

import "os"

func readEnv(k string) (string, bool) { return os.LookupEnv(k) }
