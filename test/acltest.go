package main

import (
  "acl"
  "fmt"
  "os"
)

func main() {
  cfg, _ := acl.ParseDefaultConfig()
  fmt.Println(cfg)

  if len(os.Args) < 2 {
    panic("Insufficient arguments")
  }

  var ifaceStr string = ""
  if len(os.Args) >= 3 {
    ifaceStr = os.Args[2]
  }

  fmt.Println(cfg.IsAllowedString(ifaceStr, os.Args[1]))
}
