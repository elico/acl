package acl

import (
  "github.com/BurntSushi/toml"
  "github.com/steakknife/ip"
//  "log"
  "net"
//  "os"
  "strings"
  "sync"
)

const (
  DefaultConfigFilename = "network.toml"
)

//var Logger *log.Logger = log.New(os.Stderr, "", log.Llongfile|log.LstdFlags|log.Lmicroseconds)

// Allowed defaults to none (nothing is allowed)
// Banned defaults to none
// Banned... overrides Allowed...
type ACL struct {
  AllowedInterfaces []string
  AllowedAddresses  []ip.IP
  AllowedHosts      []string

  BannedInterfaces []string
  BannedAddresses  []ip.IP
  BannedHosts      []string
}

type spec struct {
  Interfaces []string `toml:"interfaces"`
  Hosts      []string `toml:"hosts"`
}

type config struct {
  Allowed spec `toml:"allowed"`
  Banned  spec `toml:"banned"`
}

func ParseDefaultConfig() (acl ACL, err error) {
  return ParseConfig(DefaultConfigFilename)
}

func ParseConfig(filename string) (acl ACL, err error) {
  var config config

  _, err = toml.DecodeFile(filename, &config)
  if err != nil {
    return
  }

  acl.AllowedAddresses, acl.AllowedHosts, err = parseHosts(config.Allowed.Hosts)
  if err != nil {
    return
  }

  acl.BannedAddresses, acl.BannedHosts, err = parseHosts(config.Banned.Hosts)
  if err != nil {
    return
  }

  acl.AllowedInterfaces = config.Allowed.Interfaces
  acl.BannedInterfaces = config.Banned.Interfaces

  return
}

func parseHosts(strs []string) (addrs []ip.IP, hosts []string, err error) {
  addrs = []ip.IP{}
  hosts = []string{}

  for _, str := range strs {
    addr, err2 := ip.Parse(str)
    if err2 != nil {
//      Logger.Println("ip.Parse(", str, ") = <nil>, err=", err2)
      hosts = append(hosts, str)
      continue
    }
    //Logger.Println("ip.Parse(", str, ") = ", addr.Inspect(), ", err=", nil)
    addrs = append(addrs, addr)
  }
  return
}

func matchInterface(iface *net.Interface, matchIfaces []string) bool {
  for _, matchIface := range matchIfaces {
    if iface.Name == matchIface {
      //Logger.Println("matchInterface(iface=", iface, ", matchIfaces=", matchIfaces, ") = ", true)
      return true
    }
  }
  //Logger.Println("matchInterface(iface=", iface, ", matchIfaces=", matchIfaces, ") = ", false)
  return false
}

func matchAddress(iface *net.Interface, addr net.IP, matchAddrs []ip.IP) bool {
  for _, matchAddr := range matchAddrs {
    if matchAddr.ContainsWithInterface(addr, iface) {

      //Logger.Println("matchAddress(iface=", iface, ", addr=", addr, ", matchHosts=", matchAddrs, ") = ", true)
      return true
    }
  }
  //Logger.Println("matchAddress(iface=", iface, ", addr=", addr, ", matchHosts=", matchAddrs, ") = ", false)
  return false
}

// async lookup with synchronous waiting
func matchHost(iface *net.Interface, addr net.IP, matchHosts []string) (result bool) {
  result = false
  var wg sync.WaitGroup
  for _, matchHost := range matchHosts {
    wg.Add(1)
    go func() {
      defer wg.Done()
      resolvedAddrs, err := net.LookupHost(matchHost)
      if err != nil {
        //Logger.Println("matchHost LookupHost() error = ", err)
        return
      }
      for _, resolvedAddr := range resolvedAddrs {
        ipIP, err2 := ip.Parse(resolvedAddr)
        if err2 != nil {
          //Logger.Println("matchHost ip.Parse() error = ", err2)
          continue
        }
        if ipIP.ContainsWithInterface(addr, iface) {
          result = true
          return
        }
      }
    }()
  }
  wg.Wait()
  //Logger.Println("matchHost(iface=", iface, ", addr=", addr, ", matchHosts=", matchHosts, ") = ", result)
  return result
}

func (acl ACL) IsAllowedString(ifaceStr string, addrStr string) (result bool) {
  iface, _ := net.InterfaceByName(ifaceStr)
  addr := net.ParseIP(addrStr)
  return acl.IsAllowed(iface, addr)
}

func (acl ACL) IsAllowed(iface *net.Interface, addr net.IP) (result bool) {
  return (len(acl.AllowedInterfaces) == 0 || matchInterface(iface, acl.AllowedInterfaces)) &&
    (matchAddress(iface, addr, acl.AllowedAddresses) || matchHost(iface, addr, acl.AllowedHosts)) &&
    !matchAddress(iface, addr, acl.BannedAddresses) &&
    !matchHost(iface, addr, acl.BannedHosts)
  return
}

func (acl ACL) String() (result string) {
  result = "AllowedInterfaces: " + strings.Join(acl.AllowedInterfaces, ", ") + "\n"
  xstrs := []string{}
  for _, x := range acl.AllowedAddresses {
    xstrs = append(xstrs, x.String())
  }
  result += "AllowedAddresses: " + strings.Join(xstrs, ", ") + "\n"
  result += "AllowedHosts: " + strings.Join(acl.AllowedHosts, ", ") + "\n"

  result += "BannedInterfaces: " + strings.Join(acl.BannedInterfaces, ", ") + "\n"
  xstrs = []string{}
  for _, x := range acl.BannedAddresses {
    xstrs = append(xstrs, x.String())
  }
  result += "BannedAddresses: " + strings.Join(xstrs, ", ") + "\n"
  result += "BannedHosts: " + strings.Join(acl.BannedHosts, ", ") + "\n"

  return
}
