# nfhook

nfhook is a netfilter hook framework which can support different hook APIs in Linux kernels.
  - Define default hook points
  - Provide a generic hook interface
  - Support net namespaces

# How to Build
  - checkout out code
  - install build essential packages and the kernel header
  - make all

# Test
```sh
  $ sudo insmod nfhook.ko
  $ sudo insmod test_hook.ko
  $ tail -f /var/log/kern.log
```

# Interfaces

  - see nfhook.h for details
  - see test_hook.c for the sample

# Contact

johnnie.deacon@gmail.com
