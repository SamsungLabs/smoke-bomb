# smoke-bomb

- SmokeBomb is an academic paper proposing an effective mitigation method
  against cache side-channel attacks on the ARM architechture.
  (To apper in [MobiSys 2020](https://www.sigmobile.org/mobisys/2020/papers/))


## 1. Directories

- smoke-bomb/       :  main code of smoke-bomb solution
- smoke-bomb/lib/   :  smoke-bomb api
- smoke-bomb/lkm/   :  smoke-bomb lkm
- smoke-bomb/test/  :  sample program using smoke-bomb api
- smoke-bomb/arm/   :  arm 32bit-dependent code (ARMv7, ARMv8-32bit)
- smoke-bomb/arm64/ :  arm 64bit-depenent code

## 2. Build smoke-bomb for ARMv8

* build
```
$ cd smoke-bomb
$ vim build_arm64.sh (==> update KDIR and CC)
$ ./build_arm64.sh
$ ls -l build/
  ==> sb_test :  sample program using smoke-bomb
  ==> smoke_bomb.ko :  smoke-bomb lkm
```

* clean
```
$ cd smoke-bomb
$ ./clean_arm64.sh
```

## 3. Run sample-program of smoke-bomb

* on host
```
$ cd smoke-bomb
$ cp -f build/* [your USB dir]
```

* on target device (tizen-tv or rpi3)
```
$ (mount your USB)
$ (copy sb_test, smoke_bomb.ko to target device)
$ insmod [path]/smoke_bomb.ko
$ [path]/sb_test 1 48 4
  ==> refer sb_test.c to know what argument mean
```
