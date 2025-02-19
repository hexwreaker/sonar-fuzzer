

# Sonar-fuzz

<img width='200px' src='./cover-image.jpg' align="right" style="border-radius: 10px; box-shadow: 0px 0px 5px 0px; margin: 20px;"/>

[![Github last commits](https://img.shields.io/github/last-commit/hexwreaker/sonar-fuzzer)](https://github.com/hexwreaker/sonar-fuzzer/commits/master)
[![Github commit number](https://img.shields.io/github/commit-activity/t/hexwreaker/sonar-fuzzer)](https://github.com/hexwreaker/sonar-fuzzer/commits/master)
[![GitHub contributors](https://img.shields.io/github/contributors/hexwreaker/sonar-fuzzer)](https://img.shields.io/github/last-commit/hexwreaker/sonar-fuzzer/graphs/contributors)
[![Github All Releases](https://img.shields.io/github/downloads/hexwreaker/sonar-fuzzer/total.svg)](https://img.shields.io/github/last-commit/hexwreaker/sonar-fuzzer/releases/)

<p style='min-height: 150px;'>
A black box fuzzer project, currently in developpement. Only works for x86 target for instance.sdfjhsdkfjhskdjfhksdjhfksjhdkfjhsdkjfhfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffmlzkjvmqlkdjfmlqhsdmovqihermoh
</p>

## How it works

The principle is to use breakpoints (sometimes called probes) to trace the execution flow into the program. The implemented concept is not faster than instrumented binary fuzzing, but it allows you to fuzz without having the source code. This can be useful as some embbeded systems are proprietary and no sources are available.

## Working progress

### Done

1. The binary execution brick is implemented, with probes positionning and tracing.
2. The binary profile can be generated using the python script.

### To do

1. Improvement of binary profile generation, depending on the user fuzzing approche.
1. Input generation, using a SMT solver (Z3?) to run through all execution flow paths of the target.
1. Input mutation.
2. Multiprocess execution.
2. Crash handle.
2. Output formatting.
1. take in charge more architectures (ARM, MIPS, ...)


## Code maps

1. **src/sonarfuz.c** The main program of Sonar-fuzzer.
1. **src/sonar-debugger.c** Debugger functions used by the fuzzer (breakpoints positionning, step over/into, ...) .
1. **src/sprf-parser.c** The parser of SPRF profile file.
1. **src/util.c** : Some useful functions
1. **gensprf.py** : The python script to generate a SPRF profile file of a given binary.
1. **archives/*** : files that are not used enough, but contains interesting knowledge.
1. **bintest** : An example binary that can be used as test case.
1. **bintest.sprf** : The example binary SPRF profile.

## Usage

Compile the project :

```sh
$ make
```

Generate the SPRF profile of your target :

```sh
$ python3 gensprf.py target target.sprf
```

Use Sonar-fuzzer :

```sh
$ ./sonarfuz bintest.sprf bintest
```




