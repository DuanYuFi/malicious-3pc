# Malicious 3PC for Binary and Arithmetic

## Introduction

This repo is an implementation about our paper [Malicious 3PC Binary](https://eprint.iacr.org/2023/909) published in USENIX Sec'23 and [Malicious 3PC Arithmetic](https://eprint.iacr.org/2024/700) published in ACM CCS'24. The implementations are based on [MP-SPDZ](https://github.com/data61/MP-SPDZ) framework.

## Installation

To install the MP-SPDZ framework, please refer to [MP-SPDZ readme](./README-mpspdz.md).

After installation, run `make mal3pc-ring-party.x -j 16` to compile our malicious 3PC ring protocol. To run ResNet50-inference, please refer to *TensorFlow inference* section in [MP-SPDZ readme](./README-mpspdz.md).

## Benchmarks

See [benchmarks](https://github.com/DuanYuFi/Benchmarks/tree/main/Mal3PC) for details.