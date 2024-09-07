# GSipHash

[![Package Version](https://img.shields.io/hexpm/v/gsiphash)](https://hex.pm/packages/gsiphash)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/gsiphash/)
[![Package License](https://img.shields.io/hexpm/l/gsiphash)](https://hex.pm/packages/gsiphash)
[![Package Total Downloads Count](https://img.shields.io/hexpm/dt/gsiphash)](https://hex.pm/packages/gsiphash)
[![Build Status](https://img.shields.io/github/actions/workflow/status/BrendoCosta/gsiphash/test.yml)](https://hex.pm/packages/gsiphash)
[![Total Stars Count](https://img.shields.io/github/stars/BrendoCosta/gsiphash)](https://hex.pm/packages/gsiphash)

## Description

GSipHash is a small Gleam library that ports to Gleam the SipHash family of non-cryptographic hash functions, developed by Jean-Philippe Aumasson and Daniel J. Bernstein in 2012. The basic implementation follows an earlier one I wrote in C++ based on reading the [original algorithm research paper](https://www.aumasson.jp/siphash/siphash.pdf) and the [C reference code](https://github.com/veorq/SipHash), but prioritizing code clarity over constants and shortcuts. The test code is taken from the [C reference test code](https://github.com/veorq/SipHash/blob/master/test.c).

## Installation

```sh
gleam add gsiphash
```

## Usage

```gleam
import gsiphash

pub fn main()
{
    let assert Ok(0x3eb7d9b19dbec827) = gsiphash.siphash_2_4(from: <<"Hello world!":utf8>>, using: <<"8027f33015eaaba5":utf8>>)
    // The above function is an alias for calling the siphash function specifying 2 and 4 as the number of rounds C and D respectively.
    let assert Ok(0x3eb7d9b19dbec827) = gsiphash.siphash(<<"Hello world!":utf8>>, <<"8027f33015eaaba5":utf8>>, 2, 4)
}
```

## License

GSipHash source code is avaliable under the [MIT license](/LICENSE).
