# Introduction to the Arm Disassembly Library

[Arm Disassembly Library](https://github.com/ArmDeveloperEcosystem/disassembly-library) is a software library and API for decoding and disassembling AArch64 instructions.

The instruction decoder takes 32-bit instruction encodings as input and generates a data structure containing information about the decoded instruction, such as register usage and operand details.

The disassembly library API provides a way to produce text disassembly and query additional information about decoded instructions. The API aims to be as stable as possible.

# Python Package

`armdisasm.py` provides Python bindings to the Arm Disassembly Library, so that the API can be used from Python applications.

# Dependencies

Python >= 3.7 is required in order to use this Python package.

# Installation

## Local Install

The `armdisasm.py` package is automatically built as part of the `build.sh` script in the project root directory of the Arm Disassembly Library. See the [Arm Disassembly Library build instructions](https://github.com/ArmDeveloperEcosystem/disassembly-library/blob/main/README.md#Building) for more details on how to build the library.

Once the Arm Disassembly Library has been built, a Python wheel file is created under the `python/dist` directory.

To install the package:
```sh
python3 -m pip install <relative_path_to_wheel_file>
```

## PyPI Install

This package has not yet been published to the Python Package Index (PyPI).

## Learning Path

For more information and examples on how to use this tool, check out the [Arm Learning Path](https://learn.arm.com/learning-paths/servers-and-cloud-computing/arm-disassembly-library).

## Compatibility

Currently, only AArch64 instructions are supported.

Please consider raising a [GitHub issue](https://github.com/ArmDeveloperEcosystem/disassembly-library/issues/new) if this tool does not work as expected on your system.

## Contributing

Contributions are welcome. In order to contribute, follow these steps:
* Read the [contribution agreement](CONTRIBUTING.md)
* Sign the commit message to indicate that you agree to the contribution agreement
# Submit a [pull request](https://github.com/ArmDeveloperEcosystem/disassembly-library/pulls) on GitHub

## Security

To report security vulnerabilities in this project, follow the guidance in the [security policy](SECURITY.md).

## License

This project is licensed under the [Apache-2.0 License](LICENSE).