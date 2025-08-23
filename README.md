# tombocrypt

This is a VS Code extension to decrypt and view `.chi` files, which are encrypted with the Tombo cryptography algorithm. This extension allows you to open and read your Tombo notes directly within VS Code.

## Features

* **Secure Decryption**: Decrypts `.chi` files on open by prompting you for the correct passcode.

## Usage

1.  Install the extension.
2.  Open any `.chi` file from the VS Code Explorer.
3.  A "The file is not displayed in the editor because it is either binary or uses an unsupported text encoding." warning will appear. Click "Open Anyway".
4.  A passcode prompt will appear. Enter the correct passcode to decrypt the file.
5.  The decrypted content will be displayed in the editor.

## Installation

You can install this extension by downloading the `.vsix` file from the [releases page on GitHub](https://github.com/T-Nosaka/tombocrypt/releases) and installing it through the VS Code command line or Extension view.

## Building from Source

If you want to build the extension from the source code, follow these steps:

1.  Clone the repository:
    ```bash
    git clone https://github.com/T-Nosaka/tombocrypt.git
    ```

2.  Navigate to the project directory:
    ```bash
    cd tombocrypt
    ```

3.  Install the dependencies:
    ```bash
    npm install
    ```

4.  Install the VS Code Extension packaging tool (vsce):
    ```bash
    npm install -g vsce
    ```

5.  Package the extension into a `.vsix` file:
    ```bash
    vsce package
    ```

This will create a `tombocrypt-0.0.1.vsix` file in your project directory, which you can then install into VS Code.

## Release Notes

### 0.0.2

bug fix.

### 0.0.1

Initial release of the extension with basic decryption functionality.

---

## License

Licensed under the MIT License.

## Following extension guidelines

* [Extension Guidelines](https://code.visualstudio.com/api/references/extension-guidelines)

