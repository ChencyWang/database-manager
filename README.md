# Database‑KV‑Encrypted
> Release: v1.0
Author: ChencyWang
Github: https://github.com/ChencyWang

A simple encrypted key‑value database written in C++17.
- Binary `.data` storage, plain text editors cannot read content
- Password protection (password input masked by asterisk `*`, max 3 password attempts)
- Two‑mode: interactive shell & command‑line batch mode
- File‑level safety protection: prevent accidental deletion of non‑`.data` files
- Occupied file detection: cannot remove currently opened database before `close`
- Complete command‑set: create / work / remove / add / get / del / find / list / setpw / clearpw / close / help / exit

> Note: The internal AES‑256‑CBC implementation is for demo / educational purpose only, **not for production security usage**.

## Environment requirement
- C++17 compiler (GCC / MSVC)
- Support C++17 `<filesystem>` library

## Compile

### WSL / Linux
```bash
g++ main.cpp -o database -std=c++17
## tip:made with AI!
