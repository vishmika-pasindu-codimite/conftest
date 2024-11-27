package main

# Deny if USER instruction is set to "root"
deny[msg] {
    input[i].Cmd == "user"
    input[i].Value == ["root"]
    msg := "Dockerfile must not set USER to root. Use a non-root user for better security."
}
