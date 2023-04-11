start .\build\Debug\server.exe
timeout 3
start .\build\Debug\client.exe Alice
timeout 1
start .\build\Debug\client.exe Bob
timeout 1
start .\build\Debug\client.exe Carol
