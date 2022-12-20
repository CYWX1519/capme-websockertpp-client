#include <iostream>
#include "websocketclient.hpp"

int main(int, char**) {
    std::cout << "Hello, world!\n";

    websocketclient client;
    client.run();
}
