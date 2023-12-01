#include <iostream>
#include <thread>
#include <condition_variable>
#include <mutex>

#include "ApplicationElementExample.hh"
#include "SecureSession/SecureSession.hh"
#include "SecureSession/SecureSessionTLS.hh"
#include "SecuritySubsystem/SecuritySubsystem.hh"
#include "SecuritySubsystem/SecuritySubsystemAppAPI.hh"
#include "AdaptorLayer/AdaptorLayer.hh"

#include "AppFullInstance.hh"

// Synchronisation to inform client that the server is ready;
std::condition_variable cond_var;
std::mutex m;
bool serverReady = false;

auto serverThreadFn = [](){
    AppFullInstance appServ(std::make_shared<SecureSessionTLS>(SecureSessionTLS()));

    appServ.configureApplication(123, BaseTypes::Role::SERVER);
    std::cerr << "====> Server now configured\n";
    {
        std::lock_guard<std::mutex> l{m};
        serverReady = true;
    }
    cond_var.notify_all();
    std::cerr << "====> Server will check for incoming sessions\n";
    appServ.waitForNetworkInput();
    // At this stage client and server are connected
    // Now client sends data
    std::cerr << "====> Server wil receive data\n";
    appServ.waitForNetworkInput();
    std::cerr << "====> Server will send out data\n";
    BaseTypes::Data serverMessage = {0x02, 0x04, 0x06};
    appServ.sendData(serverMessage);
};

auto clientThreadFn = [](){
    AppFullInstance appClient(std::make_shared<SecureSessionTLS>(SecureSessionTLS()));

    std::unique_lock<std::mutex> lock{m};
    cond_var.wait(lock, []() { return serverReady; });

    appClient.configureApplication(456, BaseTypes::Role::CLIENT);
    std::cerr << "====> Client now configured\n";
    // Now client sends data
    std::cerr << "====> Client will send out data\n";
    BaseTypes::Data clientMessage = {0x01, 0x03, 0x07, 0x08};
    appClient.sendData(clientMessage);
    std::cerr << "====> Client wil receive data\n";
    appClient.waitForNetworkInput();
};

void runWithThreads() {
    std::thread serverThread(serverThreadFn);
    std::thread clientThread(clientThreadFn);

    serverThread.join();
    clientThread.join();
}

int main() {
    if (true) {
        runWithThreads();
    }

    if (false){
        std::cerr << "======> Now without threads\n";
        AppFullInstance appServ(std::make_shared<SecureSessionTLS>(SecureSessionTLS()));
        AppFullInstance appClient(std::make_shared<SecureSessionTLS>(SecureSessionTLS()));

        appServ.configureApplication(123, BaseTypes::Role::SERVER);
        std::cerr << "====> Server now configured\n";
        appClient.configureApplication(456, BaseTypes::Role::CLIENT);
        std::cerr << "====> Client now configured\n";
        std::cerr << "====> Server will check for incoming sessions\n";
        appServ.waitForNetworkInput();
        // At this stage client and server are connected
        // Now client sends data
        std::cerr << "====> Client will send out data\n";
        BaseTypes::Data clientMessage = {0x01, 0x03, 0x07, 0x08};
        appClient.sendData(clientMessage);
        std::cerr << "====> Server will receive data\n";
        appServ.waitForNetworkInput();
        std::cerr << "====> Server will send out data\n";
        BaseTypes::Data serverMessage = {0x02, 0x04, 0x06};
        appServ.sendData(serverMessage);
        std::cerr << "====> Client will receive data\n";
        appClient.waitForNetworkInput();

        std::cerr << "====> Client will End session\n";
        appClient.forceEndSession();

        std::cerr << "====> Server will send out data\n";
        appServ.sendData(serverMessage);   

        std::cerr << "====> Server will wait for data\n";
        appServ.waitForNetworkInput();
    }
    if (false) {
        AppFullInstance appServ;
        AppFullInstance appClient;

        appServ.configureApplication(123, BaseTypes::Role::SERVER);
        std::cerr << "====> Server now configured\n";
        appClient.configureApplication(456, BaseTypes::Role::CLIENT);
        std::cerr << "====> Client now configured\n";
        std::cerr << "====> Server will check for incoming sessions\n";
        appServ.waitForNetworkInput();
        // At this stage client and server are connected
        // Now client sends data
        std::cerr << "====> Client will send out data\n";
        BaseTypes::Data clientMessage = {0x01, 0x03, 0x07, 0x08};
        appClient.sendData(clientMessage);
        std::cerr << "====> Server will receive data\n";
        appServ.waitForNetworkInput();
        std::cerr << "====> Server will send out data\n";
        BaseTypes::Data serverMessage = {0x02, 0x04, 0x06};
        appServ.sendData(serverMessage);
        std::cerr << "====> Client will receive data\n";
        appClient.waitForNetworkInput();

        std::cerr << "====> Server will End session\n";
        appServ.forceEndSession();

        std::cerr << "====> Client will send out data\n";
        appClient.sendData(clientMessage);   

        std::cerr << "====> Client will wait for data\n";
        appClient.waitForNetworkInput();
    }

}