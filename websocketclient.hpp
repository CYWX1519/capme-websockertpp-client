#ifndef _WEBSOCKET_CLIENT
#define _WEBSOCKET_CLIENT

#include <websocketpp/config/asio_client.hpp>
#include <websocketpp/client.hpp>
#include <iostream>
#include <boost/asio/ssl/verify_context.hpp>

typedef websocketpp::client<websocketpp::config::asio_tls_client> WebsocketEndpoint;
typedef websocketpp::connection_hdl ClientConnection;
typedef websocketpp::lib::shared_ptr<websocketpp::lib::asio::ssl::context> ssl;
typedef boost::asio::ssl::verify_context verify_context;

using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;

class websocketclient
{
public:
    websocketclient();
    ~websocketclient();
    std::string hostname = "localhost";
    void run();

protected:
    WebsocketEndpoint endPoint;
    void on_message(ClientConnection conn, WebsocketEndpoint::message_ptr msg);
    ssl on_tls_init(const char * hostname, ClientConnection);
    bool verify_certificate(const char * hostname, bool preverified, verify_context& ctx);
    bool verify_subject_alternative_name(const char * hostname, X509 * cert);
    bool verify_common_name(char const * hostname, X509 * cert);
};

#endif // !_WEBSOCKET_CLIENT
