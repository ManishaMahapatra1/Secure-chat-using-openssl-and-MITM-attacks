#include<iostream>
#include<cstring>
#include<sys/socket.h>
#include<arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#define MAX 1024
#define CLIENT 1
#define SERVER 2

using namespace std;
//Initialize list of cipher suites
const char* str = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384";
//Creation of SSL object
SSL_CTX *InitCTX(int option)
{
    const SSL_METHOD *ssl_method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    if(option == CLIENT)
    {
        ssl_method = TLSv1_2_client_method();
        cout<<"\nClient ctx created"<<endl;
    }
    else if(option == SERVER)
    {
        ssl_method = TLSv1_2_server_method();
        cout<<"\nServer ctx created"<<endl;
    }
    ctx = SSL_CTX_new(ssl_method);
    if (ctx == NULL)
    {
        cout<<"\nServer ctx is null"<<endl;
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
//------------------------------------------------------------------------------------
//Funtion for certificate setup
//------------------------------------------------------------------------------------
void configureCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        cout<<"\nCertificate file not valid"<<endl;
        ERR_print_errors_fp(stderr);
        abort();
    }
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        cout<<"\nKey file not valid"<<endl;
        ERR_print_errors_fp(stderr);
        abort();
    }
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        cout<<"\nKey not match with certificate file"<<endl;
        abort();
    }
}
//------------------------------------------------------------------------------------
//Function to verify certificate
//------------------------------------------------------------------------------------
int verify_the_certificate(SSL *ssl)
{
    int result;
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert == nullptr)
    {
        ERR_print_errors_fp(stderr);
        cout<<"\nCertificate Not Given by Peer"<<endl;
        abort();
    }
    int err = SSL_get_verify_result(ssl);
    if (err != X509_V_OK)
    {
        ERR_print_errors_fp(stderr);
        const char *err_string = X509_verify_cert_error_string(err);
        printf("\nCertificate Not Valid : %s\n", err_string);
        abort();
    }
    result = err;
    return result;
}
//------------------------------------------------------------------------------------
//Client function
//------------------------------------------------------------------------------------
int client(const char *hostname, int port)
{
    int client_sd;
    X509* cert;
    X509* peer_cert;
    SSL_CTX *ctx;
    int start_tls_flag =0;
    int start_comm_flag =0;
    SSL *ssl;
    char send_buffer[MAX];
    char receive_buffer[MAX];
    struct hostent *host;
    struct sockaddr_in addr;
    if ((host = gethostbyname(hostname)) == NULL)
    {
        perror(hostname);
        abort();
    }
    client_sd = socket(AF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long *)(host->h_addr);
    cout<<"\nIP address of Client: "<<endl;
    cout<<inet_ntoa(*(struct in_addr*)host->h_addr)<<endl;
    if (connect(client_sd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        close(client_sd);
        perror(hostname);
        abort();
    }
    else
    {
        cout<<"\nClient Socket Created\n"<<endl;
    }
    cout<<"\nEnter message for Server: "<<endl;
    string s;
    getline(cin , s);
    int n = s.size();
    for(int i = 0 ; i < n ; i++)
    {
        send_buffer[i] = s[i];
    }
    send_buffer[n] = '\0';
    send(client_sd , send_buffer , strlen(send_buffer)+1 , 0);
    if((strncmp(send_buffer, "term", 4)) == 0)
    {
        close(client_sd);
        abort();
    }
    recv(client_sd , receive_buffer , MAX , 0);
    cout<<"\nReceived From Server: "<<receive_buffer<<endl;
    if((strncmp(receive_buffer, "term", 4)) == 0)
    {
        close(client_sd);
        abort();
    }
    if((strncmp(receive_buffer, "chat_reply", 10)) == 0)
    {
        start_comm_flag = 1;
    }
    cout<<"\nEnter message for Server: "<<endl;
    getline(cin , s);
     n = s.size();
    for(int i = 0 ; i < n ; i++)
    {
        send_buffer[i] = s[i];
    }
    send_buffer[n] = '\0';
    send(client_sd , send_buffer , strlen(send_buffer)+1, 0);
    recv(client_sd , receive_buffer , MAX , 0);
    cout<<"\nReceived From Server: "<<receive_buffer<<endl;
    if((strncmp(receive_buffer, "start_tls_ack", 13)) == 0)
    {        
        SSL_library_init();   
        ctx = InitCTX(CLIENT);   
        //Put client certificates file name        
        configureCertificates(ctx, "alicecert.pem", "alice.pem");
        SSL_CTX_load_verify_locations(ctx, "/usr/local/share/ca-certificates/rootCA.crt", NULL);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        ssl = SSL_new(ctx);
        if (ssl == nullptr)
        {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(client_sd);
            abort();
        }
        cert = SSL_get_certificate(ssl);            
        if(cert)
        {
         X509_NAME_print_ex_fp(stdout, X509_get_subject_name(cert), 0, XN_FLAG_ONELINE);
        }
        SSL_set_verify(ssl, SSL_VERIFY_PEER, 0);
        SSL_set_fd(ssl, client_sd);            
        if ( SSL_connect(ssl) == -1 )
        {
            ERR_print_errors_fp(stderr);
            abort();
        }
        else
        {
            peer_cert = SSL_get_peer_certificate(ssl);            
            if(peer_cert)
            {
                cout<<"\n";
                X509_NAME_print_ex_fp(stdout, X509_get_subject_name(peer_cert), 0, XN_FLAG_ONELINE);
            }
            int result = verify_the_certificate(ssl);
            if(result == X509_V_OK)
            {
                cout<<"\nServer Certificate Valid\n";
                start_tls_flag = 1;
            }
        }
    }
    if((start_comm_flag == 1)&&(start_tls_flag == 1))
    {
        while(true)
        {
            char input[MAX];
            string s;
            cout<<"\nEnter message for Server on TLS: "<<endl;
            getline(cin , s);
            int n = s.size();
            for(int i = 0 ; i < n ; i++)
            {
                input[i] = s[i];
            }
            input[n] = '\0';
            SSL_write(ssl,input, strlen(input)+1);
            if((strncmp(input,"term",4))==0)
            {
                cout << "\nConnection Terminated\n"<<endl ;
                break;
            }
            char receiveMessage[MAX];
            SSL_read(ssl, receiveMessage, MAX);;
            if((strncmp(receiveMessage,"term",4))==0)
            {
                cout <<"\nConnection Terminated from Server\n"<<endl ;
                break;
            }
            cout << "\nServer received on tls: " << receiveMessage <<endl;             
        }
    }
    else if((start_comm_flag == 1)&&(start_tls_flag == 0))
    {
        while(true)
        {
            char input[MAX];
            string s;
            cout<<"\nEnter message for Server on socket: "<<endl;
            getline(cin , s);
            int n = s.size();
            for(int i = 0 ; i < n ; i++)
            {
                input[i] = s[i];
            }
            input[n] = '\0';
            send(client_sd , input , strlen(input)+1 , 0);
            if((strncmp(input,"term",4))==0)
            {
                cout << "Connection Terminated\n" ;
                break;
            }
            char receiveMessage[MAX];
            recv(client_sd , receiveMessage , MAX , 0);
            if((strncmp(receiveMessage,"term",4))==0)
            {
                cout << "Connection terminated from Server\n" ;
                break;
            }
            cout << "\nServer received on socket: " << receiveMessage <<endl;   
        }
    }
    else
    {
        cout<<"\nERROR:Connection Not Established\n";
        close(client_sd);
        abort();
    }
    close(client_sd);
    return 0;
}
//------------------------------------------------------------------------------------
//Server function
//------------------------------------------------------------------------------------
int server(int port)
{
    X509 *cert;
    X509 *peer_cert;
    int start_tls_flag = 0;
    int start_comm_flag = 0;
    char send_buffer[MAX];
    char receive_buffer[MAX];
    SSL *ssl;
    int server_sd;
    SSL_CTX *ctx;
    int connection;
    struct sockaddr_in addr, client_addr;
    server_sd = socket(AF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if(bind(server_sd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        cout<<"\nBind port error"<<endl;
        close(server_sd);
        abort();
    }
    if (listen(server_sd, 10) != 0)
    {
        cout<<"\nListening port error"<<endl;
        close(server_sd);
        abort();
    }
    cout<<"......Waiting for client connection........\n"<<endl;
    char buff[MAX];
    socklen_t len = sizeof(client_addr);
    if((connection = accept(server_sd , (struct sockaddr*)&client_addr, &len)) < 0)
    {
        cout << "\nClient request not accepted"<< endl;
        return 0;
    }
    else
    {
        cout << "Client request accepted from IP: "<<inet_ntoa(client_addr.sin_addr)<<endl ;
    } 
    recv(connection , receive_buffer , MAX , 0);//first receive
    if((strncmp(receive_buffer, "term", 4)) == 0)
    {
        close(connection);
        abort();
    }
    if((strncmp(receive_buffer, "chat_request", 12)) == 0)
    {
        start_comm_flag = 1;
    }
    string s;
    cout<<"\nReceived From Client: "<<receive_buffer<<endl;
    cout<<"\nEnter message for Client: "<<endl;
    getline(cin , s);
    int n = s.size();
    for(int i = 0 ; i < n ; i++)
    {
        send_buffer[i] = s[i];
    }
    send_buffer[n] = '\0';
    send(connection , send_buffer , strlen(send_buffer)+1, 0);//first send
    recv(connection , receive_buffer , MAX , 0);
    if((strncmp(receive_buffer, "start_tls", 9)) == 0)
    {
        cout<<"\nReceived From Client: "<<receive_buffer<<endl;
        cout<<"\nEnter message for Client: "<<endl;
        getline(cin , s);
        int n = s.size();
        for(int i = 0 ; i < n ; i++)
        {
              send_buffer[i] = s[i];
        }
        send_buffer[n] = '\0';
        send(connection , send_buffer , strlen(send_buffer)+1, 0);
        if((strncmp(send_buffer, "start_tls_ack", 13))== 0)
        {
        
		SSL_library_init();
		ctx = InitCTX(SERVER);
		configureCertificates(ctx, "bobcert.pem", "bob.pem");//put server certificates file names
		SSL_CTX_load_verify_locations(ctx, "/usr/local/share/ca-certificates/rootCA.crt", NULL);
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
		ssl = SSL_new(ctx);
		if (ssl == nullptr)
		{
		    ERR_print_errors_fp(stderr);
		    SSL_CTX_free(ctx);
		    close(connection);
		    close(server_sd);
		    abort();
		}
		SSL_set_verify(ssl, SSL_VERIFY_PEER, 0);
		cert = SSL_get_certificate(ssl);
		X509_NAME_print_ex_fp(stdout, X509_get_subject_name(cert), 0, XN_FLAG_ONELINE);
		SSL_set_fd(ssl, connection);
		if (SSL_accept(ssl) == -1)
		{
		    ERR_print_errors_fp(stderr);
		    SSL_free(ssl);
		    SSL_CTX_free(ctx);
		    close(connection);
		    close(server_sd);
		    abort();
		}
		else
		{
		    peer_cert = SSL_get_peer_certificate(ssl);
		    if(peer_cert != nullptr)
		    {
		        cout<<" 4here in this\n";
		    X509_NAME_print_ex_fp(stdout, X509_get_subject_name(peer_cert), 0, XN_FLAG_ONELINE);
		    }
		    else
		    {
		        ERR_print_errors_fp(stderr);
		        SSL_free(ssl);
		        SSL_CTX_free(ctx);
		        close(connection);
		        abort();
		    }
		    int result = verify_the_certificate(ssl);
		    if(result == X509_V_OK)
		    {
		        cout<<"\nClient Certificate Valid\n";
		        start_tls_flag = 1;
		    }
        	}
        }
    }
    else//if not received start_tls
    {
        cout<<"\nReceived From Client: ";
        cout<<receive_buffer;
        cout<<"\nEnter message for Client: "<<endl;
        getline(cin , s);
        int n = s.size();
        for(int i = 0 ; i < n ; i++)
        {
            send_buffer[i] = s[i];
        }
        send_buffer[n] = '\0';
        send(connection , send_buffer , strlen(send_buffer)+1, 0);
    }
    if((start_comm_flag == 1)&&(start_tls_flag == 1))
    {
        while(true)
        {
            char input[MAX];
            char receiveMessage[MAX];
            string s;
            SSL_read(ssl, receiveMessage, sizeof(receiveMessage));;
            if((strncmp(receiveMessage,"term",4)) == 0)
            {
                cout << "\nConnection terminated from Client\n" ;
                break;
            }
            cout << "Received from Client on TLS: " << receiveMessage <<endl;
            cout<<"\nEnter message for Client on TLS:"<<endl;
            getline(cin , s);
            int n = s.size();
            for(int i = 0 ; i < n ; i++)
            {
                input[i] = s[i];
            }
            input[n] = '\0';
            SSL_write(ssl,input, strlen(input)+1);
            if((strncmp(input,"term",4)) == 0)
            {
                cout << "\nConnection terminated\n" ;
                break;
            }
        }
    }
    else if((start_comm_flag == 1)&&(start_tls_flag == 0))
    {
        while(true)
        {
            char input[MAX];
            string s;
            char receiveMessage[MAX];
            recv(connection , receiveMessage , MAX , 0);
            if((strncmp(receiveMessage,"term",4))==0)
            {
                cout << "\nConnection terminated from Client\n"<<endl ;
                break;
            }
            cout << "Received from Client on socket: " << receiveMessage <<endl;
            cout<<"\nEnter message for Client on socket: "<<endl;
            getline(cin , s);
            int n = s.size();
            for(int i = 0 ; i < n ; i++)
            {
                input[i] = s[i];
            }
            input[n] = '\0';
            send(connection , input , strlen(input)+1 , 0);
            if((strncmp(input,"term",4))==0)
            {
                cout << "\nConnection terminated\n"<<endl ;
                break;
            }           
        }         
    }
    else
    {
        cout<<"\nERROR:Connection Not Established\n";
        close(connection);
        close(server_sd);
        abort();
    }    
    close(connection);
    close(server_sd);
    return 0;
}
//------------------------------------------------------------------------------------
//Main Function
//------------------------------------------------------------------------------------
int main(int argc, char *argv[])
{
    char *host_name, *port_no, *option;
    if(argc == 3)
    {
        option = argv[1];
        port_no = argv[2];
    }
    else if(argc == 4)
    {
        option = argv[1];
        host_name = argv[2];
        port_no = argv[3];
    }
    else
    {
        cout<<"No of Arguments wrong: "<<endl;
        cout<<argc<<endl;
        exit(0);
    }
    if(strcmp(option, "-s")==0)
    {
        server(atoi(port_no));
    }
    else if (strcmp(option, "-c")==0)
    {
        client(host_name,atoi(port_no));
    }
    else
    {
        cout<<"Wrong Option"<<endl;
    }
    return 0;
}
