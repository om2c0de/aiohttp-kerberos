import sys


# Platform-specific Kerberos requirements
if sys.platform == 'win32':
    import kerberos_sspi as kerberos
else:
    import kerberos

flags = kerberos.GSS_C_CONF_FLAG | kerberos.GSS_C_INTEG_FLAG | kerberos.GSS_C_MUTUAL_FLAG | kerberos.GSS_C_SEQUENCE_FLAG

client_errors, client = kerberos.authGSSClientInit("HTTP@gpnhpecent.gpndt.test", gssflags=flags)
server_errors, server = kerberos.authGSSServerInit("HTTP@gpnhpecent.gpndt.test")

client_response = server_response = kerberos.AUTH_GSS_CONTINUE

response = ""
counter = 0

while server_response == kerberos.AUTH_GSS_CONTINUE or client_response == kerberos.AUTH_GSS_CONTINUE:

    if client_response == kerberos.AUTH_GSS_CONTINUE:
        client_response = kerberos.authGSSClientStep(client, response)
        if client_response == -1:
            print("Client step error")
            break
        response = kerberos.authGSSClientResponse(client)
    if server_response == kerberos.AUTH_GSS_CONTINUE:
        server_response = kerberos.authGSSServerStep(server, response)
        if server_response == -1:
            print("Server step error")
            break
        response = kerberos.authGSSServerResponse(server)

    print("Counter: ", counter)
    print("Server status: ", server_response)
    print("Client status: ", client_response)
    counter += 1

if server_response == kerberos.AUTH_GSS_COMPLETE and client_response == kerberos.AUTH_GSS_COMPLETE:
    print("client: my username:", kerberos.authGSSClientUserName(client))
    print("server: who authenticated to me:", kerberos.authGSSServerUserName(server))
    print("server: my spn:", kerberos.authGSSServerTargetName(server))
else:
    print("failed!")
