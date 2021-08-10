# Encrypted-Proxy-Channel
The tool "plugboard" proxy is for adding an extra layer of protection to publicly accessible network services. The program is written in Go using the Crypto library.

Consider for example the case of an SSH server with a public IP address. No
matter how securely the server has been configured and how strong the keys
used are, it might suffer from a "pre-auth" zero day vulnerability that allows
remote code execution even before the completion of the authentication
process. This could allow attackers to compromise the server even without
providing proper authentication credentials. The Heartbleed OpenSSL bug is an
example of such a serious vulnerability against SSL/TLS.

The plugboard proxy, named 'pbproxy', adds an extra
layer of encryption to connections towards TCP services. Instead of connecting
directly to the service, clients connect to pbproxy (running on the same
server), which then relays all traffic to the actual service. Before relaying
the traffic, pbproxy always decrypts it using a static symmetric key. This
means that if the data of any connection towards the protected server is not
properly encrypted, then it will turn into garbage before reaching the
protected service.

This is a better option than port knocking and similar solutions, as attackers
who might want to exploit a zero day vulnerability in the protected service
would first have to know the secret key for having a chance to successfully
deliver their attack vector to the server. This of course assumes that the
plugboard proxy does not suffer from any vulnerability itself. Given that its
task and its code are much simpler compared to an actual service (e.g., an SSH
server), its code can be audited more easily and it can be more confidently
exposed as a publicly accessible service. Go is also a memory-safe language
that does not suffer from memory corruption bugs.

Clients who want to access the protected server should proxy their traffic
through a local instance of pbroxy, which will encrypt the traffic using the
same symmetric key used by the server. In essence, pbproxy can act both as
a client-side proxy and as server-side reverse proxy, in a way similar to
netcat.

data flow:

ssh <--stdin/stdout--> pbproxy-c <--socket 1--> pbproxy-s <--socket 2--> sshd     
